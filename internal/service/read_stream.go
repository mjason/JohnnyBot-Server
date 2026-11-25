package service

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"johnny_bot/internal/keyauth"
)

const (
	fileFrame  byte = 1
	pageFrame  byte = 2
	endFrame   byte = 3
	errorFrame byte = 4
)

type readRequest struct {
	Host    string
	Device  string
	Proof   string
	Follow  bool
	Command json.RawMessage
}

// Each bidirectional stream carries one authenticated, read-only operation.
func (s *Service) StartReadStreams(addr, host string, cert tls.Certificate, keys *keyauth.Keyring) (func(), error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"johnnybot-read-v1"}, MinVersion: tls.VersionTLS13,
	}
	config := &quic.Config{
		InitialPacketSize: 1200, MaxIncomingStreams: 16, MaxIncomingUniStreams: -1,
		MaxIdleTimeout: 35 * time.Second,
	}
	ln, err := quic.ListenAddr(addr, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(s.ctx)
	slots := make(chan struct{}, 128)
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.CloseWithError(1, "busy")
				continue
			}
			workers.Go(func() {
				defer func() { <-slots; conn.CloseWithError(0, "closed") }()
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					workers.Go(func() { s.serveReadStream(ctx, conn.Context(), stream, host, keys) })
				}
			})
		}
	})
	s.streamEnabled = true
	return func() { cancel(); ln.Close(); workers.Wait() }, nil
}

func writeFrame(w *quic.Stream, kind byte, data []byte) error {
	w.SetWriteDeadline(time.Now().Add(15 * time.Second))
	header := [5]byte{kind}
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := w.Write(data)
		return err
	}
	return nil
}

func (s *Service) serveReadStream(serviceCtx, connCtx context.Context, st *quic.Stream, host string, keys *keyauth.Keyring) {
	defer st.Close()
	defer st.CancelRead(0)
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	var size uint32
	if binary.Read(st, binary.BigEndian, &size) != nil || size > 16384 || size == 0 {
		return
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(st, raw); err != nil {
		return
	}
	var req readRequest
	if json.Unmarshal(raw, &req) != nil || req.Host != host || keys.VerifyRead(req.Device, req.Proof, time.Now()) != nil {
		writeFrame(st, errorFrame, []byte("unauthorized"))
		return
	}
	c, err := decode(req.Command)
	if err == nil {
		ctx, cancel := context.WithCancel(serviceCtx)
		defer cancel()
		stop := context.AfterFunc(connCtx, cancel)
		defer stop()
		switch c.Op {
		case "file.read":
			err = s.streamFile(ctx, st, c, req.Device)
		case "sync.pull":
			err = s.streamScope(ctx, st, c, req.Device, req.Follow)
		default:
			err = fault("invalid_argument", "unknown read operation")
		}
	}
	if err != nil {
		code := "read_error"
		var f *protocolError
		if errors.As(err, &f) {
			code = f.Code
		}
		writeFrame(st, errorFrame, []byte(code))
		return
	}
	writeFrame(st, endFrame, nil)
}

func (s *Service) streamFile(ctx context.Context, st *quic.Stream, c command, device string) error {
	f, info, err := s.openProjectFile(c)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	remaining := info.Size()
	for remaining > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.authorized(device) {
			return fault("revoked", "device revoked")
		}
		n, err := io.ReadFull(f, buf[:min(int64(len(buf)), remaining)])
		if err != nil {
			return err
		}
		if err := writeFrame(st, fileFrame, buf[:n]); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	end, err := f.Stat()
	if err != nil || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return fault("file_changed", "restart read")
	}
	return nil
}

func (s *Service) streamScope(ctx context.Context, st *quic.Stream, c command, device string, follow bool) error {
	signal := make(chan struct{}, 1)
	if follow {
		s.hintsMu.Lock()
		if s.watchers[c.Scope] == nil {
			s.watchers[c.Scope] = make(map[chan struct{}]bool)
		}
		s.watchers[c.Scope][signal] = true
		s.hintsMu.Unlock()
		defer func() {
			s.hintsMu.Lock()
			defer s.hintsMu.Unlock()
			delete(s.watchers[c.Scope], signal)
			if len(s.watchers[c.Scope]) == 0 {
				delete(s.watchers, c.Scope)
			}
		}()
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.authorized(device) {
			return fault("revoked", "device revoked")
		}
		page, err := s.pull(c)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(page)
		if err != nil {
			return err
		}
		if err := writeFrame(st, pageFrame, payload); err != nil {
			return err
		}
		if page.Reset {
			return nil
		}
		c.Epoch = page.Epoch
		if page.More {
			if len(page.Events) == 0 {
				return errors.New("empty continuation")
			}
			c.After = page.Events[len(page.Events)-1].Seq
			c.Through = page.Through
			continue
		}
		if !follow {
			return nil
		}
		c.After = page.Through
		c.Through = 0
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-st.Context().Done():
			return context.Canceled
		case <-signal:
		case <-time.After(15 * time.Second):
		}
	}
}
