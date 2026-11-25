package service

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/creack/pty"
)

const terminalCapacity = 256 << 10
const terminalPage = 24 << 10

type terminalInfo struct {
	ID         string `json:"terminal_id"`
	Workspace  string `json:"workspace_id"`
	Path       string `json:"path"`
	Title      string `json:"title"`
	Cols       int    `json:"cols"`
	Rows       int    `json:"rows"`
	Controller string `json:"controller_device_id"`
	Running    bool   `json:"running"`
}

type terminalManager struct {
	mu   sync.Mutex
	tabs map[string]*terminal
}

type terminal struct {
	mu    sync.Mutex
	info  terminalInfo
	cmd   *exec.Cmd
	fd    *os.File
	input chan []byte
	done  chan struct{}
	ring  []byte
	end   int64
}

func (t *terminal) append(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	start := int(t.end % int64(len(t.ring)))
	n := copy(t.ring[start:], data)
	copy(t.ring, data[n:])
	t.end += int64(len(data))
}

func (t *terminal) serve() {
	go func() {
		for {
			select {
			case <-t.done:
				return
			case data := <-t.input:
				if _, err := t.fd.Write(data); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := t.fd.Read(buf)
			if n > 0 {
				t.append(buf[:n])
			}
			if err != nil {
				break
			}
		}
		t.cmd.Wait()
		t.fd.Close()
		t.mu.Lock()
		t.info.Running = false
		t.mu.Unlock()
		close(t.done)
	}()
}

// A PTY is live, so it must never start from an offline database job after a restart.
// Keep only the request hash and reply in the shared dedup ledger; input can contain secrets.
func (s *Service) liveTerminalCommand(device string, c command, raw []byte) error {
	digest := sha256.Sum256(raw)
	var claimed bool
	var existing, reply []byte
	err := s.store.write(s.ctx, func(tx *sql.Tx) error {
		row, err := tx.Exec("INSERT OR IGNORE INTO commands(device,id,body,state) VALUES(?,?,?,'running')", device, c.ID, digest[:])
		if err != nil {
			return err
		}
		n, err := row.RowsAffected()
		if err != nil {
			return err
		}
		claimed = n == 1
		if claimed {
			return nil
		}
		return tx.QueryRow("SELECT body,reply FROM commands WHERE device=? AND id=?", device, c.ID).Scan(&existing, &reply)
	})
	if err != nil {
		return err
	}
	if !claimed {
		if !bytes.Equal(existing, digest[:]) {
			reply = s.encode(c.ID, nil, fault("command_conflict", "cmd_id was already used with different bytes"))
		}
		if reply != nil {
			return s.publisher.Reply(device, reply)
		}
		return nil
	}
	result, opErr := s.terminalOperation(device, c)
	reply = s.encode(c.ID, result, opErr)
	if err = s.store.write(s.ctx, func(tx *sql.Tx) error { return finish(tx, job{device: device, id: c.ID}, reply) }); err != nil {
		return err
	}
	return s.publisher.Reply(device, reply)
}

func terminalAvailable() bool {
	_, err := exec.LookPath("bwrap")
	return runtime.GOOS == "linux" && err == nil
}

func validDimensions(cols, rows int) bool {
	return cols >= 1 && rows >= 1 && cols <= 512 && rows <= 256
}

func (s *Service) terminalOperation(device string, c command) (any, error) {
	m := &s.terminals
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Op == "terminal.list" || c.Op == "terminal.create" {
		w, err := s.workspace(c.Workspace)
		if err != nil {
			return nil, err
		}
		if c.Op == "terminal.list" {
			items := []terminalInfo{}
			for _, t := range m.tabs {
				t.mu.Lock()
				if t.info.Workspace == w.ID {
					items = append(items, t.info)
				}
				t.mu.Unlock()
			}
			slices.SortFunc(items, func(a, b terminalInfo) int { return strings.Compare(a.ID, b.ID) })
			return map[string]any{"terminals": items}, nil
		}
		if len(m.tabs) >= 16 {
			return nil, fault("server_busy", "close a terminal before creating another")
		}
		if !validDimensions(c.Cols, c.Rows) {
			return nil, fault("invalid_argument", "invalid terminal dimensions")
		}
		_, rel, err := w.directory(c.Path)
		if err != nil {
			return nil, err
		}
		t, err := startTerminal(w, rel, device, c.Cols, c.Rows)
		if err != nil {
			return nil, err
		}
		if m.tabs == nil {
			m.tabs = make(map[string]*terminal)
		}
		m.tabs[t.info.ID] = t
		info := t.info
		t.serve()
		return map[string]any{"terminal": info}, nil
	}
	t := m.tabs[c.Terminal]
	if t == nil {
		return nil, fault("not_found", "terminal does not exist")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c.Op == "terminal.read" {
		if c.Offset < 0 {
			return nil, fault("invalid_argument", "offset must be nonnegative")
		}
		first := max(int64(0), t.end-int64(len(t.ring)))
		offset := c.Offset
		reset := offset < first || offset > t.end
		if reset {
			offset = first
		}
		n := min(t.end-offset, int64(terminalPage))
		data := make([]byte, n)
		start := int(offset % int64(len(t.ring)))
		k := copy(data, t.ring[start:])
		copy(data[k:], t.ring)
		return map[string]any{"bytes": data, "first_offset": first, "next_offset": offset + n, "reset": reset, "running": t.info.Running, "terminal": t.info}, nil
	}
	if c.Op == "terminal.claim" {
		t.info.Controller = device
		return map[string]any{"terminal": t.info}, nil
	}
	if t.info.Controller != device {
		return nil, fault("not_controller", "claim control of this terminal first")
	}
	if c.Op == "terminal.close" {
		if t.info.Running {
			if err := t.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return nil, err
			}
		}
		delete(m.tabs, c.Terminal)
		return map[string]any{"terminal_id": c.Terminal, "closed": true}, nil
	}
	if !t.info.Running {
		return nil, fault("terminal_closed", "terminal process has exited")
	}
	switch c.Op {
	case "terminal.input":
		if len(c.Bytes) == 0 || len(c.Bytes) > 32<<10 {
			return nil, fault("invalid_argument", "input must be 1 to 32768 bytes")
		}
		select {
		case t.input <- c.Bytes:
			return map[string]int{"accepted": len(c.Bytes)}, nil
		default:
			return nil, fault("server_busy", "terminal input is full")
		}
	case "terminal.resize":
		if !validDimensions(c.Cols, c.Rows) {
			return nil, fault("invalid_argument", "invalid terminal dimensions")
		}
		if err := pty.Setsize(t.fd, &pty.Winsize{Cols: uint16(c.Cols), Rows: uint16(c.Rows)}); err != nil {
			return nil, err
		}
		t.info.Cols, t.info.Rows = c.Cols, c.Rows
		return map[string]any{"terminal": t.info}, nil
	}
	return nil, fault("unsupported_op", "unknown terminal operation")
}

func startTerminal(w Workspace, rel, device string, cols, rows int) (*terminal, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fault("unsupported", "terminal requires bubblewrap on the server")
	}
	// Only this workspace is writable on the host. Use a private /tmp and no
	// agent sockets, service credentials in the environment, or host /proc.
	args := []string{"--unshare-all", "--share-net", "--die-with-parent", "--ro-bind", "/usr", "/usr", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"}
	for _, path := range []string{"/bin", "/lib", "/lib64", "/sbin", "/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/alternatives", "/etc/terminfo"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	args = append(args, "--bind", w.Path, "/workspace", "--chdir", filepath.Join("/workspace", rel), "/bin/bash", "--noprofile", "--norc", "-i")
	cmd := exec.Command(bwrap, args...)
	cmd.Env = []string{"PATH=/workspace/.local/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/workspace", "LANG=C.UTF-8", "TERM=xterm-256color", "SHELL=/bin/bash"}
	fd, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	title := filepath.Base(rel)
	if rel == "." {
		title = w.ID
	}
	return &terminal{info: terminalInfo{newID(), w.ID, rel, title, cols, rows, device, true}, cmd: cmd, fd: fd, input: make(chan []byte, 32), done: make(chan struct{}), ring: make([]byte, terminalCapacity)}, nil
}

func (m *terminalManager) closeAll() {
	m.mu.Lock()
	tabs := m.tabs
	m.tabs = nil
	m.mu.Unlock()
	for _, t := range tabs {
		t.cmd.Process.Kill()
	}
	for _, t := range tabs {
		<-t.done
	}
}
