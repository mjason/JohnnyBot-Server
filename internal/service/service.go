// Package service owns the command inbox and the scoped offline replication log.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"johnny_bot/internal/agent"
	"johnny_bot/internal/syncwire"
)

type Publisher interface {
	Reply(device string, payload []byte) error
	Event(scope string, payload []byte) error
}

type Service struct {
	streamEnabled   bool
	watchers        map[string]map[chan struct{}]bool
	terminals       terminalManager
	terminalReaders chan struct{}
	ctx             context.Context
	cancel          context.CancelCauseFunc
	store           *store
	log             *slog.Logger
	workspaces      map[string]Workspace
	publisher       Publisher
	authorized      func(string) bool
	wake            chan struct{}
	workers         sync.WaitGroup
	dispatchDone    chan struct{}
	hintsDone       chan struct{}
	hintsMu         sync.Mutex
	hints           map[string]struct{}
	pool            map[string]*adapter
	turnSlots       chan struct{}
	mu              sync.Mutex
	busy            map[string]bool
	active          map[string]*turn
	permissions     map[string]*approval
}

type command struct {
	WaitMS     int                `json:"wait_ms,omitempty"`
	Terminal   string             `json:"terminal_id,omitempty"`
	Cols       int                `json:"cols,omitempty"`
	Rows       int                `json:"rows,omitempty"`
	Bytes      []byte             `json:"bytes,omitempty"`
	ConfigID   string             `json:"config_id,omitempty"`
	Value      json.RawMessage    `json:"value,omitempty"`
	ModeID     string             `json:"mode_id,omitempty"`
	ID         string             `json:"cmd_id"`
	Op         string             `json:"op"`
	Scope      string             `json:"scope,omitempty"`
	Epoch      string             `json:"epoch,omitempty"`
	After      int64              `json:"after,omitempty"`
	Through    int64              `json:"through,omitempty"`
	Limit      int                `json:"limit,omitempty"`
	Workspace  string             `json:"workspace_id,omitempty"`
	Thread     string             `json:"thread_id,omitempty"`
	Agent      string             `json:"agent,omitempty"`
	Path       string             `json:"path,omitempty"`
	Title      string             `json:"title,omitempty"`
	Archived   *bool              `json:"archived,omitempty"`
	Prompt     []acp.ContentBlock `json:"prompt,omitempty"`
	Turn       string             `json:"turn_id,omitempty"`
	Permission string             `json:"permission_id,omitempty"`
	Option     string             `json:"option_id,omitempty"`
	NameAfter  string             `json:"name_after,omitempty"`
	Offset     int64              `json:"offset,omitempty"`
	Version    string             `json:"version,omitempty"`
}

type protocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *protocolError) Error() string { return e.Message }
func fault(code, message string) error { return &protocolError{code, message} }

type reply struct {
	ID     string         `json:"cmd_id"`
	OK     bool           `json:"ok"`
	Result any            `json:"result,omitempty"`
	Error  *protocolError `json:"error,omitempty"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func stableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z") }

func Open(ctx context.Context, path string, configs []Workspace, authorized func(string) bool, log *slog.Logger) (*Service, error) {
	ws, err := normalizeWorkspaces(configs)
	if err != nil {
		return nil, err
	}
	db, err := openStore(ctx, path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	s := &Service{
		ctx: ctx, cancel: cancel, store: db, log: log, workspaces: ws, authorized: authorized,
		terminalReaders: make(chan struct{}, 64), wake: make(chan struct{}, 1), dispatchDone: make(chan struct{}), turnSlots: make(chan struct{}, 8),
		hintsDone: make(chan struct{}), hints: make(map[string]struct{}), watchers: make(map[string]map[chan struct{}]bool),
		pool: make(map[string]*adapter), busy: make(map[string]bool), active: make(map[string]*turn), permissions: make(map[string]*approval),
	}
	for name, spec := range agent.Presets {
		s.pool[name] = newAdapter(s, spec)
	}
	if err := s.recover(); err != nil {
		cancel(nil)
		db.close()
		return nil, err
	}
	return s, nil
}

func (s *Service) Run(p Publisher) {
	s.publisher = p
	go s.dispatch()
	go s.publishHints()
}

func (s *Service) Context() context.Context { return s.ctx }

func (s *Service) Close() {
	s.cancel(nil)
	if s.publisher != nil {
		<-s.dispatchDone
		<-s.hintsDone
	}
	s.workers.Wait()
	s.terminals.closeAll()
	for _, a := range s.pool {
		a.close()
	}
	s.store.close()
}

func (s *Service) encode(id string, result any, err error) []byte {
	r := reply{ID: id, OK: err == nil, Result: result}
	if err != nil {
		if !errors.As(err, &r.Error) {
			s.log.Error("operation failed", "err", err)
			r.Error = &protocolError{"internal", "server could not complete the operation"}
		}
	}
	raw, marshalErr := json.Marshal(r)
	if marshalErr != nil {
		s.log.Error("encode reply", "err", marshalErr)
		raw, _ = json.Marshal(reply{ID: id, Error: &protocolError{"internal", "could not encode reply"}})
	}
	return raw
}

func decode(payload []byte) (command, error) {
	var c command
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fault("invalid_argument", "invalid command object")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, fault("invalid_argument", "expected one command object")
	}
	if !identifier.MatchString(c.ID) {
		return c, fault("invalid_argument", "invalid cmd_id")
	}
	return c, nil
}

func (s *Service) Handle(device string, payload []byte) error {
	if len(payload) > 128<<10 {
		return errors.New("command exceeds 128 KiB")
	}
	c, err := decode(payload)
	if err != nil {
		if !identifier.MatchString(c.ID) {
			var header struct {
				ID string `json:"cmd_id"`
			}
			if json.Unmarshal(payload, &header) != nil || !identifier.MatchString(header.ID) {
				return err
			}
			c.ID = header.ID
		}
		return s.publisher.Reply(device, s.encode(c.ID, nil, err))
	}
	var result any
	if !s.authorized(device) {
		return s.publisher.Reply(device, s.encode(c.ID, nil, fault("revoked", "device access revoked")))
	}
	switch c.Op {
	case "ping":
		result = map[string]any{"time": time.Now().UnixMilli(), "epoch": s.store.epoch}
	case "workspaces.list":
		ids := make([]string, 0, len(s.workspaces))
		for id := range s.workspaces {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		result = map[string]any{"workspaces": ids, "agents": []string{"codex", "antigravity"}, "epoch": s.store.epoch, "capabilities": map[string]bool{"quic_reads_v1": s.streamEnabled, "terminal": terminalAvailable(), "terminal_wait": terminalAvailable(), "thread_forget_antigravity": true, "thread_delete": true, "thread_config": true, "thread_mode": true}}
	case "directories.list":
		result, err = s.browse(c)
	case "file.read":
		result, err = s.readFile(c)
	case "terminal.read":
		return s.readTerminal(device, c)
	case "terminal.list":
		result, err = s.terminalOperation(device, c)
	case "terminal.create", "terminal.claim", "terminal.input", "terminal.resize", "terminal.close":
		if c.Epoch != s.store.epoch {
			err = fault("epoch_mismatch", "database epoch changed or was omitted")
			break
		}
		return s.liveTerminalCommand(device, c, payload)
	case "sync.pull":
		result, err = s.pull(c)
	case "thread.forget", "thread.delete", "thread.set_config", "thread.set_mode", "thread.refresh", "thread.create", "thread.open", "thread.rename", "thread.archive", "prompt.send", "turn.cancel", "permission.answer":
		if c.Epoch != s.store.epoch {
			err = fault("epoch_mismatch", "database epoch changed or was omitted; reconcile queued commands")
			break
		}
		return s.accept(device, c, payload)
	default:
		err = fault("unsupported_op", "unknown operation")
	}
	return s.publisher.Reply(device, s.encode(c.ID, result, err))
}

func (s *Service) pull(c command) (syncwire.Page, error) {
	kind, id, ok := strings.Cut(c.Scope, "/")
	if !ok || !identifier.MatchString(id) {
		return syncwire.Page{}, fault("invalid_argument", "invalid sync scope")
	}
	switch kind {
	case "threads":
		if _, err := s.workspace(id); err != nil {
			return syncwire.Page{}, err
		}
	case "thread":
		t, err := s.store.thread(s.ctx, id)
		if err != nil {
			return syncwire.Page{}, err
		}
		if _, err := s.workspace(t.Workspace); err != nil {
			return syncwire.Page{}, err
		}
	default:
		return syncwire.Page{}, fault("invalid_argument", "unknown sync scope")
	}
	if c.After < 0 || c.Through < 0 || c.Limit < 0 || c.Limit > 100 {
		return syncwire.Page{}, fault("invalid_argument", "invalid cursor or limit")
	}
	if c.Limit == 0 {
		c.Limit = 100
	}
	return s.store.pull(s.ctx, c.Scope, c.Epoch, c.After, c.Through, c.Limit)
}

func (s *Service) accept(device string, c command, payload []byte) error {
	// Compare the original bytes to distinguish retransmission from ID reuse.
	var stored, output []byte
	err := s.store.write(s.ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT OR IGNORE INTO commands(device,id,body,state) VALUES(?,?,?,'queued')", device, c.ID, payload); err != nil {
			return err
		}
		return tx.QueryRow("SELECT body,reply FROM commands WHERE device=? AND id=?", device, c.ID).Scan(&stored, &output)
	})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(stored, payload) && !bytes.Equal(stored, digest[:]) {
		return s.publisher.Reply(device, s.encode(c.ID, nil, fault("command_conflict", "cmd_id was already used with different bytes")))
	}
	if len(output) != 0 {
		return s.publisher.Reply(device, output)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *Service) dispatch() {
	defer close(s.dispatchDone)
	slots := make(chan struct{}, 32)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for s.ctx.Err() == nil {
		select {
		case slots <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		j, err := s.store.claim(s.ctx)
		if err != nil {
			<-slots
			if !errors.Is(err, sql.ErrNoRows) && s.ctx.Err() == nil {
				s.log.Error("claim command", "err", err)
			}
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
			case <-tick.C:
			}
			continue
		}
		s.workers.Go(func() {
			defer func() { <-slots }()
			s.execute(j)
		})
	}
}

func (s *Service) execute(j job) {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	c, err := decode(j.body)
	var outcome mutation
	if err == nil {
		if c.Epoch != s.store.epoch {
			err = fault("epoch_mismatch", "queued command belongs to an earlier database epoch")
		} else if !s.authorized(j.device) {
			err = fault("revoked", "device access revoked")
		} else {
			outcome, err = s.mutate(ctx, j, c)
		}
	}
	payload := s.encode(j.id, outcome.result, err)
	commit := s.store.write(context.Background(), func(tx *sql.Tx) error {
		if outcome.apply != nil {
			if err := outcome.apply(tx); err != nil {
				return err
			}
		}
		return finish(tx, j, payload)
	})
	if commit == nil && outcome.committed != nil {
		outcome.committed()
	}
	if outcome.release != nil {
		outcome.release()
	}
	if commit != nil {
		s.cancel(fmt.Errorf("commit command %s: %w", j.id, commit))
		return
	}
	s.notify(outcome.scopes...)
	s.send(j.device, payload)
}

func (s *Service) send(device string, payload []byte) {
	if err := s.publisher.Reply(device, payload); err != nil {
		s.log.Debug("reply publish failed", "err", err)
	}
}

func (s *Service) notify(scopes ...string) {
	s.hintsMu.Lock()
	defer s.hintsMu.Unlock()
	for _, scope := range scopes {
		s.hints[scope] = struct{}{}
	}
}

func (s *Service) publishHints() {
	defer close(s.hintsDone)
	tick := time.NewTicker(75 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			s.hintsMu.Lock()
			if len(s.hints) == 0 {
				s.hintsMu.Unlock()
				continue
			}
			for scope := range s.hints {
				for ch := range s.watchers[scope] {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
			hints := s.hints
			s.hints = make(map[string]struct{})
			s.hintsMu.Unlock()
			for scope := range hints {
				raw, _ := json.Marshal(map[string]string{"scope": scope, "epoch": s.store.epoch})
				if err := s.publisher.Event(scope, raw); err != nil {
					s.log.Debug("sync hint publish failed", "err", err)
				}
			}
		}
	}
}

type mutation struct {
	result    any
	apply     func(*sql.Tx) error
	scopes    []string
	release   func()
	committed func()
}

func (s *Service) lockThread(id string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[id] {
		return nil, fault("thread_busy", "thread already has an operation in progress")
	}
	s.busy[id] = true
	return func() { s.mu.Lock(); delete(s.busy, id); s.mu.Unlock() }, nil
}

func (s *Service) mutate(ctx context.Context, j job, c command) (mutation, error) {
	switch c.Op {
	case "thread.create":
		return s.create(ctx, c)
	case "thread.refresh":
		return s.refresh(ctx, c)
	case "turn.cancel":
		return mutation{}, s.cancelTurn(ctx, c)
	case "permission.answer":
		return s.answerPermission(j, c)
	}
	release, err := s.lockThread(c.Thread)
	if err != nil {
		return mutation{}, err
	}
	m := mutation{release: release}
	t, err := s.store.thread(ctx, c.Thread)
	if err != nil {
		return m, err
	}
	if _, err := s.workspace(t.Workspace); err != nil {
		return m, err
	}
	switch c.Op {
	case "thread.forget":
		if t.Agent != "antigravity" {
			return m, fault("unsupported", "removal without upstream deletion is only supported for Antigravity")
		}
		m = s.removeThreadRecords(t)
	case "thread.delete":
		m, err = s.deleteThread(ctx, t)
	case "thread.set_config", "thread.set_mode":
		m, err = s.changeSettings(ctx, t, c)
	case "thread.open":
		m, err = s.openThread(ctx, t)
	case "prompt.send":
		m, err = s.prompt(ctx, j, c, t)
	case "thread.rename":
		if strings.TrimSpace(c.Title) == "" || len(c.Title) > 512 {
			return m, fault("invalid_argument", "title must be 1 to 512 bytes")
		}
		t.Title, t.Updated = c.Title, now()
		m = patch(t)
	case "thread.archive":
		if c.Archived == nil {
			return m, fault("invalid_argument", "archived is required")
		}
		t.Archived, t.Updated = *c.Archived, now()
		m = patch(t)
	}
	m.release = release
	return m, err
}

func patch(t thread) mutation {
	return mutation{result: t, scopes: []string{"threads/" + t.Workspace}, apply: func(tx *sql.Tx) error { return putThread(tx, t) }}
}

func (s *Service) adapter(name string) (*adapter, error) {
	if name == "" {
		name = "codex"
	}
	a := s.pool[name]
	if a == nil {
		return nil, fault("invalid_argument", fmt.Sprintf("unknown agent %q", name))
	}
	return a, nil
}
