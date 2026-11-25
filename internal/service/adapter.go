package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"johnny_bot/internal/agent"
)

type agentProcess interface {
	Done() <-chan struct{}
	Close() error
	NewSession(context.Context, string) (acp.NewSessionResponse, error)
	Open(context.Context, acp.SessionId, string) (acp.NewSessionResponse, error)
	LoadHistory(context.Context, acp.SessionId, string) (acp.NewSessionResponse, error)
	CanDelete() bool
	Delete(context.Context, acp.SessionId) error
	SetConfig(context.Context, acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error)
	SetMode(context.Context, acp.SessionId, acp.SessionModeId) error
	List(context.Context) ([]acp.SessionInfo, error)
	Prompt(context.Context, acp.SessionId, ...acp.ContentBlock) (acp.PromptResponse, error)
	Cancel(context.Context, acp.SessionId) error
}

type adapter struct {
	service *Service
	gate    chan struct{}
	start   func(context.Context, agent.Handler) (agentProcess, error)
	current *agentRun
}

type agentRun struct {
	adapter  *adapter
	process  agentProcess
	mu       sync.Mutex
	attached map[acp.SessionId]bool
	streams  map[acp.SessionId]*stream
}

type sessionSetup struct {
	SessionID     acp.SessionId             `json:"sessionId"`
	Meta          acp.Meta                  `json:"_meta,omitempty"`
	ConfigOptions []acp.SessionConfigOption `json:"configOptions,omitempty"`
	Modes         *acp.SessionModeState     `json:"modes,omitempty"`
	CanDelete     bool                      `json:"canDelete"`
}

func setup(out acp.NewSessionResponse, canDelete bool) sessionSetup {
	return sessionSetup{out.SessionId, out.Meta, out.ConfigOptions, out.Modes, canDelete}
}

type stream struct {
	agentTitle  string
	setup       *sessionSetup
	thread      thread
	turn        string
	replay      []json.RawMessage
	replayBytes int
	isReplay    bool
	err         error
}

func newAdapter(s *Service, spec agent.Spec) *adapter {
	return &adapter{service: s, gate: make(chan struct{}, 1), start: func(ctx context.Context, h agent.Handler) (agentProcess, error) {
		return agent.Start(ctx, spec, h, s.log)
	}}
}

func (a *adapter) get(ctx context.Context) (*agentRun, error) {
	select {
	case a.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-a.gate }()
	if a.current != nil {
		select {
		case <-a.current.process.Done():
			a.current.process.Close()
			a.current = nil
		default:
			return a.current, nil
		}
	}
	run := &agentRun{adapter: a, attached: make(map[acp.SessionId]bool), streams: make(map[acp.SessionId]*stream)}
	process, err := a.start(ctx, run)
	if err != nil {
		return nil, err
	}
	run.process = process
	a.current = run
	return run, nil
}

func (a *adapter) close() {
	if a.current != nil {
		a.current.process.Close()
	}
}

func (r *agentRun) attach(ctx context.Context, t thread, cwd string) (*stream, error) {
	id := acp.SessionId(t.Session)
	r.mu.Lock()
	attached := r.attached[id]
	r.mu.Unlock()
	if attached {
		return nil, nil
	}
	var history *stream
	if !t.Imported {
		history = &stream{thread: t, isReplay: true}
		r.setStream(id, history)
		out, err := r.process.LoadHistory(ctx, id, cwd)
		state := setup(out, r.process.CanDelete())
		history.setup = &state
		r.setStream(id, nil)
		if err != nil {
			r.adapter.service.log.Warn("load agent history", "thread", t.ID, "err", err)
			history = nil
		}
	}
	if history == nil {
		out, err := r.process.Open(ctx, id, cwd)
		if err != nil {
			return nil, err
		}
		state := setup(out, r.process.CanDelete())
		history = &stream{thread: t, setup: &state}
	}
	return history, nil
}

func (r *agentRun) markAttached(id acp.SessionId) {
	r.mu.Lock()
	r.attached[id] = true
	r.mu.Unlock()
}

func (r *agentRun) setStream(id acp.SessionId, st *stream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st == nil {
		delete(r.streams, id)
		return
	}
	r.streams[id] = st
}

func (r *agentRun) Update(n acp.SessionNotification) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.streams[n.SessionId]
	if st == nil {
		return
	}
	if st.err != nil {
		return
	}
	if st.isReplay {
		raw, err := json.Marshal(n)
		if err != nil {
			st.err = err
			return
		}
		if len(st.replay) >= 20000 || st.replayBytes+len(raw) > 32<<20 {
			st.err = fault("history_too_large", "agent replay exceeds this server's import limit")
			return
		}
		st.replay = append(st.replay, raw)
		st.replayBytes += len(raw)
		return
	}
	if info := n.Update.SessionInfoUpdate; info != nil {
		if title, ok := info.Title.Value(); ok && strings.TrimSpace(title) != "" {
			st.agentTitle = strings.TrimSpace(title)
		}
	}
	s := r.adapter.service
	scope := "thread/" + st.thread.ID
	st.err = s.store.write(context.Background(), func(tx *sql.Tx) error {
		return appendEvent(tx, scope, "acp.update", map[string]any{"turn_id": st.turn, "notification": n})
	})
	if st.err == nil {
		s.notify(scope)
	}
}

func (r *agentRun) Permission(ctx context.Context, req acp.RequestPermissionRequest) (acp.PermissionOptionId, error) {
	r.mu.Lock()
	st := r.streams[req.SessionId]
	r.mu.Unlock()
	if st == nil || st.isReplay {
		return "", errors.New("no active turn")
	}
	return r.adapter.service.requestPermission(ctx, st, req)
}

func (s *Service) create(ctx context.Context, c command) (mutation, error) {
	w, err := s.workspace(c.Workspace)
	if err != nil {
		return mutation{}, err
	}
	if len(c.Title) > 512 {
		return mutation{}, fault("invalid_argument", "title exceeds 512 bytes")
	}
	cwd, rel, err := w.directory(c.Path)
	if err != nil {
		return mutation{}, err
	}
	a, err := s.adapter(c.Agent)
	if err != nil {
		return mutation{}, err
	}
	if c.Agent == "" {
		c.Agent = "codex"
	}
	r, err := a.get(ctx)
	if err != nil {
		return mutation{}, err
	}
	out, err := r.process.NewSession(ctx, cwd)
	if err != nil {
		return mutation{}, err
	}
	if out.SessionId == "" {
		return mutation{}, errors.New("adapter returned an empty session ID")
	}
	r.markAttached(out.SessionId)
	t := thread{ID: stableID(c.Agent, string(out.SessionId)), Workspace: w.ID, Agent: c.Agent, Session: string(out.SessionId), Path: rel, Title: c.Title, Updated: now(), Imported: true}
	m := patch(t)
	apply := m.apply
	m.scopes = append(m.scopes, "thread/"+t.ID)
	m.apply = func(tx *sql.Tx) error {
		if err := apply(tx); err != nil {
			return err
		}
		return appendEvent(tx, "thread/"+t.ID, "session.setup", setup(out, r.process.CanDelete()))
	}
	return m, nil
}

func (s *Service) refresh(ctx context.Context, c command) (mutation, error) {
	if _, err := s.workspace(c.Workspace); err != nil {
		return mutation{}, err
	}
	a, err := s.adapter(c.Agent)
	if err != nil {
		return mutation{}, err
	}
	if c.Agent == "" {
		c.Agent = "codex"
	}
	r, err := a.get(ctx)
	if err != nil {
		return mutation{}, err
	}
	sessions, err := r.process.List(ctx)
	if err != nil {
		return mutation{}, err
	}
	var found []thread
	for _, info := range sessions {
		w, rel, ok := s.matchWorkspace(info.Cwd)
		if !ok || w.ID != c.Workspace || info.SessionId == "" {
			continue
		}
		t := thread{ID: stableID(c.Agent, string(info.SessionId)), Workspace: w.ID, Agent: c.Agent, Session: string(info.SessionId), Path: rel}
		if info.Title != nil {
			t.Title = *info.Title
		}
		if info.UpdatedAt != nil {
			t.Updated = *info.UpdatedAt
		}
		if info.Archived != nil {
			t.Archived = *info.Archived
		}
		found = append(found, t)
	}
	return mutation{
		result: map[string]int{"found": len(found)}, scopes: []string{"threads/" + c.Workspace},
		apply: func(tx *sql.Tx) error {
			for _, t := range found {
				var deleted bool
				if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM deleted_threads WHERE id=?)", t.ID).Scan(&deleted); err != nil {
					return err
				}
				if deleted {
					continue
				}
				_, err := scanThread(tx.QueryRow("SELECT "+threadFields+" FROM threads WHERE id=?", t.ID))
				if err == nil {
					// Existing metadata can be deliberately edited by Johnny clients.
					continue
				}
				if !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if t.Updated == "" {
					t.Updated = now()
				}
				if err := putThread(tx, t); err != nil {
					return err
				}
			}
			return nil
		},
	}, nil
}

func (s *Service) attach(ctx context.Context, t thread) (*agentRun, *stream, error) {
	w, err := s.workspace(t.Workspace)
	if err != nil {
		return nil, nil, err
	}
	cwd, _, err := w.directory(t.Path)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.adapter(t.Agent)
	if err != nil {
		return nil, nil, err
	}
	r, err := a.get(ctx)
	if err != nil {
		return nil, nil, err
	}
	history, err := r.attach(ctx, t, cwd)
	return r, history, err
}

func saveReplay(tx *sql.Tx, t thread, history *stream) error {
	if history == nil {
		return nil
	}
	if history.err != nil {
		return history.err
	}
	if history.setup != nil {
		if err := appendEvent(tx, "thread/"+t.ID, "session.setup", history.setup); err != nil {
			return err
		}
	}
	for _, n := range history.replay {
		if err := appendEvent(tx, "thread/"+t.ID, "acp.history", n); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) openThread(ctx context.Context, t thread) (mutation, error) {
	r, history, err := s.attach(ctx, t)
	if err != nil {
		return mutation{}, err
	}
	if history == nil {
		r.markAttached(acp.SessionId(t.Session))
		return mutation{result: t}, nil
	}
	if history.err != nil {
		return mutation{}, history.err
	}
	t.Imported = t.Imported || history.isReplay
	m := patch(t)
	m.scopes = append(m.scopes, "thread/"+t.ID)
	m.apply = func(tx *sql.Tx) error {
		if err := saveReplay(tx, t, history); err != nil {
			return err
		}
		return putThread(tx, t)
	}
	m.committed = func() { r.markAttached(acp.SessionId(t.Session)) }
	return m, nil
}

type turn struct {
	mu     sync.Mutex
	done   bool
	id     string
	idACP  acp.SessionId
	agent  agentProcess
	cancel context.CancelFunc
}

// Agents may omit session_info_update. Keep the first user text as a stable
// list title until the agent supplies one for the new conversation.
func promptTitle(blocks []acp.ContentBlock) string {
	for _, block := range blocks {
		if block.Text == nil {
			continue
		}
		text := strings.Join(strings.Fields(block.Text.Text), " ")
		if text == "" {
			continue
		}
		chars := []rune(text)
		if len(chars) > 60 {
			return string(chars[:59]) + "…"
		}
		return text
	}
	return ""
}

func (s *Service) prompt(ctx context.Context, j job, c command, t thread) (mutation, error) {
	if len(c.Prompt) == 0 || len(c.Prompt) > 32 {
		return mutation{}, fault("invalid_argument", "prompt must contain 1 to 32 ACP content blocks")
	}
	if t.Archived {
		return mutation{}, fault("thread_archived", "unarchive the thread before sending")
	}
	select {
	case s.turnSlots <- struct{}{}:
		defer func() { <-s.turnSlots }()
	default:
		return mutation{}, fault("server_busy", "too many turns in progress")
	}
	r, history, err := s.attach(ctx, t)
	if err != nil {
		return mutation{}, err
	}
	if history != nil && history.err != nil {
		return mutation{}, history.err
	}
	id := stableID(j.device, j.id)
	scope := "thread/" + t.ID
	listScope := "threads/" + t.Workspace
	needsTitle := strings.TrimSpace(t.Title) == ""
	if needsTitle {
		t.Title = promptTitle(c.Prompt)
	}
	t.Active, t.Updated = id, now()
	t.Imported = t.Imported || (history != nil && history.isReplay)
	turnCtx, cancel := context.WithTimeout(s.ctx, 30*time.Minute)
	defer cancel()
	tr := &turn{id: id, idACP: acp.SessionId(t.Session), agent: r.process, cancel: cancel}
	s.mu.Lock()
	s.active[t.ID] = tr
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.active, t.ID); s.mu.Unlock() }()
	err = s.store.write(ctx, func(tx *sql.Tx) error {
		if err := saveReplay(tx, t, history); err != nil {
			return err
		}
		if err := putThread(tx, t); err != nil {
			return err
		}
		if err := appendEvent(tx, scope, "turn.started", map[string]any{"turn_id": id, "device_id": j.device, "cmd_id": j.id}); err != nil {
			return err
		}
		return appendEvent(tx, scope, "message.user", map[string]any{"turn_id": id, "prompt": c.Prompt})
	})
	if err != nil {
		return mutation{}, err
	}
	r.markAttached(tr.idACP)
	st := &stream{thread: t, turn: id}
	r.setStream(tr.idACP, st)
	s.notify(scope, listScope)
	out, promptErr := r.process.Prompt(turnCtx, tr.idACP, c.Prompt...)
	tr.mu.Lock()
	tr.done = true
	tr.mu.Unlock()
	if turnCtx.Err() != nil {
		cancelCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		r.process.Cancel(cancelCtx, tr.idACP)
		stop()
	}
	r.setStream(tr.idACP, nil)
	status := "finished"
	if promptErr != nil {
		status = "failed"
	}
	if turnCtx.Err() != nil {
		status = "interrupted"
	}
	if out.StopReason == acp.StopReasonCancelled || errors.Is(turnCtx.Err(), context.Canceled) && s.ctx.Err() == nil {
		status = "cancelled"
	}
	if st.err != nil {
		status = "failed"
		promptErr = st.err
	}
	if needsTitle && st.agentTitle != "" {
		t.Title = st.agentTitle
	}
	t.Active, t.Updated = "", now()
	state := map[string]any{"turn_id": id, "status": status, "stop_reason": out.StopReason}
	m := mutation{result: state, scopes: []string{scope, listScope}, apply: func(tx *sql.Tx) error {
		if err := expireTurn(tx, t.ID, id); err != nil {
			return err
		}
		if err := putThread(tx, t); err != nil {
			return err
		}
		return appendEvent(tx, scope, "turn.finished", state)
	}}
	if promptErr != nil && status == "failed" {
		return m, fmt.Errorf("prompt: %w", promptErr)
	}
	return m, nil
}

func (s *Service) cancelTurn(ctx context.Context, c command) error {
	if c.Turn == "" {
		return fault("invalid_argument", "turn_id is required")
	}
	s.mu.Lock()
	t := s.active[c.Thread]
	s.mu.Unlock()
	if t == nil || t.id != c.Turn {
		return fault("not_active", "turn is no longer active")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return fault("not_active", "turn is no longer active")
	}
	cancelCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	err := t.agent.Cancel(cancelCtx, t.idACP)
	t.cancel()
	return err
}
