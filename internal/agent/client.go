package agent

import (
	"bytes"
	"context"
	"log/slog"
	"sync"

	acp "github.com/coder/acp-go-sdk"
)

// client is the side of the connection that the agent calls.
type client struct{ a *Agent }

var _ acp.Client = (*client)(nil)

// SessionUpdate only queues: the SDK closes the connection when notifications
// pile up behind a slow handler.
func (c *client) SessionUpdate(_ context.Context, n acp.SessionNotification) error {
	c.a.updates.push(n)
	return nil
}

func (c *client) RequestPermission(ctx context.Context, req acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	ctx, done := c.a.trackPermission(ctx, req.SessionId)
	defer done()
	cancelled := acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Cancelled: &acp.RequestPermissionOutcomeCancelled{}}}
	c.a.updates.flush() // the user sees what led to the question first
	id, err := c.a.h.Permission(ctx, req)
	if err != nil || ctx.Err() != nil {
		return cancelled, nil
	}
	for _, o := range req.Options {
		if o.OptionId == id {
			return acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Selected: &acp.RequestPermissionOutcomeSelected{OptionId: id}}}, nil
		}
	}
	return cancelled, nil // not an offered option
}

func (c *client) ReadTextFile(context.Context, acp.ReadTextFileRequest) (r acp.ReadTextFileResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodFsReadTextFile)
}
func (c *client) WriteTextFile(context.Context, acp.WriteTextFileRequest) (r acp.WriteTextFileResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodFsWriteTextFile)
}
func (c *client) CreateTerminal(context.Context, acp.CreateTerminalRequest) (r acp.CreateTerminalResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodTerminalCreate)
}
func (c *client) KillTerminal(context.Context, acp.KillTerminalRequest) (r acp.KillTerminalResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodTerminalKill)
}
func (c *client) TerminalOutput(context.Context, acp.TerminalOutputRequest) (r acp.TerminalOutputResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodTerminalOutput)
}
func (c *client) ReleaseTerminal(context.Context, acp.ReleaseTerminalRequest) (r acp.ReleaseTerminalResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodTerminalRelease)
}
func (c *client) WaitForTerminalExit(context.Context, acp.WaitForTerminalExitRequest) (r acp.WaitForTerminalExitResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodTerminalWaitForExit)
}
func (c *client) CreateElicitation(context.Context, acp.CreateElicitationRequest) (r acp.CreateElicitationResponse, err error) {
	return r, acp.NewMethodNotFound(acp.ClientMethodElicitationCreate)
}
func (c *client) CompleteElicitation(context.Context, acp.CompleteElicitationNotification) error {
	return nil
}

// queue hands updates to fn one at a time, in order.
type queue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []any // acp.SessionNotification, or chan struct{} for flush
	closed bool
	done   chan struct{}
}

func newQueue(fn func(acp.SessionNotification)) *queue {
	q := &queue{done: make(chan struct{})}
	q.cond = sync.NewCond(&q.mu)
	go func() {
		defer close(q.done)
		for {
			q.mu.Lock()
			for len(q.items) == 0 && !q.closed {
				q.cond.Wait()
			}
			batch := q.items
			q.items = nil
			q.mu.Unlock()
			if len(batch) == 0 {
				return // closed and drained
			}
			for _, it := range batch {
				switch it := it.(type) {
				case acp.SessionNotification:
					fn(it)
				case chan struct{}:
					close(it)
				}
			}
		}
	}()
	return q
}

func (q *queue) push(it any) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.items = append(q.items, it)
	q.cond.Signal()
	return true
}

// flush waits until everything pushed before it was handled.
func (q *queue) flush() {
	ch := make(chan struct{})
	if q.push(ch) {
		<-ch
	}
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Signal()
	q.mu.Unlock()
	<-q.done
}

// lineLogger logs the agent's stderr line by line.
type lineLogger struct {
	log   *slog.Logger
	agent string
	buf   []byte
}

func (l *lineLogger) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			if len(l.buf) > 64<<10 { // never hold an endless line
				l.buf = l.buf[:0]
			}
			return len(p), nil
		}
		l.log.Info("agent stderr", "agent", l.agent, "line", string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
}
