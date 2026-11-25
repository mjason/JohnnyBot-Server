// Package agent runs an ACP agent as a child process and talks ACP v1 to it.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	acp "github.com/coder/acp-go-sdk"
)

// Spec says how to start an agent.
type Spec struct {
	Name    string
	Command string
	Args    []string
	Env     []string // added to the environment of this process
}

// Presets are the built-in agents. Both always run the latest published adapter.
var Presets = map[string]Spec{
	"codex": {Name: "codex", Command: "npx", Args: []string{"-y", "@agentclientprotocol/codex-acp@latest"}, Env: []string{"NO_BROWSER=1"}},
	"pi":    {Name: "pi", Command: "npx", Args: []string{"-y", "pi-acp@latest"}},
}

// Handler receives what the agent sends.
type Handler interface {
	// Update is called in arrival order from one goroutine. It may block: updates
	// queue up behind it without stalling the ACP connection.
	Update(acp.SessionNotification)
	// Permission blocks until the user answers. ctx ends when the turn is
	// cancelled or the agent goes away; any error is answered as "cancelled".
	Permission(ctx context.Context, req acp.RequestPermissionRequest) (acp.PermissionOptionId, error)
}

// Agent is one ACP connection.
type Agent struct {
	Info acp.InitializeResponse

	conn    *acp.ClientSideConnection
	h       Handler
	updates *queue
	stop    func() error

	mu      sync.Mutex
	nextID  int
	pending map[acp.SessionId]map[int]context.CancelFunc // open permission requests
}

// Start launches the agent and initializes the connection. ctx bounds only the
// startup, which includes the npx download.
func Start(ctx context.Context, spec Spec, h Handler, log *slog.Logger) (*Agent, error) {
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = append(os.Environ(), spec.Env...)
	// npx starts node, which starts codex: signal the group to reach them all.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stderr = &lineLogger{log: log, agent: spec.Name}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// A pipe of our own: cmd.StdoutPipe is closed by Wait, which can lose output.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("start %s: %w", spec.Name, err)
	}
	pw.Close()

	exited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		log.Info("agent exited", "agent", spec.Name, "err", errText(err))
		close(exited)
	}()
	stop := func() error {
		stdin.Close() // a well-behaved agent exits on EOF
		pid := cmd.Process.Pid
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			syscall.Kill(-pid, syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
			}
		}
		syscall.Kill(-pid, syscall.SIGKILL) // whatever is left of the group
		<-exited
		return pr.Close()
	}
	a, err := connect(ctx, stdin, pr, h, log, stop)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", spec.Name, err)
	}
	return a, nil
}

func connect(ctx context.Context, w io.Writer, r io.Reader, h Handler, log *slog.Logger, stop func() error) (*Agent, error) {
	a := &Agent{h: h, updates: newQueue(h.Update), stop: stop, pending: map[acp.SessionId]map[int]context.CancelFunc{}}
	a.conn = acp.NewClientSideConnection(&client{a}, w, r)
	a.conn.SetLogger(log)
	info, err := a.conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientInfo:      &acp.Implementation{Name: "johnny_bot", Version: "0.1.0"},
		// No fs or terminal: the agent works on the host itself.
	})
	if err == nil && info.ProtocolVersion != acp.ProtocolVersionNumber {
		err = fmt.Errorf("agent speaks ACP v%v, want v%v", info.ProtocolVersion, acp.ProtocolVersionNumber)
	}
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	a.Info = info
	return a, nil
}

// Done is closed when the connection ends, for example when the agent crashes.
func (a *Agent) Done() <-chan struct{} { return a.conn.Done() }

// Close stops the agent and everything it started.
func (a *Agent) Close() error {
	err := a.stop()
	a.updates.close()
	return err
}

func (a *Agent) NewSession(ctx context.Context, cwd string) (acp.NewSessionResponse, error) {
	return a.conn.NewSession(ctx, acp.NewSessionRequest{Cwd: cwd, McpServers: []acp.McpServer{}})
}

// Open returns the current settings negotiated when attaching to an existing session.
func (a *Agent) Open(ctx context.Context, id acp.SessionId, cwd string) (acp.NewSessionResponse, error) {
	if a.Info.AgentCapabilities.SessionCapabilities.Resume != nil {
		out, err := a.conn.ResumeSession(ctx, acp.ResumeSessionRequest{SessionId: id, Cwd: cwd, McpServers: []acp.McpServer{}})
		return acp.NewSessionResponse{SessionId: id, Meta: out.Meta, ConfigOptions: out.ConfigOptions, Modes: out.Modes}, err
	}
	return a.LoadHistory(ctx, id, cwd)
}

func (a *Agent) CanDelete() bool { return a.Info.AgentCapabilities.SessionCapabilities.Delete != nil }

func (a *Agent) Delete(ctx context.Context, id acp.SessionId) error {
	_, err := a.conn.DeleteSession(ctx, acp.DeleteSessionRequest{SessionId: id})
	return err
}
func (a *Agent) SetConfig(ctx context.Context, req acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	return a.conn.SetSessionConfigOption(ctx, req)
}
func (a *Agent) SetMode(ctx context.Context, id acp.SessionId, mode acp.SessionModeId) error {
	_, err := a.conn.SetSessionMode(ctx, acp.SetSessionModeRequest{SessionId: id, ModeId: mode})
	return err
}

// List returns all sessions, following the pages.
func (a *Agent) List(ctx context.Context) ([]acp.SessionInfo, error) {
	if a.Info.AgentCapabilities.SessionCapabilities.List == nil {
		return nil, errors.New("agent cannot list sessions")
	}
	var all []acp.SessionInfo
	var req acp.ListSessionsRequest
	for {
		resp, err := a.conn.ListSessions(ctx, req)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Sessions...)
		if resp.NextCursor == nil || *resp.NextCursor == "" {
			return all, nil
		}
		if req.Cursor != nil && *req.Cursor == *resp.NextCursor {
			return nil, errors.New("agent repeated a session/list cursor")
		}
		req.Cursor = resp.NextCursor
	}
}

// Prompt runs one turn. When it returns, Handler.Update has seen every update of
// the turn. To stop a turn call Cancel and keep waiting here.
func (a *Agent) Prompt(ctx context.Context, id acp.SessionId, blocks ...acp.ContentBlock) (acp.PromptResponse, error) {
	if err := ctx.Err(); err != nil {
		return acp.PromptResponse{}, err
	}
	resp, err := a.conn.Prompt(ctx, acp.PromptRequest{SessionId: id, Prompt: blocks})
	a.updates.flush()
	return resp, err
}

// Cancel stops the running turn. ACP requires the client to answer the open
// permission requests of the session with "cancelled".
func (a *Agent) Cancel(ctx context.Context, id acp.SessionId) error {
	err := a.conn.Cancel(ctx, acp.CancelNotification{SessionId: id})
	a.mu.Lock()
	for _, cancel := range a.pending[id] {
		cancel()
	}
	a.mu.Unlock()
	return err
}

func (a *Agent) trackPermission(ctx context.Context, id acp.SessionId) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.nextID
	a.nextID++
	if a.pending[id] == nil {
		a.pending[id] = map[int]context.CancelFunc{}
	}
	a.pending[id][n] = cancel
	return ctx, func() {
		cancel()
		a.mu.Lock()
		defer a.mu.Unlock()
		delete(a.pending[id], n)
		if len(a.pending[id]) == 0 {
			delete(a.pending, id)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// LoadHistory attaches the session and asks the adapter to replay its history.
func (a *Agent) LoadHistory(ctx context.Context, id acp.SessionId, cwd string) (acp.NewSessionResponse, error) {
	if !a.Info.AgentCapabilities.LoadSession {
		return acp.NewSessionResponse{}, errors.New("agent does not advertise history replay")
	}
	out, err := a.conn.LoadSession(ctx, acp.LoadSessionRequest{SessionId: id, Cwd: cwd, McpServers: []acp.McpServer{}})
	a.updates.flush()
	return acp.NewSessionResponse{SessionId: id, Meta: out.Meta, ConfigOptions: out.ConfigOptions, Modes: out.Modes}, err
}
