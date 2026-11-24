package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"
)

// fakeAgent embeds the interface: only the methods the tests use exist.
type fakeAgent struct {
	acp.Agent
	conn *acp.AgentSideConnection
}

func (f *fakeAgent) Initialize(context.Context, acp.InitializeRequest) (acp.InitializeResponse, error) {
	return acp.InitializeResponse{ProtocolVersion: acp.ProtocolVersionNumber, AuthMethods: []acp.AuthMethod{},
		AgentCapabilities: acp.AgentCapabilities{SessionCapabilities: acp.SessionCapabilities{List: &acp.SessionListCapabilities{}}}}, nil
}

func (f *fakeAgent) Cancel(context.Context, acp.CancelNotification) error {
	return nil
}

func (f *fakeAgent) ListSessions(_ context.Context, r acp.ListSessionsRequest) (acp.ListSessionsResponse, error) {
	if r.Cursor == nil {
		return acp.ListSessionsResponse{Sessions: []acp.SessionInfo{{SessionId: "a", Cwd: "/"}}, NextCursor: acp.Ptr("2")}, nil
	}
	return acp.ListSessionsResponse{Sessions: []acp.SessionInfo{{SessionId: "b", Cwd: "/"}}}, nil
}

func (f *fakeAgent) Prompt(ctx context.Context, r acp.PromptRequest) (acp.PromptResponse, error) {
	if r.Prompt[0].Text.Text == "ask" {
		resp, err := f.conn.RequestPermission(context.WithoutCancel(ctx), acp.RequestPermissionRequest{SessionId: r.SessionId,
			ToolCall: acp.ToolCallUpdate{ToolCallId: "t"},
			Options:  []acp.PermissionOption{{OptionId: "yes", Name: "Yes", Kind: acp.PermissionOptionKindAllowOnce}}})
		if err != nil {
			return acp.PromptResponse{}, err
		}
		if resp.Outcome.Selected != nil {
			return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
		}
		return acp.PromptResponse{StopReason: acp.StopReasonCancelled}, nil
	}
	for i := 0; i < 3000; i++ {
		if err := f.conn.SessionUpdate(ctx, acp.SessionNotification{SessionId: r.SessionId, Update: acp.UpdateAgentMessageText(fmt.Sprintf("%d,", i))}); err != nil {
			return acp.PromptResponse{}, err
		}
	}
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
}

type testHandler struct {
	mu    sync.Mutex
	text  strings.Builder
	delay time.Duration
	asked chan struct{}
	perm  func(context.Context) (acp.PermissionOptionId, error)
}

func (h *testHandler) Update(n acp.SessionNotification) {
	time.Sleep(h.delay)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.text.WriteString(n.Update.AgentMessageChunk.Content.Text.Text)
}

func (h *testHandler) Permission(ctx context.Context, _ acp.RequestPermissionRequest) (acp.PermissionOptionId, error) {
	close(h.asked)
	return h.perm(ctx)
}

func start(t *testing.T, h *testHandler) *Agent {
	t.Helper()
	h.asked = make(chan struct{})
	ar, cw := io.Pipe()
	cr, aw := io.Pipe()
	f := &fakeAgent{}
	f.conn = acp.NewAgentSideConnection(f, aw, ar)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := connect(ctx, cw, cr, h, slog.New(slog.DiscardHandler), func() error { cw.Close(); return aw.Close() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// More updates than the SDK queues by default, with a handler slower than the agent.
func TestPromptDeliversAllUpdatesInOrder(t *testing.T) {
	h := &testHandler{delay: 100 * time.Microsecond}
	a := start(t, h)
	if _, err := a.Prompt(context.Background(), "s", acp.TextBlock("go")); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&want, "%d,", i)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.text.String() != want.String() {
		t.Fatal("updates missing or out of order when Prompt returned")
	}
}

func TestPermissionAnswers(t *testing.T) {
	h := &testHandler{perm: func(context.Context) (acp.PermissionOptionId, error) { return "yes", nil }}
	resp, err := start(t, h).Prompt(context.Background(), "s", acp.TextBlock("ask"))
	if err != nil || resp.StopReason != acp.StopReasonEndTurn {
		t.Fatal(resp.StopReason, err)
	}
}

// An answer that was not offered must not be sent as a selection.
func TestUnknownOptionIsCancelled(t *testing.T) {
	h := &testHandler{perm: func(context.Context) (acp.PermissionOptionId, error) { return "root", nil }}
	resp, err := start(t, h).Prompt(context.Background(), "s", acp.TextBlock("ask"))
	if err != nil || resp.StopReason != acp.StopReasonCancelled {
		t.Fatal(resp.StopReason, err)
	}
}

func TestCancelReleasesOpenPermission(t *testing.T) {
	h := &testHandler{perm: func(ctx context.Context) (acp.PermissionOptionId, error) { <-ctx.Done(); return "", ctx.Err() }}
	a := start(t, h)
	go func() { <-h.asked; a.Cancel(context.Background(), "s") }()
	resp, err := a.Prompt(context.Background(), "s", acp.TextBlock("ask"))
	if err != nil || resp.StopReason != acp.StopReasonCancelled {
		t.Fatal(resp.StopReason, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) != 0 {
		t.Fatal("permission still tracked")
	}
}

func TestListFollowsPages(t *testing.T) {
	got, err := start(t, &testHandler{}).List(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
}

func TestOpenWithoutCapability(t *testing.T) {
	if _, err := start(t, &testHandler{}).Open(context.Background(), "s", "/"); err == nil {
		t.Fatal("want an error")
	}
}
