package service

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"

	acp "github.com/coder/acp-go-sdk"
	"johnny_bot/internal/agent"
)

type titleProcess struct {
	fakeProcess
	generated string
}

func (f *titleProcess) Prompt(ctx context.Context, id acp.SessionId, blocks ...acp.ContentBlock) (acp.PromptResponse, error) {
	if f.generated != "" {
		f.handler.Update(acp.SessionNotification{SessionId: id, Update: acp.SessionUpdate{SessionInfoUpdate: &acp.SessionSessionInfoUpdate{Title: acp.PatchSet(f.generated)}}})
	}
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
}

func TestFirstTurnListTitle(t *testing.T) {
	for _, tc := range []struct{ name, old, generated, want string }{
		{"agent", "", "Agent 标题", "Agent 标题"},
		{"fallback", "", "", "第一条 消息"},
		{"named", "手动命名", "Agent 标题", "手动命名"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"), []Workspace{{"default", t.TempDir()}}, func(string) bool { return true }, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.pool["codex"].start = func(_ context.Context, h agent.Handler) (agentProcess, error) {
				return &titleProcess{fakeProcess{handler: h}, tc.generated}, nil
			}
			m, err := s.create(ctx, command{Workspace: "default", Title: tc.old})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.store.write(ctx, m.apply); err != nil {
				t.Fatal(err)
			}
			row := m.result.(thread)
			m, err = s.prompt(ctx, job{device: "device", id: "cmd"}, command{Prompt: []acp.ContentBlock{acp.TextBlock("第一条\n消息")}}, row)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.store.write(ctx, m.apply); err != nil {
				t.Fatal(err)
			}
			got, err := s.store.thread(ctx, row.ID)
			if err != nil || got.Title != tc.want {
				t.Fatalf("saved title %q, err %v", got.Title, err)
			}
			// Simulate the old server persisting a blank list title after the turn.
			if tc.old == "" {
				if _, err = s.store.db.Exec("UPDATE threads SET title='' WHERE id=?", row.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.store.db.Exec("DELETE FROM meta WHERE key='session_titles_v1'"); err != nil {
				t.Fatal(err)
			}
			if err = s.store.write(ctx, func(tx *sql.Tx) error { return restoreSessionTitles(tx) }); err != nil {
				t.Fatal(err)
			}
			var listed string
			err = s.store.db.QueryRow("SELECT json_extract(CAST(body AS TEXT),'$.title') FROM events WHERE scope='threads/default' ORDER BY seq DESC LIMIT 1").Scan(&listed)
			if err != nil || listed != tc.want {
				t.Fatalf("list title after repair %q, err %v", listed, err)
			}
		})
	}
}
