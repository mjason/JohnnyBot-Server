package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"
	mqttpacket "github.com/eclipse/paho.golang/packets"
	"github.com/eclipse/paho.golang/paho"
	"golang.org/x/crypto/ssh"

	"johnny_bot/internal/agent"
	"johnny_bot/internal/broker"
	"johnny_bot/internal/keyauth"
	"johnny_bot/internal/replica"
	"johnny_bot/internal/syncwire"
)

type fakeProcess struct {
	handler agent.Handler
	calls   atomic.Int64
	cwd     string
}

func (f *fakeProcess) Done() <-chan struct{} { return nil }
func (f *fakeProcess) Close() error          { return nil }
func (f *fakeProcess) NewSession(context.Context, string) (acp.NewSessionResponse, error) {
	return acp.NewSessionResponse{SessionId: "created"}, nil
}
func (f *fakeProcess) Open(_ context.Context, id acp.SessionId, _ string) (acp.NewSessionResponse, error) {
	return acp.NewSessionResponse{SessionId: id}, nil
}
func (f *fakeProcess) CanDelete() bool                             { return true }
func (f *fakeProcess) Delete(context.Context, acp.SessionId) error { return nil }
func (f *fakeProcess) SetConfig(context.Context, acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	return acp.SetSessionConfigOptionResponse{}, nil
}
func (f *fakeProcess) SetMode(context.Context, acp.SessionId, acp.SessionModeId) error { return nil }
func (f *fakeProcess) LoadHistory(_ context.Context, id acp.SessionId, _ string) (acp.NewSessionResponse, error) {
	f.handler.Update(acp.SessionNotification{SessionId: id, Update: acp.UpdateAgentMessageText("old transcript")})
	return acp.NewSessionResponse{SessionId: id}, nil
}
func (f *fakeProcess) List(context.Context) ([]acp.SessionInfo, error) {
	return []acp.SessionInfo{{SessionId: "old", Cwd: f.cwd, Title: acp.Ptr("existing")}}, nil
}
func (f *fakeProcess) Cancel(context.Context, acp.SessionId) error { return nil }
func (f *fakeProcess) Prompt(ctx context.Context, id acp.SessionId, blocks ...acp.ContentBlock) (acp.PromptResponse, error) {
	f.calls.Add(1)
	if blocks[0].Text.Text == "approve" {
		_, err := f.handler.Permission(ctx, acp.RequestPermissionRequest{
			SessionId: id, ToolCall: acp.ToolCallUpdate{ToolCallId: "tool"},
			Options: []acp.PermissionOption{{OptionId: "yes", Name: "Yes", Kind: acp.PermissionOptionKindAllowOnce}},
		})
		if err != nil {
			return acp.PromptResponse{StopReason: acp.StopReasonCancelled}, nil
		}
	}
	f.handler.Update(acp.SessionNotification{SessionId: id, Update: acp.UpdateAgentMessageText(strings.Repeat("z", 120<<10))})
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
}

type mqttDevice struct {
	id      string
	key     ed25519.PrivateKey
	conn    net.Conn
	client  *paho.Client
	replies chan []byte
	hints   chan string
}

func newDevice(t *testing.T) (*mqttDevice, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &mqttDevice{id: keyauth.DeviceID(pub), key: key}, ssh.MarshalAuthorizedKey(pk)
}

func (d *mqttDevice) connect(t *testing.T, addr, fingerprint string, scopes ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(s tls.ConnectionState) error {
			if broker.HostFingerprint(tls.Certificate{Certificate: [][]byte{s.PeerCertificates[0].Raw}}) != fingerprint {
				return errors.New("unexpected certificate")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	d.conn = c
	replies, hints := make(chan []byte, 32), make(chan string, 32)
	d.replies, d.hints = replies, hints
	d.client = paho.NewClient(paho.ClientConfig{Conn: mqttpacket.NewThreadSafeConn(c),
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){func(p paho.PublishReceived) (bool, error) {
			if strings.Contains(p.Packet.Topic, "/reply/") {
				replies <- p.Packet.Payload
			} else {
				select {
				case hints <- p.Packet.Topic:
				default:
				}
			}
			return true, nil
		}},
	})
	_, err = d.client.Connect(ctx, &paho.Connect{
		ClientID: d.id, KeepAlive: 30, CleanStart: true,
		UsernameFlag: true, Username: keyauth.Scheme,
		PasswordFlag: true, Password: []byte(keyauth.Sign(d.key, fingerprint, time.Now())),
	})
	if err != nil {
		t.Fatal(err)
	}
	subs := []paho.SubscribeOptions{{Topic: "jb/v1/test/reply/" + d.id, QoS: 1}}
	for _, scope := range scopes {
		subs = append(subs, paho.SubscribeOptions{Topic: "jb/v1/test/ev/" + scope, QoS: 1})
	}
	if _, err = d.client.Subscribe(ctx, &paho.Subscribe{Subscriptions: subs}); err != nil {
		t.Fatal(err)
	}
}

func (d *mqttDevice) send(t *testing.T, raw []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, err := d.client.Publish(ctx, &paho.Publish{Topic: "jb/v1/test/cmd/" + d.id, QoS: 1, Payload: raw})
	if err != nil || ack.ReasonCode >= 128 {
		t.Fatalf("publish: %#v %v", ack, err)
	}
}

type testReply struct {
	ID     string          `json:"cmd_id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *protocolError  `json:"error"`
}

func (d *mqttDevice) recv(t *testing.T, id string) []byte {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case raw := <-d.replies:
			var r testReply
			decodeJSON(t, raw, &r)
			if r.ID == id {
				return raw
			}
		case <-timer.C:
			t.Fatalf("missing reply %q", id)
		}
	}
}

func (d *mqttDevice) call(t *testing.T, c command, result any) {
	t.Helper()
	d.send(t, mustJSON(t, c))
	var r testReply
	decodeJSON(t, d.recv(t, c.ID), &r)
	if !r.OK {
		t.Fatalf("%s failed: %+v", c.Op, r.Error)
	}
	if result != nil {
		decodeJSON(t, r.Result, result)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeJSON(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}

func syncDevice(t *testing.T, d *mqttDevice, c *replica.Cache, scope string) []syncwire.Event {
	t.Helper()
	ctx := context.Background()
	if err := c.Select(ctx, scope); err != nil {
		t.Fatal(err)
	}
	for {
		pos, err := c.Position(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		var p syncwire.Page
		d.call(t, command{ID: newID(), Op: "sync.pull", Scope: scope, Epoch: pos.Epoch, After: pos.After, Through: pos.Through, Limit: 2}, &p)
		if err := c.Apply(ctx, pos, p); err != nil {
			t.Fatal(err)
		}
		if !p.More && !p.Reset {
			break
		}
	}
	events, err := c.Events(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestMQTTScopedOfflineWorkflow(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	a, aKey := newDevice(t)
	b, bKey := newDevice(t)
	config := t.TempDir()
	hostCert, err := broker.LoadOrCreateCert(filepath.Join(config, "host.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fp := broker.HostFingerprint(hostCert)
	keysFile := filepath.Join(config, "authorized_keys")
	if err := os.WriteFile(keysFile, append(aKey, bKey...), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	keys, err := keyauth.Open(keysFile, fp, log)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), filepath.Join(config, "server.db"), []Workspace{{"mobile", root}, {"other", other}}, keys.Has, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	fake := &fakeProcess{cwd: root}
	s.pool["codex"].start = func(_ context.Context, h agent.Handler) (agentProcess, error) {
		fake.handler = h
		return fake, nil
	}
	brokerServer, err := broker.New("test", "127.0.0.1:0", hostCert, keys, s.Handle, log)
	if err != nil {
		t.Fatal(err)
	}
	s.Run(brokerServer)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- brokerServer.Run(ctx) }()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	addr := brokerServer.Addr().String()
	a.connect(t, addr, fp, "threads/mobile")
	b.connect(t, addr, fp, "threads/mobile")
	var ping struct{ Epoch string }
	a.call(t, command{ID: newID(), Op: "ping"}, &ping)
	epoch := ping.Epoch

	a.call(t, command{ID: newID(), Op: "thread.refresh", Workspace: "mobile", Epoch: epoch}, nil)
	a.call(t, command{ID: newID(), Op: "thread.refresh", Workspace: "other", Epoch: epoch}, nil)
	oldID := stableID("codex", "old")
	a.call(t, command{ID: newID(), Op: "thread.open", Thread: oldID, Epoch: epoch}, nil)
	var created thread
	a.call(t, command{ID: newID(), Op: "thread.create", Workspace: "mobile", Epoch: epoch, Title: "New"}, &created)
	if created.ID == "" || !created.Imported {
		t.Fatalf("invalid new thread: %+v", created)
	}
	scope := "thread/" + created.ID
	cachePath := filepath.Join(t.TempDir(), "device.db")
	cache, err := replica.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	if n := len(syncDevice(t, b, cache, "threads/mobile")); n != 3 {
		t.Fatalf("expected three list events, got %d", n)
	}
	if n := len(syncDevice(t, b, cache, "threads/other")); n != 0 {
		t.Fatalf("other workspace leaked %d events", n)
	}
	if _, err := cache.Position(ctx, scope); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unselected detail unexpectedly cached: %v", err)
	}
	if got := syncDevice(t, b, cache, "thread/"+oldID); len(got) != 2 || got[0].Kind != "session.setup" || got[1].Kind != "acp.history" {
		t.Fatalf("missing imported transcript: %v", got)
	}

	// Persist an offline command and verify it survives disconnect and restart of the client.
	b.conn.Close()
	prompt := command{ID: newID(), Op: "prompt.send", Epoch: epoch, Thread: created.ID, Prompt: []acp.ContentBlock{acp.TextBlock("approve")}}
	raw := mustJSON(t, prompt)
	if err := cache.Queue(ctx, raw); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	cache, err = replica.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if pending, held, err := cache.PendingFor(ctx, "new-epoch"); err != nil || len(pending) != 0 || held != 1 {
		t.Fatalf("epoch hold: %v %d %v", pending, held, err)
	}
	pending, held, err := cache.PendingFor(ctx, epoch)
	if err != nil || len(pending) != 1 || held != 0 || !bytes.Equal(pending[0].Payload, raw) {
		t.Fatalf("outbox: %v %d %v", pending, held, err)
	}

	b.connect(t, addr, fp, "threads/mobile", scope)
	b.send(t, pending[0].Payload)
	b.send(t, pending[0].Payload)
	var permission struct {
		ID   string `json:"permission_id"`
		Turn string `json:"turn_id"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for permission.ID == "" && time.Now().Before(deadline) {
		select {
		case hint := <-b.hints:
			if hint != "jb/v1/test/ev/"+scope {
				continue
			}
		case <-time.After(100 * time.Millisecond):
		}
		for _, e := range syncDevice(t, b, cache, scope) {
			if e.Kind == "permission.requested" {
				decodeJSON(t, e.Data, &permission)
			}
		}
	}
	if permission.ID == "" {
		t.Fatal("missing durable approval")
	}
	answer := command{ID: newID(), Op: "permission.answer", Epoch: epoch, Thread: created.ID, Turn: permission.Turn, Permission: permission.ID, Option: "yes"}
	a.call(t, answer, nil)
	answer.ID = newID()
	b.send(t, mustJSON(t, answer))
	var lost testReply
	decodeJSON(t, b.recv(t, answer.ID), &lost)
	if lost.OK || lost.Error.Code != "permission_closed" {
		t.Fatalf("second approval succeeded: %+v", lost)
	}

	b.send(t, raw)
	finished := b.recv(t, prompt.ID)
	if err := cache.Complete(ctx, finished); err != nil {
		t.Fatal(err)
	}
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("prompt ran %d times", n)
	}
	var final testReply
	decodeJSON(t, finished, &final)
	if !final.OK || !bytes.Contains(final.Result, []byte("end_turn")) {
		t.Fatalf("prompt failed: %s", finished)
	}
	if pending, _, err := cache.PendingFor(ctx, epoch); err != nil || len(pending) != 0 {
		t.Fatalf("outbox still pending: %v %v", pending, err)
	}

	var fragments []byte
	events := syncDevice(t, b, cache, scope)
	if events[len(events)-1].Kind != "turn.finished" {
		t.Fatal("missing turn completion")
	}
	for _, e := range events {
		if e.Kind == "event.fragment" {
			var p struct{ Bytes string }
			decodeJSON(t, e.Data, &p)
			part, err := base64.StdEncoding.DecodeString(p.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			fragments = append(fragments, part...)
		}
	}
	if !json.Valid(fragments) || !bytes.Contains(fragments, []byte(strings.Repeat("z", 120<<10))) {
		t.Fatalf("large streamed response lost bytes: %d bytes", len(fragments))
	}
	b.call(t, command{ID: newID(), Op: "thread.set_config", Thread: oldID, Epoch: epoch, ConfigID: "model", Value: json.RawMessage(`"test"`)}, nil)
	b.call(t, command{ID: newID(), Op: "thread.set_mode", Thread: oldID, Epoch: epoch, ModeID: "fixture"}, nil)
	configEvents := syncDevice(t, b, cache, "thread/"+oldID)
	if len(configEvents) < 2 || configEvents[len(configEvents)-2].Kind != "session.config" || configEvents[len(configEvents)-1].Kind != "session.mode" {
		t.Fatalf("missing settings sync: %v", configEvents)
	}
	b.call(t, command{ID: newID(), Op: "thread.delete", Thread: oldID, Epoch: epoch}, nil)
	b.call(t, command{ID: newID(), Op: "thread.refresh", Workspace: "mobile", Epoch: epoch}, nil)
	if _, err := s.store.thread(ctx, oldID); err == nil {
		t.Fatal("refresh resurrected deleted session")
	}
	indexEvents := syncDevice(t, b, cache, "threads/mobile")
	if len(indexEvents) == 0 || indexEvents[len(indexEvents)-1].Kind != "thread.deleted" {
		t.Fatal("missing durable list deletion")
	}
	if terminalAvailable() {
		t.Run("terminal", func(t *testing.T) { testTerminalMQTT(t, s, a, b, epoch) })
	}
	b.conn.Close()
	offline, err := cache.Events(ctx, scope, 0, 100)
	if err != nil || len(offline) != len(events) {
		t.Fatalf("offline read failed: %d %v", len(offline), err)
	}
}

func TestRecoveryAndScopedEpoch(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	folder := t.TempDir()
	path := filepath.Join(folder, "server.db")
	ws := []Workspace{{"main", folder}}
	open := func() *Service {
		t.Helper()
		s, err := Open(ctx, path, ws, func(string) bool { return true }, log)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	epoch := s.store.epoch
	if err := s.store.write(ctx, func(tx *sql.Tx) error {
		if err := putThread(tx, thread{ID: "t", Workspace: "main", Agent: "codex", Session: "abc", Path: ".", Active: "turn"}); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO permissions VALUES('p','t','turn','pending')"); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO commands(device,id,body,state) VALUES('dev','id',x'00','running')")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open()
	t.Cleanup(s.Close)
	p, err := s.pull(command{Scope: "thread/t"})
	if err != nil || len(p.Events) != 2 || p.Epoch != epoch || p.Events[0].Kind != "permission.resolved" || p.Events[1].Kind != "turn.finished" {
		t.Fatalf("recovery page: %+v %v", p, err)
	}
	p, err = s.pull(command{Scope: "thread/t", Epoch: "old", After: 17})
	if err != nil || !p.Reset || len(p.Events) != 0 {
		t.Fatalf("invalid reset: %+v %v", p, err)
	}
	var raw []byte
	if err := s.store.db.QueryRow("SELECT reply FROM commands WHERE device='dev' AND id='id'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var r testReply
	decodeJSON(t, raw, &r)
	if r.OK || r.Error.Code != "interrupted" {
		t.Fatalf("invalid recovered command reply: %s", raw)
	}
}

func TestFixedSyncWindowAndCacheReset(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openStore(ctx, filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	const scope = "threads/main"
	appendItem := func(key string, n int) {
		t.Helper()
		if err := s.write(ctx, func(tx *sql.Tx) error { return appendEvent(tx, key, "test", n) }); err != nil {
			t.Fatal(err)
		}
	}
	appendItem(scope, 1)
	appendItem("threads/other", 2)
	appendItem(scope, 3)
	first, err := s.pull(ctx, scope, "", 0, 0, 1)
	if err != nil || !first.More || first.Through != 3 || len(first.Events) != 1 {
		t.Fatalf("first page: %+v %v", first, err)
	}
	appendItem(scope, 4)
	c, err := replica.Open(filepath.Join(dir, "device"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Select(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, replica.Position{}, first); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, replica.Position{}, first); err == nil {
		t.Fatal("reapplied delayed page")
	}
	pos, err := c.Position(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.pull(ctx, scope, pos.Epoch, pos.After, pos.Through, 10)
	if err != nil || next.More || len(next.Events) != 1 || next.Events[0].Seq != 3 {
		t.Fatalf("continuation: %+v %v", next, err)
	}
	if err := c.Apply(ctx, pos, next); err != nil {
		t.Fatal(err)
	}
	pos, err = c.Position(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	increment, err := s.pull(ctx, scope, pos.Epoch, pos.After, pos.Through, 10)
	if err != nil || len(increment.Events) != 1 || increment.Events[0].Seq != 4 {
		t.Fatalf("increment: %+v %v", increment, err)
	}
	if err := c.Apply(ctx, pos, increment); err != nil {
		t.Fatal(err)
	}
	old, err := c.Position(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	reset := syncwire.Page{Scope: scope, After: old.After, Epoch: "new-epoch", Reset: true}
	if err := c.Apply(ctx, old, reset); err != nil {
		t.Fatal(err)
	}
	items, err := c.Events(ctx, scope, 0, 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("reset kept stale events: %v %v", items, err)
	}
}

func TestProjectFileIsConfinedAndVersioned(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	project := filepath.Join(root, "app")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(other, "private")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(project, "outside")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(project, "example.txt")
	if err := os.WriteFile(file, bytes.Repeat([]byte{'x'}, 64<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "db"), []Workspace{{"main", root}}, func(string) bool { return true }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.store.write(ctx, func(tx *sql.Tx) error {
		return putThread(tx, thread{ID: "test", Workspace: "main", Agent: "codex", Session: "test", Path: "app"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readFile(command{Thread: "test", Path: "outside/private"}); err == nil {
		t.Fatal("escaped the project root")
	}
	if _, err := s.browse(command{Workspace: "main", Path: "app/outside"}); err == nil {
		t.Fatal("escaped the workspace root")
	}
	for _, c := range []command{
		{Workspace: "main", Path: "app/example.txt"},
		{Path: file},
		{Thread: "test", Path: "../app/example.txt"},
	} {
		if _, err := s.readFile(c); err != nil {
			t.Fatalf("workspace read %+v: %v", c, err)
		}
	}
	for _, c := range []command{
		{Path: outside},
		{Workspace: "main", Path: "app/outside/private"},
		{Path: filepath.Join(project, "outside", "private")},
		{Thread: "test", Path: "../../" + filepath.Base(other) + "/private"},
	} {
		if _, err := s.readFile(c); err == nil {
			t.Fatalf("escaped workspace: %+v", c)
		}
	}
	val, err := s.readFile(command{Thread: "test", Path: "example.txt"})
	if err != nil {
		t.Fatal(err)
	}
	first := val.(map[string]any)
	if first["more"] != true || first["next_offset"] != int64(48<<10) {
		t.Fatalf("invalid first page: %v %v", first["more"], first["next_offset"])
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte{'y'}, 65<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.readFile(command{Thread: "test", Path: "example.txt", Offset: first["next_offset"].(int64), Version: first["version"].(string)})
	var protocolErr *protocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != "file_changed" {
		t.Fatalf("stale file version accepted: %v", err)
	}
}
