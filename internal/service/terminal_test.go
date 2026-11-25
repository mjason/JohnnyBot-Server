package service

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testTerminalMQTT(t *testing.T, s *Service, a, b *mqttDevice, epoch string) {
	var created struct{ Terminal terminalInfo }
	a.call(t, command{ID: newID(), Op: "terminal.create", Epoch: epoch, Workspace: "mobile", Path: ".", Cols: 80, Rows: 24}, &created)
	id := created.Terminal.ID
	if id == "" || !created.Terminal.Running {
		t.Fatalf("invalid new tab: %+v", created)
	}
	call := func(d *mqttDevice, op string, out any) {
		d.call(t, command{ID: newID(), Op: op, Epoch: epoch, Terminal: id}, out)
	}
	a.call(t, command{ID: newID(), Op: "terminal.create", Epoch: epoch, Workspace: "other", Cols: 80, Rows: 24}, nil)
	var list struct{ Terminals []terminalInfo }
	b.call(t, command{ID: newID(), Op: "terminal.list", Workspace: "mobile"}, &list)
	if len(list.Terminals) != 1 || list.Terminals[0].ID != id {
		t.Fatalf("unexpected tabs: %+v", list)
	}
	call(b, "terminal.claim", &created)
	write := command{ID: newID(), Op: "terminal.input", Terminal: id, Epoch: epoch, Bytes: []byte("printf '\\n__JB_%s__\\n' PTY; pwd; stty size\n")}
	a.send(t, mustJSON(t, write))
	var denied testReply
	decodeJSON(t, a.recv(t, write.ID), &denied)
	if denied.OK || denied.Error.Code != "not_controller" {
		t.Fatalf("lost claim: %+v", denied)
	}
	b.call(t, command{ID: newID(), Op: "terminal.resize", Epoch: epoch, Terminal: id, Cols: 99, Rows: 35}, nil)
	b.call(t, write, nil)
	b.call(t, write, nil)
	var raw []byte
	if err := s.store.db.QueryRow("SELECT body FROM commands WHERE id=? AND state='done' LIMIT 1", write.ID).Scan(&raw); err != nil || len(raw) != 32 {
		t.Fatal("terminal input retained in command inbox", err)
	}
	var offset int64
	var output strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var page struct {
			Bytes []byte
			Next  int64 `json:"next_offset"`
			Reset bool
		}
		a.call(t, command{ID: newID(), Op: "terminal.read", Terminal: id, Offset: offset}, &page)
		if page.Reset || page.Next != offset+int64(len(page.Bytes)) {
			t.Fatal("incorrect terminal read cursor")
		}
		offset = page.Next
		output.Write(page.Bytes)
		if strings.Contains(output.String(), "35 99") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	text := output.String()
	if strings.Count(text, "__JB_PTY__") != 1 || !strings.Contains(text, "/workspace") || !strings.Contains(text, "35 99") {
		t.Fatalf("invalid terminal output: %q", text)
	}
	call(b, "terminal.close", nil)
	b.call(t, command{ID: newID(), Op: "terminal.list", Workspace: "mobile"}, &list)
	if len(list.Terminals) != 0 {
		t.Fatal("closed tab retained")
	}
}

func TestOutputRingResetAtByteBoundary(t *testing.T) {
	s := &Service{}
	tab := &terminal{ring: make([]byte, 8), info: terminalInfo{ID: "tab"}}
	s.terminals.tabs = map[string]*terminal{"tab": tab}
	tab.append([]byte("abcdef"))
	tab.append([]byte("ghijkl"))
	got, err := s.terminalOperation("a", command{Op: "terminal.read", Terminal: "tab", Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	var p struct {
		Bytes []byte
		Reset bool
		Next  int `json:"next_offset"`
		First int `json:"first_offset"`
	}
	if err = json.Unmarshal(raw, &p); err != nil || !p.Reset || p.First != 4 || p.Next != 12 || !bytes.Equal(p.Bytes, []byte("efghijkl")) {
		t.Fatalf("wrapped read: %+v %v", p, err)
	}
}

func TestWaitingTerminalRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replies := make(chan []byte, 4)
	tab := &terminal{info: terminalInfo{ID: "tab", Running: true}, ring: make([]byte, 32), done: make(chan struct{})}
	s := &Service{ctx: ctx, publisher: terminalTestReplies{replies}, authorized: func(string) bool { return true }, terminalReaders: make(chan struct{}, 4)}
	s.terminals.tabs = map[string]*terminal{"tab": tab}
	read := command{Op: "terminal.read", Terminal: "tab", WaitMS: 2000}
	for _, id := range []string{"one", "two"} {
		read.ID = id
		if err := s.readTerminal(id, read); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-replies:
		t.Fatal("idle read returned early")
	default:
	}
	tab.append([]byte("echo"))
	for range 2 {
		select {
		case raw := <-replies:
			var r struct {
				OK     bool
				Result struct {
					Bytes []byte
					Next  int `json:"next_offset"`
				}
			}
			if err := json.Unmarshal(raw, &r); err != nil || !r.OK || string(r.Result.Bytes) != "echo" || r.Result.Next != 4 {
				t.Fatalf("incorrect wakeup: %s", raw)
			}
		case <-time.After(time.Second):
			t.Fatal("output did not wake both waiting clients")
		}
	}
	read.Offset = 4
	read.WaitMS = 10
	if err := s.readTerminal("one", read); err != nil {
		t.Fatal(err)
	}
	select {
	case <-replies:
	case <-time.After(time.Second):
		t.Fatal("read did not time out")
	}
	read.WaitMS = 2000
	if err := s.readTerminal("one", read); err != nil {
		t.Fatal(err)
	}
	tab.mu.Lock()
	tab.info.Running = false
	tab.mu.Unlock()
	close(tab.done)
	select {
	case raw := <-replies:
		if !bytes.Contains(raw, []byte(`"running":false`)) {
			t.Fatalf("missing exit: %s", raw)
		}
	case <-time.After(time.Second):
		t.Fatal("exit did not wake reader")
	}
	s.workers.Wait()
}

type terminalTestReplies struct{ ch chan []byte }

func (p terminalTestReplies) Reply(_ string, payload []byte) error { p.ch <- payload; return nil }
func (p terminalTestReplies) Event(string, []byte) error           { return nil }
