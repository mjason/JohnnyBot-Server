package service

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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
	mu      sync.Mutex
	info    terminalInfo
	cmd     *exec.Cmd
	fd      *os.File
	input   chan []byte
	done    chan struct{}
	changed chan struct{}
	ring    []byte
	end     int64
}

func (t *terminal) append(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	start := int(t.end % int64(len(t.ring)))
	n := copy(t.ring[start:], data)
	copy(t.ring, data[n:])
	t.end += int64(len(data))
	if t.changed != nil {
		close(t.changed)
		t.changed = nil
	}
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

// An outstanding read must never block the broker from receiving the next keystroke.
func (s *Service) readTerminal(device string, c command) error {
	if c.WaitMS < 0 || c.WaitMS > 2000 {
		return s.publisher.Reply(device, s.encode(c.ID, nil, fault("invalid_argument", "wait_ms must be between 0 and 2000")))
	}
	reply := func() error {
		result, err := s.terminalOperation(device, c)
		return s.publisher.Reply(device, s.encode(c.ID, result, err))
	}
	if c.WaitMS == 0 {
		return reply()
	}
	s.terminals.mu.Lock()
	t := s.terminals.tabs[c.Terminal]
	s.terminals.mu.Unlock()
	if t == nil {
		return reply()
	}
	t.mu.Lock()
	if !t.info.Running || c.Offset != t.end {
		t.mu.Unlock()
		return reply()
	}
	select {
	case s.terminalReaders <- struct{}{}:
	default:
		t.mu.Unlock()
		return s.publisher.Reply(device, s.encode(c.ID, nil, fault("server_busy", "too many waiting terminal reads")))
	}
	if t.changed == nil {
		t.changed = make(chan struct{})
	}
	changed := t.changed
	t.mu.Unlock()
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer func() { <-s.terminalReaders }()
		timer := time.NewTimer(time.Duration(c.WaitMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-changed:
		case <-t.done:
		case <-timer.C:
		case <-s.ctx.Done():
			return
		}
		if s.authorized(device) {
			if err := reply(); err != nil && s.ctx.Err() == nil {
				s.log.Warn("terminal read reply", "err", err)
			}
		}
	}()
	return nil
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

// Resolve the service account through NSS; systemd's environment need not contain SHELL.
func terminalAccount() (shell, home string, err error) {
	uid := strconv.Itoa(os.Geteuid())
	record, err := exec.Command("getent", "passwd", uid).Output()
	if err != nil {
		record, err = os.ReadFile("/etc/passwd")
		if err != nil {
			return "", "", err
		}
	}
	for _, line := range strings.Split(string(record), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[2] != uid {
			continue
		}
		shell, home = fields[6], fields[5]
		if shell == "" {
			shell = "/bin/sh"
		}
		if !filepath.IsAbs(shell) {
			return "", "", fmt.Errorf("account shell must be absolute: %q", shell)
		}
		if _, err := exec.LookPath(shell); err != nil {
			return "", "", err
		}
		return shell, home, nil
	}
	return "", "", fmt.Errorf("no passwd entry for service uid %s", uid)
}

func startTerminal(w Workspace, rel, device string, cols, rows int) (*terminal, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fault("unsupported", "terminal requires bubblewrap on the server")
	}
	// Only this workspace is writable on the host. Use a private /tmp and no
	// agent sockets, service credentials in the environment, or host /proc.
	shell, accountHome, err := terminalAccount()
	if err != nil {
		return nil, err
	}
	args := []string{"--unshare-all", "--share-net", "--die-with-parent", "--ro-bind", "/usr", "/usr", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"}
	for _, path := range []string{"/bin", "/lib", "/lib64", "/sbin", "/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/alternatives", "/etc/os-release", "/etc/terminfo", "/etc/zsh", "/etc/bash.bashrc", "/etc/inputrc", "/etc/fish"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	// A custom account shell can live outside the mounted system runtime.
	if !(strings.HasPrefix(shell, "/usr/") || strings.HasPrefix(shell, "/bin/") || strings.HasPrefix(shell, "/sbin/")) {
		args = append(args, "--ro-bind", shell, shell)
	}
	home := "/tmp/terminal-home"
	// Only load personal startup files when the account home is the configured workspace.
	// A project's own .zshrc or .bashrc must not become the account's startup file.
	if realHome, err := filepath.EvalSymlinks(accountHome); err == nil && realHome == w.Path {
		home = "/workspace"
		// Preserve absolute paths in personal startup files without exposing another host directory.
		if filepath.Dir(accountHome) == "/home" || accountHome == "/root" {
			args = append(args, "--symlink", "/workspace", accountHome)
			home = accountHome
		}
	} else {
		args = append(args, "--dir", home)
	}
	args = append(args, "--bind", w.Path, "/workspace", "--chdir", filepath.Join("/workspace", rel), "--", shell)
	if home == "/tmp/terminal-home" && filepath.Base(shell) == "zsh" {
		// A fresh private HOME otherwise triggers zsh-newuser-install and consumes the first key.
		args = append(args, "-f")
	}
	cmd := exec.Command(bwrap, args...)
	cmd.Env = []string{"PATH=" + home + "/.local/bin:/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8", "TERM=xterm-256color", "SHELL=" + shell}
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
