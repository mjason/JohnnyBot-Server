package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"johnny_bot/internal/agent"
)

// startTimeout leaves room for the npx download.
const startTimeout = 3 * time.Minute

func sessions(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	pick := agentFlags(fs)
	fs.Parse(args)
	spec, log, err := pick()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	a, err := agent.Start(ctx, spec, &terminal{}, log)
	if err != nil {
		return err
	}
	defer a.Close()
	list, err := a.List(ctx)
	if err != nil {
		return err
	}
	for _, s := range list {
		fmt.Printf("%s\t%s\t%s\t%s\n", s.SessionId, deref(s.UpdatedAt), s.Cwd, strings.Join(strings.Fields(deref(s.Title)), " "))
	}
	return nil
}

func chat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ExitOnError)
	pick := agentFlags(fs)
	cwd := fs.String("cwd", ".", "working directory of the session")
	session := fs.String("session", "", "open this session instead of a new one")
	fs.Parse(args)
	spec, log, err := pick()
	if err != nil {
		return err
	}
	dir, err := absDir(*cwd)
	if err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	t := &terminal{lines: readLines()}
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	go func() { // Ctrl-C while starting
		select {
		case <-sig:
			cancel()
		case <-ctx.Done():
		}
	}()
	a, err := agent.Start(ctx, spec, t, log)
	if err != nil {
		return err
	}
	defer a.Close()
	id := acp.SessionId(*session)
	if id == "" {
		resp, err := a.NewSession(ctx, dir)
		if err != nil {
			return err
		}
		id = resp.SessionId
	} else {
		t.mute.Store(true) // replayed history
		_, err := a.Open(ctx, id, dir)
		t.mute.Store(false)
		if err != nil {
			return err
		}
	}
	cancel()
	name := spec.Name
	if i := a.Info.AgentInfo; i != nil {
		name = i.Name + " " + i.Version
	}
	fmt.Printf("%s, session %s\nCtrl-C cancels a turn, Ctrl-D quits.\n", name, id)

	for {
		fmt.Print("\n> ")
		var line string
		select {
		case l, ok := <-t.lines:
			if !ok {
				return nil
			}
			line = strings.TrimSpace(l)
		case <-sig:
			return nil
		case <-a.Done():
			return errors.New("agent went away")
		}
		if line == "" {
			continue
		}
		type result struct {
			resp acp.PromptResponse
			err  error
		}
		done := make(chan result, 1)
		go func() {
			resp, err := a.Prompt(context.Background(), id, acp.TextBlock(line))
			done <- result{resp, err}
		}()
		for running := true; running; {
			select {
			case <-sig:
				fmt.Println("\n[cancelling]")
				if err := a.Cancel(context.Background(), id); err != nil {
					return err
				}
			case r := <-done:
				running = false
				if r.err != nil {
					fmt.Println("\n[error]", r.err)
				} else {
					fmt.Printf("\n[%s]\n", r.resp.StopReason)
				}
			}
		}
	}
}

type terminal struct {
	lines <-chan string
	mute  atomic.Bool
}

func (t *terminal) Update(n acp.SessionNotification) {
	if t.mute.Load() {
		return
	}
	switch u := n.Update; {
	case u.AgentMessageChunk != nil:
		if c := u.AgentMessageChunk.Content.Text; c != nil {
			fmt.Print(c.Text)
		}
	case u.AgentThoughtChunk != nil:
		if c := u.AgentThoughtChunk.Content.Text; c != nil {
			fmt.Print("\x1b[2m", c.Text, "\x1b[0m")
		}
	case u.ToolCall != nil:
		fmt.Printf("\n[tool] %s (%s)\n", u.ToolCall.Title, u.ToolCall.Status)
	case u.ToolCallUpdate != nil:
		if s, ok := u.ToolCallUpdate.Status.Value(); ok {
			fmt.Printf("\n[tool] %s: %s\n", u.ToolCallUpdate.ToolCallId, s)
		}
	case u.Plan != nil:
		for _, e := range u.Plan.Entries {
			fmt.Printf("\n[plan] %s: %s", e.Status, e.Content)
		}
		fmt.Println()
	}
}

func (t *terminal) Permission(ctx context.Context, req acp.RequestPermissionRequest) (acp.PermissionOptionId, error) {
	title, _ := req.ToolCall.Title.Value()
	fmt.Printf("\n[permission] %s\n", title)
	if raw, ok := req.ToolCall.RawInput.Value(); ok {
		fmt.Printf("  %s\n", raw)
	}
	for i, o := range req.Options {
		fmt.Printf("  %d. %s (%s)\n", i+1, o.Name, o.Kind)
	}
	for {
		fmt.Print("? ")
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case l, ok := <-t.lines:
			if !ok {
				return "", errors.New("stdin closed")
			}
			if n, err := strconv.Atoi(strings.TrimSpace(l)); err == nil && n >= 1 && n <= len(req.Options) {
				return req.Options[n-1].OptionId, nil
			}
		}
	}
}

func readLines() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			ch <- sc.Text()
		}
	}()
	return ch
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
