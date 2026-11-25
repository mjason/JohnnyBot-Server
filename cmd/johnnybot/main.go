// johnnybot runs ACP agents on this host for remote clients.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"johnny_bot/internal/agent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	// The first signal ends ctx; after that a second one kills the program.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	var err error
	switch os.Args[1] {
	case "chat":
		err = chat(os.Args[2:])
	case "sessions":
		err = sessions(ctx, os.Args[2:])
	case "serve":
		err = serve(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "johnnybot:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  johnnybot chat     [-agent codex|antigravity] [-cwd dir] [-session id]
  johnnybot sessions [-agent codex|antigravity]
  johnnybot serve    [-addr :8883] [-host name] [-data dir] [-workspace ID=/path]`)
	os.Exit(2)
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == "packet" { // mochi logs whole packets: payloads and passwords
				return slog.Attr{}
			}
			return a
		}}))
}

// agentFlags adds the flags that choose an agent.
func agentFlags(fs *flag.FlagSet) func() (agent.Spec, *slog.Logger, error) {
	name := fs.String("agent", "codex", "codex or antigravity")
	verbose := fs.Bool("v", false, "log the agent's stderr")
	return func() (agent.Spec, *slog.Logger, error) {
		spec, ok := agent.Presets[*name]
		if !ok {
			return spec, nil, fmt.Errorf("unknown agent %q", *name)
		}
		return spec, newLogger(*verbose), nil
	}
}

func absDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err == nil && !st.IsDir() {
		err = errors.New(abs + " is not a directory")
	}
	return abs, err
}
