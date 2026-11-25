package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"johnny_bot/internal/broker"
	"johnny_bot/internal/keyauth"
	"johnny_bot/internal/service"
)

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8883", "address to listen on")
	hostname, _ := os.Hostname()
	host := fs.String("host", hostname, "name of this host in the topics")
	conf, _ := os.UserConfigDir()
	data := fs.String("data", filepath.Join(conf, "johnnybot"), "directory of the database, host.pem, and authorized_keys")
	config := fs.String("config", os.Getenv("JOHNNYBOT_CONFIG"), "JSON device configuration path")
	var workspaces []service.Workspace
	fs.Func("workspace", "workspace ID and server directory (ID=/path, repeatable)", func(value string) error {
		id, path, ok := strings.Cut(value, "=")
		if !ok || id == "" || path == "" {
			return fmt.Errorf("expected ID=/path")
		}
		workspaces = append(workspaces, service.Workspace{ID: id, Path: path})
		return nil
	})
	fs.Parse(args)
	if len(workspaces) == 0 {
		workspaces = []service.Workspace{{ID: "default", Path: "."}}
	}

	log := newLogger(true)
	dataPath, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return err
	}
	cert, err := broker.LoadOrCreateCert(filepath.Join(dataPath, "host.pem"))
	if err != nil {
		return err
	}
	fp := broker.HostFingerprint(cert)
	keysPath := filepath.Join(dataPath, "authorized_keys")
	openKeys := keyauth.Open
	if *config != "" {
		keysPath = *config
		openKeys = keyauth.OpenConfig
	}
	keys, err := openKeys(keysPath, fp, log)
	if err != nil {
		return err
	}
	s, err := service.Open(ctx, filepath.Join(dataPath, "johnnybot.db"), workspaces, keys.Has, log)
	if err != nil {
		return err
	}
	defer s.Close()
	b, err := broker.New(*host, *addr, cert, keys, s.Handle, log)
	if err != nil {
		return err
	}
	s.Run(b)
	fmt.Printf("listening on   %s\nhost           %s\nfingerprint    %s\nauthorized_keys %s\n", b.Addr(), *host, fp, keysPath)
	if err := b.Run(s.Context()); err != nil {
		return err
	}
	if ctx.Err() == nil {
		return context.Cause(s.Context())
	}
	return nil
}
