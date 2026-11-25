package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	acp "github.com/coder/acp-go-sdk"
)

func adapterError(err error) error {
	var rpc *acp.RequestError
	if errors.As(err, &rpc) {
		switch rpc.Code {
		case -32601:
			return fault("unsupported", "agent does not support this operation")
		case -32602:
			return fault("invalid_argument", "agent rejected this option or value")
		}
	}
	return err
}

func (s *Service) deleteThread(ctx context.Context, t thread) (mutation, error) {
	a, err := s.adapter(t.Agent)
	if err != nil {
		return mutation{}, err
	}
	run, err := a.get(ctx)
	if err != nil {
		return mutation{}, err
	}
	if !run.process.CanDelete() {
		return mutation{}, fault("unsupported", "agent does not advertise permanent session deletion")
	}
	id := acp.SessionId(t.Session)
	if err := run.process.Delete(ctx, id); err != nil {
		return mutation{}, adapterError(err)
	}
	result := map[string]any{"thread_id": t.ID, "workspace_id": t.Workspace, "deleted": true}
	scope := "threads/" + t.Workspace
	return mutation{result: result, scopes: []string{scope}, apply: func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT OR IGNORE INTO deleted_threads VALUES(?)", t.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM permissions WHERE thread=?", t.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM events WHERE scope=? OR (scope=? AND kind='thread.upsert' AND json_extract(body,'$.thread_id')=?)", "thread/"+t.ID, scope, t.ID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM threads WHERE id=?", t.ID); err != nil {
			return err
		}
		if err := s.redactThreadCommands(tx, t.ID); err != nil {
			return err
		}
		return appendEvent(tx, scope, "thread.deleted", result)
	}, committed: func() { run.mu.Lock(); delete(run.attached, id); run.mu.Unlock() }}, nil
}

// Completed command envelopes can contain prompts, permission answers and thread titles.
// Retain the identifier and hash so a retry cannot recreate the deleted conversation.
func (s *Service) redactThreadCommands(tx *sql.Tx, id string) error {
	rows, err := tx.Query(`SELECT device,id,body FROM commands WHERE state='done' AND
	  (CASE WHEN json_valid(CAST(body AS TEXT)) THEN json_extract(CAST(body AS TEXT),'$.thread_id') END=?
	   OR json_extract(CAST(reply AS TEXT),'$.result.thread_id')=?)`, id, id)
	if err != nil {
		return err
	}
	type entry struct {
		device, id string
		digest     [32]byte
	}
	var entries []entry
	for rows.Next() {
		var e entry
		var b []byte
		if err := rows.Scan(&e.device, &e.id, &b); err != nil {
			rows.Close()
			return err
		}
		e.digest = sha256.Sum256(b)
		entries = append(entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		reply := s.encode(e.id, nil, fault("not_found", "thread was permanently deleted"))
		if _, err := tx.Exec("UPDATE commands SET body=?,reply=? WHERE device=? AND id=?", e.digest[:], reply, e.device, e.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) changeSettings(ctx context.Context, t thread, c command) (mutation, error) {
	var req acp.SetSessionConfigOptionRequest
	id := acp.SessionId(t.Session)
	if c.Op == "thread.set_config" {
		if strings.TrimSpace(c.ConfigID) == "" || len(c.ConfigID) > 512 {
			return mutation{}, fault("invalid_argument", "config_id must be 1 to 512 bytes")
		}
		var v any
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return mutation{}, fault("invalid_argument", "a setting value is required")
		}
		switch val := v.(type) {
		case string:
			if val == "" || len(val) > 2048 {
				return mutation{}, fault("invalid_argument", "invalid option value")
			}
			req.ValueId = &acp.SetSessionConfigOptionValueId{ConfigId: acp.SessionConfigId(c.ConfigID), SessionId: id, Value: acp.SessionConfigValueId(val)}
		case bool:
			req.Boolean = &acp.SetSessionConfigOptionBoolean{ConfigId: acp.SessionConfigId(c.ConfigID), SessionId: id, Type: "boolean", Value: val}
		default:
			return mutation{}, fault("invalid_argument", "value must be an option ID or boolean")
		}
	} else if strings.TrimSpace(c.ModeID) == "" || len(c.ModeID) > 512 {
		return mutation{}, fault("invalid_argument", "mode_id must be 1 to 512 bytes")
	}
	run, history, err := s.attach(ctx, t)
	if err != nil {
		return mutation{}, err
	}
	if history != nil && history.err != nil {
		return mutation{}, history.err
	}
	var out any
	var kind string
	if c.Op == "thread.set_config" {
		out, err = run.process.SetConfig(ctx, req)
		kind = "session.config"
	} else {
		err = run.process.SetMode(ctx, id, acp.SessionModeId(c.ModeID))
		out = map[string]string{"currentModeId": c.ModeID}
		kind = "session.mode"
	}
	if err != nil {
		return mutation{}, adapterError(err)
	}
	scope := "thread/" + t.ID
	m := mutation{result: out, scopes: []string{scope}, apply: func(tx *sql.Tx) error {
		if err := saveReplay(tx, t, history); err != nil {
			return err
		}
		if history != nil && history.isReplay && !t.Imported {
			t.Imported = true
			if err := putThread(tx, t); err != nil {
				return err
			}
		}
		return appendEvent(tx, scope, kind, out)
	}, committed: func() { run.markAttached(id) }}
	if history != nil && history.isReplay && !t.Imported {
		m.scopes = append(m.scopes, "threads/"+t.Workspace)
	}
	return m, nil
}
