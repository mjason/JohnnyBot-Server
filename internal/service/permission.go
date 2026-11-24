package service

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	acp "github.com/coder/acp-go-sdk"
)

type approval struct {
	thread  string
	turn    string
	options []acp.PermissionOption
	answer  chan acp.PermissionOptionId
}

func (s *Service) requestPermission(ctx context.Context, st *stream, req acp.RequestPermissionRequest) (acp.PermissionOptionId, error) {
	id := newID()
	a := &approval{thread: st.thread.ID, turn: st.turn, options: req.Options, answer: make(chan acp.PermissionOptionId, 1)}
	scope := "thread/" + a.thread
	s.mu.Lock()
	err := s.store.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO permissions(id,thread,turn,state) VALUES(?,?,?,'pending')", id, a.thread, a.turn); err != nil {
			return err
		}
		return appendEvent(tx, scope, "permission.requested", map[string]any{"permission_id": id, "turn_id": a.turn, "request": req})
	})
	if err == nil {
		s.permissions[id] = a
	}
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	s.notify(scope)
	defer func() {
		s.mu.Lock()
		delete(s.permissions, id)
		s.mu.Unlock()
	}()
	select {
	case option := <-a.answer:
		return option, nil
	case <-ctx.Done():
	case <-s.ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case option := <-a.answer:
		return option, nil
	default:
	}
	delete(s.permissions, id)
	err = s.store.write(context.Background(), func(tx *sql.Tx) error { return resolvePermission(tx, id, a.thread, "expired", nil) })
	if err == nil {
		s.notify(scope)
	} else {
		s.log.Error("expire permission", "err", err)
	}
	return "", errors.New("permission request expired")
}

func (s *Service) answerPermission(j job, c command) (mutation, error) {
	s.mu.Lock()
	a := s.permissions[c.Permission]
	if a == nil || a.thread != c.Thread || a.turn != c.Turn {
		s.mu.Unlock()
		return mutation{}, fault("permission_closed", "approval is no longer pending")
	}
	index := slices.IndexFunc(a.options, func(o acp.PermissionOption) bool { return string(o.OptionId) == c.Option })
	if index < 0 {
		s.mu.Unlock()
		return mutation{}, fault("invalid_argument", "option was not offered")
	}
	result := map[string]any{"device_id": j.device, "option_id": c.Option}
	return mutation{
		result: result, scopes: []string{"thread/" + a.thread}, release: s.mu.Unlock,
		committed: func() { delete(s.permissions, c.Permission); a.answer <- a.options[index].OptionId },
		apply:     func(tx *sql.Tx) error { return resolvePermission(tx, c.Permission, a.thread, "answered", result) },
	}, nil
}

func resolvePermission(tx *sql.Tx, id, threadID, state string, result map[string]any) error {
	r, err := tx.Exec("UPDATE permissions SET state=? WHERE id=? AND state='pending'", state, id)
	if err != nil {
		return err
	}
	count, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	return appendEvent(tx, "thread/"+threadID, "permission.resolved", map[string]any{"permission_id": id, "status": state, "answer": result})
}

func expireTurn(tx *sql.Tx, threadID, turnID string) error {
	rows, err := tx.Query("SELECT id FROM permissions WHERE thread=? AND turn=? AND state='pending'", threadID, turnID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := resolvePermission(tx, id, threadID, "expired", nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recover() error {
	return s.store.write(s.ctx, func(tx *sql.Tx) error {
		rows, err := tx.Query("SELECT " + threadFields + " FROM threads WHERE active<>''")
		if err != nil {
			return err
		}
		var active []thread
		for rows.Next() {
			t, err := scanThread(rows)
			if err != nil {
				rows.Close()
				return err
			}
			active = append(active, t)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, t := range active {
			id := t.Active
			if err := expireTurn(tx, t.ID, id); err != nil {
				return err
			}
			t.Active, t.Updated = "", now()
			if err := putThread(tx, t); err != nil {
				return err
			}
			if err := appendEvent(tx, "thread/"+t.ID, "turn.finished", map[string]string{"turn_id": id, "status": "interrupted"}); err != nil {
				return err
			}
		}
		rows, err = tx.Query("SELECT device,id FROM commands WHERE state='running'")
		if err != nil {
			return err
		}
		var interrupted []job
		for rows.Next() {
			var j job
			if err := rows.Scan(&j.device, &j.id); err != nil {
				rows.Close()
				return err
			}
			interrupted = append(interrupted, j)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, j := range interrupted {
			payload := s.encode(j.id, nil, fault("interrupted", "the server restarted while this command was running"))
			if err := finish(tx, j, payload); err != nil {
				return err
			}
		}
		return nil
	})
}
