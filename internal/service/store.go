package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"johnny_bot/internal/syncwire"
)

const (
	pageBytes  = 160 << 10
	eventBytes = 32 << 10
)

type store struct {
	db    *sql.DB
	epoch string
	lock  *os.File
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commands (
	device TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, state TEXT NOT NULL,
	reply BLOB, PRIMARY KEY(device,id)
);
CREATE INDEX IF NOT EXISTS command_queue ON commands(state);
CREATE TABLE IF NOT EXISTS events (
	seq INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS event_scope ON events(scope,seq);
CREATE TABLE IF NOT EXISTS threads (
	id TEXT PRIMARY KEY, workspace TEXT NOT NULL, agent TEXT NOT NULL, session TEXT NOT NULL,
	path TEXT NOT NULL, title TEXT NOT NULL, updated TEXT NOT NULL, archived INTEGER NOT NULL,
	imported INTEGER NOT NULL, active TEXT NOT NULL DEFAULT '', UNIQUE(agent,session)
);
CREATE TABLE IF NOT EXISTS permissions (
	id TEXT PRIMARY KEY, thread TEXT NOT NULL REFERENCES threads(id), turn TEXT NOT NULL,
	state TEXT NOT NULL
);
`

func openStore(ctx context.Context, path string) (*store, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock database: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.Clean(path), RawQuery: "_journal_mode=WAL&_synchronous=FULL&_foreign_keys=on&_busy_timeout=5000"}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		file.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &store{db: db, lock: file}
	err = s.write(ctx, func(tx *sql.Tx) error {
		var version int
		if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version > 1 {
			return fmt.Errorf("database schema %d is newer than this server", version)
		}
		if version == 0 {
			if _, err := tx.Exec(schema); err != nil {
				return err
			}
			if _, err := tx.Exec("PRAGMA user_version=1"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("INSERT OR IGNORE INTO meta VALUES('epoch',lower(hex(randomblob(16))))"); err != nil {
			return err
		}
		return tx.QueryRow("SELECT value FROM meta WHERE key='epoch'").Scan(&s.epoch)
	})
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *store) close() {
	s.db.Close()
	s.lock.Close()
}

func (s *store) write(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func appendEvent(tx *sql.Tx, scope, kind string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(raw) <= eventBytes {
		_, err = tx.Exec("INSERT INTO events(scope,kind,body) VALUES(?,?,?)", scope, kind, raw)
		return err
	}
	// Keep large event bodies lossless without exceeding the MQTT packet budget.
	id := newID()
	for offset := 0; offset < len(raw); offset += eventBytes {
		end := min(offset+eventBytes, len(raw))
		part, err := json.Marshal(map[string]any{"id": id, "kind": kind, "part": offset / eventBytes, "last": end == len(raw), "bytes": raw[offset:end:end]})
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO events(scope,kind,body) VALUES(?,?,?)", scope, "event.fragment", part); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) pull(ctx context.Context, scope, epoch string, after, through int64, limit int) (syncwire.Page, error) {
	p := syncwire.Page{Epoch: s.epoch, Scope: scope, After: after, Events: []syncwire.Event{}}
	err := s.write(ctx, func(tx *sql.Tx) error {
		var head int64
		if err := tx.QueryRow("SELECT coalesce(max(seq),0) FROM events WHERE scope=?", scope).Scan(&head); err != nil {
			return err
		}
		if (epoch != "" && epoch != s.epoch) || (epoch == "" && (after != 0 || through != 0)) || after > head || through > head || (through != 0 && through < after) {
			p.Reset = true
			return nil
		}
		if through == 0 {
			through = head
		}
		p.Through = through
		rows, err := tx.Query("SELECT seq,kind,body FROM events WHERE scope=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?", scope, after, through, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		size := 0
		for rows.Next() {
			var e syncwire.Event
			if err := rows.Scan(&e.Seq, &e.Kind, &e.Data); err != nil {
				return err
			}
			size += len(e.Data) + 128
			if len(p.Events) == limit || size > pageBytes {
				p.More = true
				break
			}
			p.Events = append(p.Events, e)
		}
		return rows.Err()
	})
	return p, err
}

type job struct {
	device, id string
	body       []byte
}

func (s *store) claim(ctx context.Context) (job, error) {
	var j job
	err := s.write(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRow("SELECT device,id,body FROM commands WHERE state='queued' ORDER BY rowid LIMIT 1").Scan(&j.device, &j.id, &j.body); err != nil {
			return err
		}
		_, err := tx.Exec("UPDATE commands SET state='running' WHERE device=? AND id=?", j.device, j.id)
		return err
	})
	return j, err
}

func finish(tx *sql.Tx, j job, payload []byte) error {
	_, err := tx.Exec("UPDATE commands SET state='done',reply=? WHERE device=? AND id=? AND state='running'", payload, j.device, j.id)
	return err
}

type thread struct {
	ID        string `json:"thread_id"`
	Workspace string `json:"workspace_id"`
	Agent     string `json:"agent"`
	Session   string `json:"session_id"`
	Path      string `json:"path"`
	Title     string `json:"title"`
	Updated   string `json:"updated_at"`
	Archived  bool   `json:"archived"`
	Imported  bool   `json:"history_imported"`
	Active    string `json:"active_turn_id,omitempty"`
}

const threadFields = "id,workspace,agent,session,path,title,updated,archived,imported,active"

func scanThread(row interface{ Scan(...any) error }) (thread, error) {
	var t thread
	err := row.Scan(&t.ID, &t.Workspace, &t.Agent, &t.Session, &t.Path, &t.Title, &t.Updated, &t.Archived, &t.Imported, &t.Active)
	return t, err
}

func (s *store) thread(ctx context.Context, id string) (thread, error) {
	t, err := scanThread(s.db.QueryRowContext(ctx, "SELECT "+threadFields+" FROM threads WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, fault("not_found", "thread does not exist")
	}
	return t, err
}

func putThread(tx *sql.Tx, t thread) error {
	_, err := tx.Exec(`INSERT INTO threads (`+threadFields+`) VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET title=excluded.title,updated=excluded.updated,
		archived=excluded.archived,imported=excluded.imported,active=excluded.active`,
		t.ID, t.Workspace, t.Agent, t.Session, t.Path, t.Title, t.Updated, t.Archived, t.Imported, t.Active)
	if err != nil {
		return err
	}
	return appendEvent(tx, "threads/"+t.Workspace, "thread.upsert", t)
}
