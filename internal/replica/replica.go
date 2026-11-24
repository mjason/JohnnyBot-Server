// Package replica is the Go reference for a device's persistent cache and outbox.
// An application uses one database per host and device identity.
package replica

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"

	"johnny_bot/internal/syncwire"
)

type Cache struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS scope (
	key TEXT PRIMARY KEY, epoch TEXT NOT NULL DEFAULT '',
	cursor INTEGER NOT NULL DEFAULT 0, through INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS event (
	scope TEXT NOT NULL REFERENCES scope(key) ON DELETE CASCADE,
	seq INTEGER NOT NULL, kind TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(scope,seq)
);
CREATE TABLE IF NOT EXISTS outbox (
	id TEXT PRIMARY KEY, epoch TEXT NOT NULL, payload BLOB NOT NULL, reply BLOB
);
`

type Position struct {
	Epoch   string
	After   int64
	Through int64
}

type Pending struct {
	ID      string
	Payload json.RawMessage
}

func Open(path string) (*Cache, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000"}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Cache{db}, nil
}

func (c *Cache) Close() error { return c.db.Close() }

func (c *Cache) Select(ctx context.Context, key string) error {
	_, err := c.db.ExecContext(ctx, "INSERT OR IGNORE INTO scope(key) VALUES(?)", key)
	return err
}

func (c *Cache) Remove(ctx context.Context, key string) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM scope WHERE key=?", key)
	return err
}

func (c *Cache) Position(ctx context.Context, key string) (Position, error) {
	var p Position
	err := c.db.QueryRowContext(ctx, "SELECT epoch,cursor,through FROM scope WHERE key=?", key).Scan(&p.Epoch, &p.After, &p.Through)
	return p, err
}

// Apply atomically checkpoints events and the cursor. expected is the position used
// to issue this request, allowing a delayed reply to be discarded safely.
func (c *Cache) Apply(ctx context.Context, expected Position, p syncwire.Page) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored Position
	if err := tx.QueryRow("SELECT epoch,cursor,through FROM scope WHERE key=?", p.Scope).Scan(&stored.Epoch, &stored.After, &stored.Through); err != nil {
		return err
	}
	if stored != expected || p.After != expected.After {
		return errors.New("stale sync response")
	}
	if p.Epoch == "" {
		return errors.New("missing server epoch")
	}
	if p.Reset {
		if _, err := tx.Exec("DELETE FROM event WHERE scope=?", p.Scope); err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE scope SET epoch=?,cursor=0,through=0 WHERE key=?", p.Epoch, p.Scope)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if expected.Epoch != "" && expected.Epoch != p.Epoch || p.Through < expected.After || expected.Through != 0 && expected.Through != p.Through {
		return errors.New("inconsistent sync window")
	}
	cursor := expected.After
	for _, e := range p.Events {
		if e.Seq <= cursor || e.Seq > p.Through || !json.Valid(e.Data) {
			return errors.New("invalid event in sync page")
		}
		if _, err := tx.Exec("INSERT INTO event VALUES(?,?,?,?)", p.Scope, e.Seq, e.Kind, []byte(e.Data)); err != nil {
			return err
		}
		cursor = e.Seq
	}
	var through int64
	if p.More {
		if cursor == expected.After || cursor >= p.Through {
			return errors.New("invalid nonfinal sync page")
		}
		through = p.Through
	} else if cursor != p.Through {
		return errors.New("invalid final sync page")
	}
	if _, err := tx.Exec("UPDATE scope SET epoch=?,cursor=?,through=? WHERE key=?", p.Epoch, cursor, through, p.Scope); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *Cache) Events(ctx context.Context, key string, after int64, limit int) ([]syncwire.Event, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid limit")
	}
	rows, err := c.db.QueryContext(ctx, "SELECT seq,kind,data FROM event WHERE scope=? AND seq>? ORDER BY seq LIMIT ?", key, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []syncwire.Event{}
	for rows.Next() {
		var e syncwire.Event
		if err := rows.Scan(&e.Seq, &e.Kind, &e.Data); err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, rows.Err()
}

// Queue persists the exact bytes sent on every retry. Generate unique cmd_id
// values at the time of the user's action.
func (c *Cache) Queue(ctx context.Context, payload []byte) error {
	var header struct {
		ID    string `json:"cmd_id"`
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal(payload, &header); err != nil || header.ID == "" || header.Epoch == "" {
		return errors.New("queued command requires cmd_id and epoch")
	}
	_, err := c.db.ExecContext(ctx, "INSERT INTO outbox(id,epoch,payload) VALUES(?,?,?)", header.ID, header.Epoch, payload)
	return err
}

// PendingFor returns commands safe to resend and the count held back after an epoch change.
func (c *Cache) PendingFor(ctx context.Context, epoch string) (pending []Pending, held int, err error) {
	rows, err := c.db.QueryContext(ctx, "SELECT id,payload,epoch FROM outbox WHERE reply IS NULL ORDER BY rowid")
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var item Pending
		var commandEpoch string
		if err := rows.Scan(&item.ID, &item.Payload, &commandEpoch); err != nil {
			return nil, 0, err
		}
		if commandEpoch != epoch {
			held++
			continue
		}
		pending = append(pending, item)
	}
	return pending, held, rows.Err()
}

func (c *Cache) Complete(ctx context.Context, payload []byte) error {
	var header struct {
		ID    string `json:"cmd_id"`
		OK    *bool  `json:"ok"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &header); err != nil || header.ID == "" || header.OK == nil {
		return errors.New("invalid command reply")
	}
	if header.Error != nil && header.Error.Code == "epoch_mismatch" {
		return nil
	}
	result, err := c.db.ExecContext(ctx, "UPDATE outbox SET reply=coalesce(reply,?) WHERE id=?", payload, header.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return fmt.Errorf("unknown command %q", header.ID)
	}
	return err
}
