package store

// Tests of what the handlers of package web lean on: duplicates told apart
// from failures, lookups by id, the format of the audit log.

import (
	"context"
	"errors"
	"testing"
)

// The detail of an audit entry is key=value pairs; a value that could be
// read as another field or another line is quoted.
func TestAuditDetail(t *testing.T) {
	for _, c := range []struct {
		kv   []any
		want string
	}{
		{nil, ""},
		{[]any{"id", int64(12)}, "id=12"},
		{[]any{"id", 12, "role", "analyst", "enabled", true}, "id=12 role=analyst enabled=true"},
		{[]any{"name", "Équipe sécu"}, `name="Équipe sécu"`},
		{[]any{"alerts", ""}, `alerts=""`},
		{[]any{"user", "admin role=admin"}, `user="admin role=admin"`},
		{[]any{"text", `a"b`}, `text="a\"b"`},
		{[]any{"text", "a\nid=1"}, `text="a\nid=1"`},
		{[]any{"text", "a\u2028b"}, `text="a\u2028b"`},
		{[]any{"text", "\xff"}, `text="\xff"`},
		{[]any{"url", "https://example.org/…"}, "url=https://example.org/…"},
		{[]any{"countries", "FR,BE"}, "countries=FR,BE"},
		{[]any{"odd"}, `odd=""`},
	} {
		if got := AuditDetail(c.kv...); got != c.want {
			t.Errorf("AuditDetail(%q) = %s, want %s", c.kv, got, c.want)
		}
	}
}

// Only a violated UNIQUE or PRIMARY KEY constraint is a duplicate; another
// failed constraint, or any other error, stays what it is.
func TestMapUnique(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	exec := func(query string) error {
		_, err := st.db.ExecContext(ctx, query)
		return err
	}
	if err := exec(`INSERT INTO settings (key, value) VALUES ('k', 'v')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO cti_feeds (name, url) VALUES ('a', 'https://example.org/feed')`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, query string
		exists      bool
	}{
		{"primary key", `INSERT INTO settings (key, value) VALUES ('k', 'w')`, true},
		{"unique", `INSERT INTO cti_feeds (name, url) VALUES ('b', 'https://example.org/feed')`, true},
		{"not null", `INSERT INTO settings (key, value) VALUES ('n', NULL)`, false},
		{"no such table", `INSERT INTO nothing VALUES (1)`, false},
	} {
		err := exec(c.query)
		if err == nil {
			t.Fatalf("%s: no error", c.name)
		}
		if got := mapUnique(err); errors.Is(got, ErrExists) != c.exists || !c.exists && got != err {
			t.Errorf("%s: mapUnique(%v) = %v", c.name, err, got)
		}
	}
	if mapUnique(nil) != nil {
		t.Error("mapUnique(nil) is not nil")
	}
}

// A feed URL is unique: a second feed with the same URL is ErrExists.
func TestCreateFeedTwice(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	f := Feed{Name: "CERT-FR", URL: "https://example.org/feed", Enabled: true}
	if _, err := st.CreateFeed(ctx, f); err != nil {
		t.Fatal(err)
	}
	f.Name = "Another name"
	if _, err := st.CreateFeed(ctx, f); !errors.Is(err, ErrExists) {
		t.Errorf("same URL twice: %v, want ErrExists", err)
	}
}

// The check by name passes when another process inserts the same name
// between it and the insert (vigil user add while the UI creates it): the
// constraint of the column then says ErrExists, not an internal error.
func TestCreateUserRaceIsExists(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	// The trigger plays the other process: the same name lands just before
	// the insert (recursive triggers are off, so it fires once).
	if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER other_process BEFORE INSERT ON users WHEN NEW.username = 'bob'
		BEGIN INSERT INTO users (username, password_hash, role, created_at) VALUES ('bob', 'x', 'viewer', ''); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "bob", "hash", "viewer", Access{All: true}); !errors.Is(err, ErrExists) {
		t.Errorf("name inserted meanwhile: %v, want ErrExists", err)
	}
}

// A feed and a channel are read by their id; an unknown id is ErrNotFound.
func TestFeedAndWebhookByID(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	feedID, err := st.CreateFeed(ctx, Feed{Name: "CERT-FR", URL: "https://example.org/feed", Country: "FR", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := st.Feed(ctx, feedID); err != nil || f.ID != feedID || f.Name != "CERT-FR" || f.Country != "FR" || !f.Enabled {
		t.Errorf("Feed = %+v, %v", f, err)
	}
	hookID, err := st.CreateWebhook(ctx, Webhook{Name: "Équipe", Kind: "slack", URL: "https://hooks.example/x", Enabled: true, Alerts: "severe"})
	if err != nil {
		t.Fatal(err)
	}
	if h, err := st.Webhook(ctx, hookID); err != nil || h.ID != hookID || h.Name != "Équipe" || h.Alerts != "severe" || h.CreatedAt.IsZero() {
		t.Errorf("Webhook = %+v, %v", h, err)
	}
	if _, err := st.Feed(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown feed: %v", err)
	}
	if _, err := st.Webhook(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown channel: %v", err)
	}
}
