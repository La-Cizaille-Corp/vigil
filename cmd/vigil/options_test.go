package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// stderr runs fn and returns what it wrote on the standard error, where flag
// writes the help of a command.
func stderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	saved := os.Stderr
	os.Stderr = f
	fn()
	os.Stderr = saved
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The shared options, with their one help text each.
var (
	dbOption       = "fichier SQLite"
	serviceOptions = map[string]string{
		"base-url":           "adresse publique de l'interface, pour les liens des alertes, des digests et des webhooks",
		"allow-private-urls": "autoriser flux et webhooks vers des adresses privées ou locales",
		"nvd-api-key":        "clé d'API NVD facultative, qui relève la limite de requêtes (préférez la variable VIGIL_NVD_API_KEY)",
		"smtp-addr":          "serveur SMTP hôte:port pour les notifications par e-mail (vide = désactivé)",
	}
)

// X7: every command answers -h with its help, without opening the database;
// -db is in each one, once, with the same text, and the options of the
// services in serve, sync and digest only.
func TestCommandHelp(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vigil.db")
	t.Setenv("VIGIL_DB", db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, c := range []struct {
		args     []string
		services bool
		own      []string // options of the command itself
	}{
		{[]string{"serve"}, true, []string{"addr", "tls-cert", "behind-proxy", "sync-interval", "backup-dir", "audit-retention-days"}},
		{[]string{"sync"}, true, nil},
		{[]string{"digest"}, true, []string{"no-webhooks"}},
		{[]string{"import-sbom"}, false, []string{"project"}},
		{[]string{"backup"}, false, []string{"o"}},
		{[]string{"check"}, false, nil},
		{[]string{"user", "add"}, false, []string{"username", "role", "groups"}},
		{[]string{"user", "list"}, false, []string{"username", "role"}},
		{[]string{"user", "set-role"}, false, []string{"username", "role"}},
		{[]string{"user", "set-access"}, false, []string{"username", "all", "groups"}},
		{[]string{"user", "disable"}, false, []string{"username"}},
		{[]string{"user", "enable"}, false, []string{"username"}},
		{[]string{"user", "reset-password"}, false, []string{"username"}},
		{[]string{"user", "reset-totp"}, false, []string{"username", "all"}},
	} {
		name := strings.Join(c.args, " ")
		var err error
		help := stderr(t, func() { err = run(context.Background(), log, append(c.args, "-h")) })
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%s -h: %v", name, err)
		}
		option := func(name string) int {
			return strings.Count(help, "\n  -"+name+" ") + strings.Count(help, "\n  -"+name+"\n")
		}
		if option("db") != 1 || strings.Count(help, dbOption) != 1 {
			t.Errorf("%s: -db not once, with %q:\n%s", name, dbOption, help)
		}
		for opt, text := range serviceOptions {
			if n := option(opt); c.services && (n != 1 || !strings.Contains(help, text)) || !c.services && n != 0 {
				t.Errorf("%s: -%s seen %d times (services %v):\n%s", name, opt, n, c.services, help)
			}
		}
		for _, opt := range c.own {
			if option(opt) != 1 {
				t.Errorf("%s: no -%s:\n%s", name, opt, help)
			}
		}
	}
	if _, err := os.Stat(db); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("database opened by a help: %v", err)
	}
}

// A command line that cannot run ends with status 2, after its explanation.
func TestCommandLineErrors(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("VIGIL_DB", filepath.Join(t.TempDir(), "vigil.db"))
	for _, args := range [][]string{nil, {"frobnicate"}, {"sync", "-no-such-option"}} {
		var err error
		out := stderr(t, func() { err = run(context.Background(), log, args) })
		var bad *usageError
		if !errors.As(err, &bad) || out == "" {
			t.Errorf("%q: %v, said %q", args, err, out)
		}
	}
	// A value from the environment that does not fit its option is named.
	t.Setenv("VIGIL_SYNC_INTERVAL", "souvent")
	err := run(context.Background(), log, []string{"serve"})
	var bad *usageError
	if !errors.As(err, &bad) || !strings.HasPrefix(err.Error(), `VIGIL_SYNC_INTERVAL="souvent" : `) {
		t.Errorf("invalid VIGIL_SYNC_INTERVAL: %v", err)
	}
}

// Every option comes from VIGIL_ + its name when the command line does not
// give it: VIGIL_DB and the NVD key included, read by that one mechanism.
func TestOptionsFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VIGIL_DB", filepath.Join(dir, "env.db"))
	t.Setenv("VIGIL_NVD_API_KEY", "key-from-env")
	t.Setenv("VIGIL_BASE_URL", "https://vigil.example")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, o := newCommand("sync", true)
	if err := o.parse(nil); err != nil {
		t.Fatal(err)
	}
	sv := o.services(nil, log)
	if *o.db != filepath.Join(dir, "env.db") || sv.syncer.NVD.APIKey != "key-from-env" || sv.notifier.BaseURL != "https://vigil.example" {
		t.Errorf("from the environment: db %q, NVD key %q, base URL %q", *o.db, sv.syncer.NVD.APIKey, sv.notifier.BaseURL)
	}

	// The command line wins.
	_, o = newCommand("sync", true)
	if err := o.parse([]string{"-db", filepath.Join(dir, "cli.db"), "-nvd-api-key", "key-from-cli"}); err != nil {
		t.Fatal(err)
	}
	if sv := o.services(nil, log); *o.db != filepath.Join(dir, "cli.db") || sv.syncer.NVD.APIKey != "key-from-cli" {
		t.Errorf("from the command line: db %q, NVD key %q", *o.db, sv.syncer.NVD.APIKey)
	}

	// Without VIGIL_DB, the database is in the user's configuration folder.
	t.Setenv("VIGIL_DB", "")
	os.Unsetenv("VIGIL_DB")
	_, o = newCommand("check", false)
	if err := o.parse(nil); err != nil || *o.db != defaultDB() || filepath.Base(*o.db) != "vigil.db" {
		t.Errorf("default database: %q, %v", *o.db, err)
	}

	// A command run with VIGIL_DB only works on that database.
	t.Setenv("VIGIL_DB", filepath.Join(dir, "env.db"))
	if err := run(context.Background(), log, []string{"user", "list"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "env.db")); err != nil {
		t.Errorf("VIGIL_DB not used: %v", err)
	}
}

// The mail settings are checked before the database is opened, from the
// command line as from the environment.
func TestMailSettingsCheckedFirst(t *testing.T) {
	db := filepath.Join(t.TempDir(), "vigil.db")
	t.Setenv("VIGIL_SMTP_ADDR", "smtp.example")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, cmd := range []string{"sync", "digest"} {
		if err := run(context.Background(), log, []string{cmd, "-db", db}); err == nil || !strings.Contains(err.Error(), "hôte:port") {
			t.Errorf("%s with VIGIL_SMTP_ADDR without a port: %v", cmd, err)
		}
	}
	if _, err := os.Stat(db); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("database opened despite the mail settings: %v", err)
	}
}

// C8 of the 0.5.0 review: the environment sets the shared options and those
// of serve only. VIGIL_ALL=true used to make `vigil user reset-totp`, without
// an option, remove the second factor of every account; VIGIL_ROLE and
// VIGIL_GROUPS changed what `vigil user add` created.
func TestCommandOptionsNotFromEnvironment(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("VIGIL_DB", filepath.Join(dir, "vigil.db"))
	t.Setenv("VIGIL_ALL", "true")
	t.Setenv("VIGIL_ROLE", "admin")
	t.Setenv("VIGIL_GROUPS", "inconnu")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, log, []string{"user", "reset-totp"}); err == nil || !strings.Contains(err.Error(), "-username nom ou -all") {
		t.Errorf("reset-totp without an option, VIGIL_ALL=true: %v", err)
	}
	in := filepath.Join(dir, "password")
	if err := os.WriteFile(in, []byte("a-strong-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdin := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = stdin }()
	if err := run(ctx, log, []string{"user", "add", "-username", "carol"}); err != nil {
		t.Fatalf("user add with VIGIL_ROLE and VIGIL_GROUPS set: %v", err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if u, err := st.AnyUserByName(ctx, "carol"); err != nil || u.Role != "analyst" || !u.Access.All {
		t.Errorf("carol: %+v, %v; want an analyst who sees everything", u, err)
	}
}

// C8 of the 0.5.0 review: -tls-cert without -tls-key, or the other way, is
// refused; the UI used to be served in clear text without a word.
func TestTLSOptionsGoTogether(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the server, if it started, would stop at once
	t.Setenv("VIGIL_DB", filepath.Join(t.TempDir(), "vigil.db"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, half := range [][]string{{"-tls-cert", "cert.pem"}, {"-tls-key", "key.pem"}} {
		err := run(ctx, log, append([]string{"serve", "-addr", "127.0.0.1:0", "-sync-interval", "0"}, half...))
		var bad *usageError
		if !errors.As(err, &bad) || !strings.Contains(err.Error(), "-tls-cert et -tls-key") {
			t.Errorf("serve %v: %v", half, err)
		}
	}
}
