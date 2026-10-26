// Command vigil is a lightweight security watch tool: asset inventory,
// vulnerability tracking and digests, in a single binary.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
	"github.com/La-Cizaille-Corp/vigil/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `vigil — veille de sécurité légère

Usage :
  vigil serve   [-db fichier] [-addr 127.0.0.1:8080] [-tls-cert c -tls-key k] [-behind-proxy] [-sync-interval 6h]
  vigil sync    [-db fichier]
  vigil digest  [-db fichier]
  vigil user add -username nom [-role admin|analyst|viewer] [-db fichier]
  vigil version

La base par défaut se trouve dans le dossier de configuration de l'utilisateur
(variable VIGIL_DB pour la changer).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "serve":
		err = runServe(ctx, log, args)
	case "sync":
		err = runSync(ctx, log, args)
	case "digest":
		err = runDigest(ctx, args)
	case "user":
		err = runUser(ctx, args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur :", err)
		os.Exit(1)
	}
}

func defaultDB() string {
	if p := os.Getenv("VIGIL_DB"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "vigil.db"
	}
	return filepath.Join(dir, "vigil", "vigil.db")
}

func newSyncer(st *store.Store, log *slog.Logger) *tracking.Syncer {
	return &tracking.Syncer{Store: st, OSV: osv.New("vigil/" + version), Log: log}
}

func runServe(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	addr := fs.String("addr", "127.0.0.1:8080", "adresse d'écoute")
	certFile := fs.String("tls-cert", "", "certificat TLS (PEM)")
	keyFile := fs.String("tls-key", "", "clé privée TLS (PEM)")
	behindProxy := fs.Bool("behind-proxy", false, "TLS terminé par un reverse proxy")
	interval := fs.Duration("sync-interval", 6*time.Hour, "intervalle de synchronisation automatique (0 = désactivé)")
	fs.Parse(args)

	useTLS := *certFile != "" && *keyFile != ""
	// SECURITY: refuse to expose the UI in clear text on a non-local interface.
	if !isLocalAddr(*addr) && !useTLS && !*behindProxy {
		return errors.New("écoute sur une interface non locale : fournissez -tls-cert/-tls-key ou -behind-proxy")
	}

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	syncer := newSyncer(st, log)
	srv := &web.Server{Store: st, Syncer: syncer, Log: log, SecureCookies: useTLS || *behindProxy}
	handler, err := srv.Handler()
	if err != nil {
		return err
	}
	go srv.PurgeSessions(ctx)
	if *interval > 0 {
		go periodicSync(ctx, log, syncer, *interval)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdown)
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Info("vigil démarré", "url", scheme+"://"+*addr, "db", *dbPath)
	if useTLS {
		err = httpSrv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func periodicSync(ctx context.Context, log *slog.Logger, s *tracking.Syncer, every time.Duration) {
	run := func() {
		if _, err := s.Run(ctx); err != nil && !errors.Is(err, tracking.ErrRunning) {
			log.Error("synchronisation automatique", "err", err)
		}
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func isLocalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runSync(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	fs.Parse(args)

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := newSyncer(st, log).Run(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%d actifs interrogés, %d nouvelles vulnérabilités, %d réouvertes, %d résolues automatiquement\n",
		res.Assets, res.Created, res.Reopened, res.Resolved)
	return nil
}

func runDigest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	fs.Parse(args)

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	d, err := digest.Generate(ctx, st)
	if err != nil {
		return err
	}
	fmt.Print(d.Markdown)
	return nil
}

func runUser(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("sous-commande attendue : user add")
	}
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	username := fs.String("username", "", "nom d'utilisateur")
	role := fs.String("role", auth.RoleAnalyst, "rôle : admin, analyst ou viewer")
	fs.Parse(args[1:])

	if *username == "" || len(*username) > 64 {
		return errors.New("-username est obligatoire (64 caractères max)")
	}
	if !auth.ValidRole(*role) {
		return errors.New("rôle invalide")
	}
	password, err := readPassword()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	id, err := st.CreateUser(ctx, *username, hash, *role)
	if err != nil {
		return err
	}
	st.Audit(ctx, 0, "user_create", fmt.Sprintf("id=%d role=%s (CLI)", id, *role))
	fmt.Printf("utilisateur %q créé (%s)\n", *username, *role)
	return nil
}

// readPassword reads a password without echo from a terminal, or one line from stdin.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Mot de passe : ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
