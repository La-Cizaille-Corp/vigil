// Command vigil is a lightweight security watch tool: asset inventory,
// vulnerability tracking, threat-intelligence news and digests, in a single binary.
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
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sbom"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/nvd"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
	"github.com/La-Cizaille-Corp/vigil/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `vigil — veille de sécurité légère

Usage :
  vigil serve   [-db fichier] [-addr 127.0.0.1:8080] [-tls-cert c -tls-key k] [-behind-proxy]
                [-sync-interval 6h] [-digest-interval 24h] [-base-url https://...] [-allow-private-urls]
  vigil sync    [-db fichier] [-allow-private-urls]
  vigil digest  [-db fichier] [-no-webhooks] [-allow-private-urls]
  vigil import-sbom [-project nom] [-db fichier] fichier.json
  vigil user add -username nom [-role admin|analyst|viewer] [-db fichier]
  vigil version

La base par défaut se trouve dans le dossier de configuration de l'utilisateur
(variable VIGIL_DB pour la changer). Clé NVD facultative : VIGIL_NVD_API_KEY.
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
		err = runDigest(ctx, log, args)
	case "import-sbom":
		err = runImportSBOM(ctx, args)
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

func userAgent() string {
	return "vigil/" + version + " (+https://github.com/La-Cizaille-Corp/vigil)"
}

// services groups the background workers, sharing one configuration.
type services struct {
	syncer   *tracking.Syncer
	cti      *cti.Collector
	notifier *notify.Notifier
}

func newServices(st *store.Store, log *slog.Logger, allowPrivate bool) services {
	fixed := &http.Client{Timeout: 60 * time.Second} // OSV, KEV, EPSS: fixed public hosts
	// SECURITY: feeds and webhooks are user-supplied URLs, guarded against SSRF.
	userURLs := netsafe.NewClient(60*time.Second, allowPrivate)
	ua := userAgent()
	return services{
		syncer: &tracking.Syncer{Store: st, OSV: osv.New(ua), Log: log, HTTP: fixed, UserAgent: ua,
			// The optional key (free, https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit.
			NVD: &nvd.Client{URL: nvd.DefaultURL, HTTP: fixed, UserAgent: ua, APIKey: os.Getenv("VIGIL_NVD_API_KEY")}},
		cti:      &cti.Collector{Store: st, HTTP: userURLs, UserAgent: ua, Log: log},
		notifier: &notify.Notifier{Store: st, HTTP: userURLs, UserAgent: ua, Log: log},
	}
}

// refresh runs a vulnerability sync then a CTI collection.
func (sv services) refresh(ctx context.Context) error {
	_, syncErr := sv.syncer.Run(ctx)
	if errors.Is(syncErr, tracking.ErrRunning) {
		syncErr = nil
	}
	_, ctiErr := sv.cti.Run(ctx)
	return errors.Join(syncErr, ctiErr)
}

func runServe(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	addr := fs.String("addr", "127.0.0.1:8080", "adresse d'écoute")
	certFile := fs.String("tls-cert", "", "certificat TLS (PEM)")
	keyFile := fs.String("tls-key", "", "clé privée TLS (PEM)")
	behindProxy := fs.Bool("behind-proxy", false, "TLS terminé par un reverse proxy")
	syncEvery := fs.Duration("sync-interval", 6*time.Hour, "intervalle de synchronisation vulnérabilités + CTI (0 = désactivé)")
	digestEvery := fs.Duration("digest-interval", 0, "intervalle de génération et d'envoi du digest, ex. 24h (0 = désactivé)")
	baseURL := fs.String("base-url", "", "adresse publique de l'interface, utilisée dans les messages webhook")
	allowPrivate := fs.Bool("allow-private-urls", false, "autoriser flux et webhooks vers des adresses privées ou locales")
	parseFlags(fs, args)

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

	sv := newServices(st, log, *allowPrivate)
	srv := &web.Server{Store: st, Syncer: sv.syncer, CTI: sv.cti, Notifier: sv.notifier, Log: log,
		Version: version, BaseURL: *baseURL, SecureCookies: useTLS || *behindProxy, Context: ctx}
	handler, err := srv.Handler()
	if err != nil {
		return err
	}
	// Bind before starting background work so a busy port fails fast and cleanly.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("écoute sur %s (port déjà utilisé ?) : %w", *addr, err)
	}
	go srv.PurgeSessions(ctx)
	if *syncEvery > 0 {
		go every(ctx, *syncEvery, true, func() {
			if err := sv.refresh(ctx); err != nil {
				log.Error("synchronisation automatique", "err", err)
			}
		})
	}
	if *digestEvery > 0 {
		go every(ctx, *digestEvery, false, func() {
			if err := generateAndSend(ctx, st, sv.notifier, *baseURL); err != nil {
				log.Error("digest automatique", "err", err)
			}
		})
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() { // #nosec G118 -- ctx is already cancelled here; shutdown needs a fresh deadline.
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdown); err != nil {
			log.Warn("arrêt du serveur", "err", err)
		}
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Info("vigil démarré", "url", scheme+"://"+*addr, "db", *dbPath)
	if useTLS {
		err = httpSrv.ServeTLS(ln, *certFile, *keyFile)
	} else {
		err = httpSrv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// every calls fn every period until ctx is done, and once at start if now is set.
func every(ctx context.Context, period time.Duration, now bool, fn func()) {
	if now {
		fn()
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

func generateAndSend(ctx context.Context, st *store.Store, n *notify.Notifier, baseURL string) error {
	d, err := digest.Generate(ctx, st)
	if err != nil {
		return err
	}
	link := ""
	if baseURL != "" {
		link = fmt.Sprintf("%s/digests/%d", strings.TrimRight(baseURL, "/"), d.ID)
	}
	return n.SendDigest(ctx, d, link)
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
	allowPrivate := fs.Bool("allow-private-urls", false, "autoriser les flux vers des adresses privées ou locales")
	parseFlags(fs, args)

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	sv := newServices(st, log, *allowPrivate)
	res, err := sv.syncer.Run(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%d actifs interrogés, %d nouvelles vulnérabilités, %d réouvertes, %d résolues automatiquement\n",
		res.Assets, res.Created, res.Reopened, res.Resolved)
	n, err := sv.cti.Run(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%d nouvelles actualités CTI\n", n)
	return nil
}

func runDigest(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	noHooks := fs.Bool("no-webhooks", false, "ne pas envoyer le digest aux webhooks")
	allowPrivate := fs.Bool("allow-private-urls", false, "autoriser les webhooks vers des adresses privées ou locales")
	parseFlags(fs, args)

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
	if *noHooks {
		return nil
	}
	return newServices(st, log, *allowPrivate).notifier.SendDigest(ctx, d, "")
}

func runImportSBOM(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("import-sbom", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	project := fs.String("project", "", "projet (par défaut : nom indiqué dans le SBOM)")
	parseFlags(fs, args)
	if fs.NArg() != 1 {
		return errors.New("usage : vigil import-sbom [-project nom] fichier.json")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	doc, err := sbom.Parse(f)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(*project)
	if name == "" {
		name = doc.Name
	}
	if name == "" || len(name) > 200 {
		return errors.New("le SBOM ne nomme pas de composant principal : précisez -project")
	}

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := st.ReplaceProjectAssets(ctx, name, doc.Assets)
	if err != nil {
		return err
	}
	auditCLI(ctx, st, "sbom_import", fmt.Sprintf("%s (CLI): %s +%d =%d -%d", name, doc.Format, res.Added, res.Kept, res.Removed))
	fmt.Printf("projet %q (%s) : %d ajoutés, %d conservés, %d retirés, %d composants ignorés (sans purl)\n",
		name, doc.Format, res.Added, res.Kept, res.Removed, doc.Skipped)
	return nil
}

func runUser(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "reset-totp" {
		return runResetTOTP(ctx, args[1:])
	}
	if len(args) == 0 || args[0] != "add" {
		return errors.New("sous-commande attendue : user add ou user reset-totp")
	}
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	username := fs.String("username", "", "nom d'utilisateur")
	role := fs.String("role", auth.RoleAnalyst, "rôle : admin, analyst ou viewer")
	parseFlags(fs, args[1:])

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
	auditCLI(ctx, st, "user_create", fmt.Sprintf("id=%d role=%s (CLI)", id, *role))
	fmt.Printf("utilisateur %q créé (%s)\n", *username, *role)
	return nil
}

// parseFlags parses args; with flag.ExitOnError, Parse exits on error and
// never returns one.
func parseFlags(fs *flag.FlagSet, args []string) { _ = fs.Parse(args) }

// auditCLI records a CLI action and warns if the audit log cannot be written.
func auditCLI(ctx context.Context, st *store.Store, action, detail string) {
	if err := st.Audit(ctx, 0, action, detail); err != nil {
		fmt.Fprintln(os.Stderr, "avertissement : journal d'audit non écrit :", err)
	}
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

// runResetTOTP disables the second factor of a user who lost their authenticator.
func runResetTOTP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("user reset-totp", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	username := fs.String("username", "", "nom d'utilisateur")
	parseFlags(fs, args)
	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.DisableTOTPByName(ctx, *username); err != nil {
		return fmt.Errorf("utilisateur %q : %w", *username, err)
	}
	auditCLI(ctx, st, "totp_reset", *username)
	fmt.Printf("double authentification désactivée pour %q\n", *username)
	return nil
}
