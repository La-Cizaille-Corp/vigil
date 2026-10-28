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
	"syscall"
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
                [-backup-dir dossier -backup-interval 24h -backup-keep 14] [options SMTP]
  vigil sync    [-db fichier] [-allow-private-urls] [options SMTP]
  vigil digest  [-db fichier] [-no-webhooks] [-allow-private-urls] [options SMTP]
  vigil import-sbom [-project nom] [-db fichier] fichier.json
  vigil backup  -o fichier.db [-db fichier]
  vigil check   [-db fichier]
  vigil user add -username nom [-role admin|analyst|viewer] [-db fichier]
  vigil user reset-totp -username nom [-db fichier]
  vigil version

La base par défaut se trouve dans le dossier de configuration de l'utilisateur
(variable VIGIL_DB pour la changer). Clé NVD facultative : VIGIL_NVD_API_KEY.
Chaque option peut aussi venir de l'environnement : -sync-interval → VIGIL_SYNC_INTERVAL ;
une option passée en ligne de commande l'emporte.

Options SMTP (notifications par e-mail) : -smtp-addr hôte:port -smtp-from adresse
  [-smtp-tls starttls|tls|none] [-smtp-username nom] ; mot de passe : VIGIL_SMTP_PASSWORD.
Proxy sortant : variables HTTPS_PROXY et NO_PROXY.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// SIGTERM is what Docker and systemd send: shut down cleanly on it too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	case "backup":
		err = runBackup(ctx, args)
	case "check":
		err = runCheck(ctx, args)
	case "version":
		fmt.Printf("%s (schéma de base %d)\n", version, store.LatestSchema())
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

// openStore opens the database, upgrading its schema if this version is newer.
func openStore(ctx context.Context, path string) (*store.Store, error) {
	st, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	if b := st.UpgradeBackup(); b != "" {
		v, _ := st.SchemaVersion(ctx)
		fmt.Fprintf(os.Stderr, "base mise à jour vers le schéma %d ; copie de l'ancienne base : %s\n", v, b)
	}
	return st, nil
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

// smtpFlags registers the SMTP options of a command; the returned function
// builds the mailer once the flags are parsed (nil without -smtp-addr).
func smtpFlags(fs *flag.FlagSet) func() (*notify.Mailer, error) {
	addr := fs.String("smtp-addr", "", "serveur SMTP hôte:port pour les notifications par e-mail (vide = désactivé)")
	mode := fs.String("smtp-tls", notify.MailSTARTTLS, "chiffrement SMTP : starttls (587), tls (465) ou none (relais local)")
	username := fs.String("smtp-username", "", "identifiant SMTP (facultatif)")
	// SECURITY: prefer VIGIL_SMTP_PASSWORD: a command-line value is visible to other local users.
	password := fs.String("smtp-password", "", "mot de passe SMTP (préférez la variable VIGIL_SMTP_PASSWORD)")
	from := fs.String("smtp-from", "", "adresse d'expédition des e-mails")
	return func() (*notify.Mailer, error) {
		return notify.NewMailer(*addr, *mode, *username, *password, *from)
	}
}

func newServices(st *store.Store, log *slog.Logger, allowPrivate bool, mail *notify.Mailer, baseURL string) services {
	fixed := &http.Client{Timeout: 60 * time.Second} // OSV, KEV, EPSS: fixed public hosts
	// SECURITY: feeds and webhooks are user-supplied URLs, guarded against SSRF.
	userURLs := netsafe.NewClient(60*time.Second, allowPrivate)
	ua := userAgent()
	sv := services{
		syncer: &tracking.Syncer{Store: st, OSV: osv.New(ua), Log: log, HTTP: fixed, UserAgent: ua,
			// The optional key (free, https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit.
			NVD: &nvd.Client{URL: nvd.DefaultURL, HTTP: fixed, UserAgent: ua, APIKey: os.Getenv("VIGIL_NVD_API_KEY")}},
		cti:      &cti.Collector{Store: st, HTTP: userURLs, UserAgent: ua, Log: log},
		notifier: &notify.Notifier{Store: st, HTTP: userURLs, Mail: mail, BaseURL: baseURL, UserAgent: ua, Log: log},
	}
	sv.syncer.Alert = sv.notifier.SendAlerts
	return sv
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
	backupDir := fs.String("backup-dir", "", "dossier des sauvegardes automatiques (vide = désactivées)")
	backupEvery := fs.Duration("backup-interval", 24*time.Hour, "intervalle des sauvegardes automatiques")
	backupKeep := fs.Int("backup-keep", 14, "nombre de sauvegardes automatiques conservées")
	mailer := smtpFlags(fs)
	parseFlags(fs, args)
	mail, err := mailer()
	if err != nil {
		return err
	}

	useTLS := *certFile != "" && *keyFile != ""
	// SECURITY: refuse to expose the UI in clear text on a non-local interface.
	if !isLocalAddr(*addr) && !useTLS && !*behindProxy {
		return errors.New("écoute sur une interface non locale : fournissez -tls-cert/-tls-key ou -behind-proxy")
	}

	st, err := openStore(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	sv := newServices(st, log, *allowPrivate, mail, *baseURL)
	srv := &web.Server{Store: st, Syncer: sv.syncer, CTI: sv.cti, Notifier: sv.notifier, Log: log,
		Version: version, BaseURL: *baseURL, SecureCookies: useTLS || *behindProxy, BehindProxy: *behindProxy, Context: ctx}
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
	if *backupDir != "" && *backupEvery > 0 {
		go every(ctx, *backupEvery, true, func() {
			if path, err := st.BackupTo(ctx, *backupDir, *backupKeep); err != nil {
				log.Error("sauvegarde automatique", "err", err)
			} else {
				log.Info("sauvegarde", "file", path)
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
	allowPrivate := fs.Bool("allow-private-urls", false, "autoriser flux et webhooks vers des adresses privées ou locales")
	baseURL := fs.String("base-url", "", "adresse publique de l'interface, pour les liens des alertes")
	mailer := smtpFlags(fs)
	parseFlags(fs, args)
	mail, err := mailer()
	if err != nil {
		return err
	}

	st, err := openStore(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	sv := newServices(st, log, *allowPrivate, mail, *baseURL)
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
	mailer := smtpFlags(fs)
	parseFlags(fs, args)
	mail, err := mailer()
	if err != nil {
		return err
	}

	st, err := openStore(ctx, *dbPath)
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
	return newServices(st, log, *allowPrivate, mail, "").notifier.SendDigest(ctx, d, "")
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

	st, err := openStore(ctx, *dbPath)
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
	st, err := openStore(ctx, *dbPath)
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
// parseFlags parses the command line, then fills every option not given on
// it from the environment (VIGIL_ + name in upper snake case), so that a
// container or a systemd unit can be configured with an environment file.
func parseFlags(fs *flag.FlagSet, args []string) {
	_ = fs.Parse(args) // ExitOnError: never returns an error
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	fs.VisitAll(func(f *flag.Flag) {
		env := "VIGIL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok && !set[f.Name] {
			if err := fs.Set(f.Name, v); err != nil {
				fmt.Fprintf(os.Stderr, "erreur : %s=%q : %v\n", env, v, err)
				os.Exit(2)
			}
		}
	})
}

// runBackup writes a consistent copy of the database, safe while the server runs.
func runBackup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite")
	out := fs.String("o", "", "fichier de sauvegarde à créer")
	parseFlags(fs, args)
	if *out == "" {
		return errors.New("-o est obligatoire")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s existe déjà", *out)
	}
	// The copy is taken as is: no schema upgrade, even with a newer binary.
	if err := store.BackupFile(ctx, *dbPath, *out); err != nil {
		return err
	}
	fmt.Printf("sauvegarde cohérente écrite et vérifiée : %s\n", *out)
	return nil
}

// runCheck verifies the integrity of a database or of a backup before a restore.
func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB(), "fichier SQLite ou sauvegarde à vérifier")
	parseFlags(fs, args)
	if err := store.CheckIntegrity(ctx, *dbPath); err != nil {
		return err
	}
	schema, err := store.FileSchema(ctx, *dbPath)
	if err != nil {
		return err
	}
	switch latest := store.LatestSchema(); {
	case schema > latest:
		fmt.Printf("%s : intègre, schéma %d, plus récent que cette version de Vigil (schéma %d)\n", *dbPath, schema, latest)
	case schema < latest:
		fmt.Printf("%s : intègre, schéma %d, mis à jour vers le schéma %d au prochain démarrage\n", *dbPath, schema, latest)
	default:
		fmt.Printf("%s : intègre, schéma %d (à jour)\n", *dbPath, schema)
	}
	return nil
}

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
	st, err := openStore(ctx, *dbPath)
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
