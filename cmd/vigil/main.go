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
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/cti"
	"github.com/La-Cizaille-Corp/vigil/internal/digest"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/notify"
	"github.com/La-Cizaille-Corp/vigil/internal/sbom"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/epss"
	"github.com/La-Cizaille-Corp/vigil/internal/sources/kev"
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
                [-backup-dir dossier -backup-interval 24h -backup-keep 14] [-audit-retention-days 0] [options SMTP]
  vigil sync    [-db fichier] [-base-url https://...] [-allow-private-urls] [options SMTP]
  vigil digest  [-db fichier] [-no-webhooks] [-base-url https://...] [-allow-private-urls] [options SMTP]
  vigil import-sbom [-project nom] [-db fichier] fichier.json
  vigil backup  -o fichier.db [-db fichier]
  vigil check   [-db fichier]
  vigil user add -username nom [-role admin|analyst|viewer] [-db fichier]
  vigil user list [-db fichier]
  vigil user set-role -username nom -role admin|analyst|viewer [-db fichier]
  vigil user disable|enable -username nom [-db fichier]
  vigil user reset-password -username nom [-db fichier]
  vigil user reset-totp -username nom | -all [-db fichier]
  vigil version

Mot de passe de user add et user reset-password : ` + auth.PasswordHelp + `.

La base par défaut se trouve dans le dossier de configuration de l'utilisateur
(-db ou variable VIGIL_DB pour la changer). Clé NVD facultative de serve, sync et digest :
-nvd-api-key ou, de préférence, VIGIL_NVD_API_KEY.
Chaque option peut aussi venir de l'environnement : -sync-interval → VIGIL_SYNC_INTERVAL ;
une option passée en ligne de commande l'emporte.

Options SMTP (notifications par e-mail) : -smtp-addr hôte:port -smtp-from adresse
  [-smtp-tls starttls|tls|none] [-smtp-username nom] ; mot de passe : VIGIL_SMTP_PASSWORD.
Proxy sortant : variables HTTPS_PROXY et NO_PROXY.
`

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// SIGTERM is what Docker and systemd send: shut down cleanly on it too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, log, os.Args[1:])
	stop()
	var bad *usageError
	switch {
	case errors.Is(err, flag.ErrHelp): // -h: the help asked for is shown
	case errors.As(err, &bad):
		if bad.err != nil {
			fmt.Fprintln(os.Stderr, "erreur :", bad.err)
		}
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "erreur :", err)
		os.Exit(1)
	}
}

// run runs the command named by args[0] with the rest of args.
func run(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return &usageError{}
	}
	switch cmd, args := args[0], args[1:]; cmd {
	case "serve":
		return runServe(ctx, log, args)
	case "sync":
		return runSync(ctx, log, args)
	case "digest":
		return runDigest(ctx, log, args)
	case "import-sbom":
		return runImportSBOM(ctx, args)
	case "user":
		return runUser(ctx, args)
	case "backup":
		return runBackup(ctx, args)
	case "check":
		return runCheck(ctx, args)
	case "version":
		fmt.Printf("%s (schéma de base %d)\n", version, store.LatestSchema())
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return &usageError{}
}

// usageError is a command line that cannot run: vigil exits with status 2,
// as flag.ExitOnError does. err, when set, is still to be shown; flag has
// already shown the others, with the usage of the command.
type usageError struct{ err error }

func (e *usageError) Error() string {
	if e.err == nil {
		return "invalid command line"
	}
	return e.err.Error()
}

func (e *usageError) Unwrap() error { return e.err }

// defaultDB is the database used without -db or VIGIL_DB.
func defaultDB() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "vigil.db"
	}
	return filepath.Join(dir, "vigil", "vigil.db")
}

// options are the settings a command shares with others, each declared once
// with one help text: the database for every command and, for those that run
// the services (serve, sync, digest), the public address, the private URLs,
// the NVD key and the mail server.
type options struct {
	fs           *flag.FlagSet
	db           *string
	baseURL      *string
	allowPrivate *bool
	nvdKey       *string
	mailer       func() (*notify.Mailer, error)
	mail         *notify.Mailer // built by parse; nil without -smtp-addr
}

// newCommand returns the flags of the command name, the shared options
// already declared; withServices adds those of the services. The command
// declares its own flags on the set, then calls parse.
func newCommand(name string, withServices bool) (*flag.FlagSet, *options) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	o := &options{fs: fs, db: fs.String("db", defaultDB(), "fichier SQLite")}
	if withServices {
		o.baseURL = fs.String("base-url", "", "adresse publique de l'interface, pour les liens des alertes, des digests et des webhooks")
		o.allowPrivate = fs.Bool("allow-private-urls", false, "autoriser flux et webhooks vers des adresses privées ou locales")
		// SECURITY: prefer VIGIL_NVD_API_KEY: a command-line value is visible to other local users.
		o.nvdKey = fs.String("nvd-api-key", "", "clé d'API NVD facultative, qui relève la limite de requêtes (préférez la variable VIGIL_NVD_API_KEY)")
		o.mailer = smtpFlags(fs)
	}
	return fs, o
}

// parse reads the command line, then fills every option not given on it from
// the environment (VIGIL_ + name in upper snake case: -sync-interval →
// VIGIL_SYNC_INTERVAL), so that a container or a systemd unit can be
// configured with an environment file. It then checks the mail settings,
// before anything is opened.
func (o *options) parse(args []string) error {
	if err := o.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{} // flag has shown the error and the usage
	}
	set := map[string]bool{}
	o.fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var err error
	o.fs.VisitAll(func(f *flag.Flag) {
		env := "VIGIL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok && !set[f.Name] && err == nil {
			if e := o.fs.Set(f.Name, v); e != nil {
				err = &usageError{fmt.Errorf("%s=%q : %w", env, v, e)}
			}
		}
	})
	if err != nil || o.mailer == nil {
		return err
	}
	o.mail, err = o.mailer()
	return err
}

// open opens the database of -db, upgrading its schema if this version is newer.
func (o *options) open(ctx context.Context) (*store.Store, error) {
	st, err := store.Open(ctx, *o.db)
	if err != nil {
		return nil, err
	}
	if b := st.UpgradeBackup(); b != "" {
		if v, err := st.SchemaVersion(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "base mise à jour ; copie de l'ancienne base : %s ; version du schéma illisible : %v\n", b, err)
		} else {
			fmt.Fprintf(os.Stderr, "base mise à jour vers le schéma %d ; copie de l'ancienne base : %s\n", v, b)
		}
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

// services builds the background services on st, with the options of a
// command made by newCommand(name, true).
func (o *options) services(st *store.Store, log *slog.Logger) services {
	// OSV, NVD, KEV, EPSS: fixed public hosts, reached in HTTPS only.
	// SECURITY: the NVD key is dropped if a redirect changes host.
	fixed := &http.Client{Timeout: 60 * time.Second, CheckRedirect: netsafe.CheckRedirect("apiKey")}
	// OSV gets a copy, same transport and redirect policy, with its longer time limit.
	osvHTTP := *fixed
	osvHTTP.Timeout = osv.Timeout
	// SECURITY: feeds and webhooks are user-supplied URLs, guarded against SSRF.
	userURLs := netsafe.NewClient(60*time.Second, *o.allowPrivate)
	ua := userAgent()
	sv := services{
		syncer: &tracking.Syncer{Store: st, Log: log,
			OSV: &osv.Client{HTTP: &osvHTTP, UserAgent: ua},
			// The optional key (free, https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit.
			NVD:  &nvd.Client{HTTP: fixed, UserAgent: ua, APIKey: *o.nvdKey},
			KEV:  &kev.Client{HTTP: fixed, UserAgent: ua},
			EPSS: &epss.Client{HTTP: fixed, UserAgent: ua}},
		cti:      &cti.Collector{Store: st, HTTP: userURLs, UserAgent: ua, Log: log},
		notifier: &notify.Notifier{Store: st, HTTP: userURLs, Mail: o.mail, BaseURL: *o.baseURL, UserAgent: ua, Log: log},
	}
	sv.syncer.Alert = sv.notifier.SendAlerts
	return sv
}

func runServe(ctx context.Context, log *slog.Logger, args []string) error {
	fs, o := newCommand("serve", true)
	addr := fs.String("addr", "127.0.0.1:8080", "adresse d'écoute")
	certFile := fs.String("tls-cert", "", "certificat TLS (PEM)")
	keyFile := fs.String("tls-key", "", "clé privée TLS (PEM)")
	behindProxy := fs.Bool("behind-proxy", false, "TLS terminé par un reverse proxy")
	syncEvery := fs.Duration("sync-interval", 6*time.Hour, "intervalle de synchronisation des vulnérabilités (0 = désactivé, collecte des flux comprise, dont la fréquence se règle dans Paramètres)")
	digestEvery := fs.Duration("digest-interval", 0, "intervalle de génération et d'envoi du digest, ex. 24h (0 = désactivé)")
	backupDir := fs.String("backup-dir", "", "dossier des sauvegardes automatiques (vide = désactivées)")
	backupEvery := fs.Duration("backup-interval", 24*time.Hour, "intervalle des sauvegardes automatiques")
	backupKeep := fs.Int("backup-keep", 14, "nombre de sauvegardes automatiques conservées")
	auditDays := fs.Int("audit-retention-days", 0, "durée de conservation du journal d'audit en jours (0 = sans limite)")
	if err := o.parse(args); err != nil {
		return err
	}
	if o.mail.Cleartext() {
		log.Warn("e-mail sent unencrypted to a remote server (-smtp-tls none): prefer starttls or tls", "smtp", o.mail.Addr)
	}

	useTLS := *certFile != "" && *keyFile != ""
	// SECURITY: refuse to expose the UI in clear text on a non-local interface.
	if !isLocalAddr(*addr) && !useTLS && !*behindProxy {
		return errors.New("écoute sur une interface non locale : fournissez -tls-cert/-tls-key ou -behind-proxy")
	}

	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	sv := o.services(st, log)
	srv := &web.Server{Store: st, Syncer: sv.syncer, CTI: sv.cti, Notifier: sv.notifier, Log: log,
		Version: version, BaseURL: *o.baseURL, SecureCookies: useTLS || *behindProxy, BehindProxy: *behindProxy, Context: ctx,
		LocalOnly: isLocalAddr(*addr) && !useTLS && !*behindProxy, AuditRetention: time.Duration(*auditDays) * 24 * time.Hour}
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
			if _, err := sv.syncer.Run(ctx); err != nil && !errors.Is(err, tracking.ErrRunning) {
				log.Error("scheduled sync failed", "err", err)
			}
		})
		go every(ctx, time.Minute, true, func() {
			if err := sv.cti.RunIfDue(ctx); err != nil {
				log.Error("scheduled cti collection failed", "err", err)
			}
		})
	}
	if *backupDir != "" && *backupEvery > 0 {
		go every(ctx, *backupEvery, true, func() {
			if path, err := st.BackupTo(ctx, *backupDir, *backupKeep); err != nil {
				log.Error("scheduled backup failed", "err", err)
			} else {
				log.Info("backup done", "file", path)
			}
		})
	}
	if *digestEvery > 0 {
		go every(ctx, *digestEvery, false, func() {
			if err := generateAndSend(ctx, st, sv.notifier, *o.baseURL); err != nil {
				log.Error("scheduled digest failed", "err", err)
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
			log.Warn("server shutdown failed", "err", err)
		}
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Info("vigil started", "url", scheme+"://"+*addr, "db", *o.db)
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
	return n.SendDigest(ctx, d, digestLink(baseURL, d.ID))
}

// digestLink is the address of a digest in the interface, "" without -base-url.
func digestLink(baseURL string, id int64) string {
	if baseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/digests/%d", strings.TrimRight(baseURL, "/"), id)
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
	_, o := newCommand("sync", true)
	if err := o.parse(args); err != nil {
		return err
	}
	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	sv := o.services(st, log)
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
	fs, o := newCommand("digest", true)
	noHooks := fs.Bool("no-webhooks", false, "ne pas envoyer le digest aux webhooks")
	if err := o.parse(args); err != nil {
		return err
	}
	st, err := o.open(ctx)
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
	return o.services(st, log).notifier.SendDigest(ctx, d, digestLink(*o.baseURL, d.ID))
}

func runImportSBOM(ctx context.Context, args []string) error {
	fs, o := newCommand("import-sbom", false)
	project := fs.String("project", "", "projet (par défaut : nom indiqué dans le SBOM)")
	if err := o.parse(args); err != nil {
		return err
	}
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
	if name == "" || !clip.Fits(name, inventory.MaxProjectLen) {
		return errors.New("le SBOM ne nomme pas de composant principal : précisez -project")
	}

	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := st.ReplaceProjectAssets(ctx, store.Everything, name, doc.Assets)
	if err != nil {
		return err
	}
	auditCLI(ctx, st, "sbom_import", "project", name, "format", doc.Format,
		"added", res.Added, "kept", res.Kept, "removed", res.Removed, "skipped", doc.Skipped)
	fmt.Printf("projet %q (%s) : %d ajoutés, %d conservés, %d retirés, %d composants ignorés (sans purl)\n",
		name, doc.Format, res.Added, res.Kept, res.Removed, doc.Skipped)
	return nil
}

func runUser(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch cmd, args := args[0], args[1:]; cmd {
		case "add":
			return runUserAdd(ctx, args)
		case "reset-totp":
			return runResetTOTP(ctx, args)
		case "list", "set-role", "disable", "enable", "reset-password":
			return runUserChange(ctx, cmd, args)
		}
	}
	return errors.New("sous-commande attendue : user add, list, set-role, disable, enable, reset-password ou reset-totp")
}

// runUserAdd creates an account, its password read from the terminal or stdin.
func runUserAdd(ctx context.Context, args []string) error {
	fs, o := newCommand("user add", false)
	username := fs.String("username", "", "nom d'utilisateur")
	role := fs.String("role", auth.RoleAnalyst, "rôle : admin, analyst ou viewer")
	if err := o.parse(args); err != nil {
		return err
	}

	if *username == "" || !clip.Fits(*username, auth.MaxUsernameLength) {
		return fmt.Errorf("-username est obligatoire (%d caractères max)", auth.MaxUsernameLength)
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
	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	id, err := st.CreateUser(ctx, *username, hash, *role)
	if errors.Is(err, store.ErrExists) {
		return fmt.Errorf("le nom d'utilisateur %q existe déjà (majuscules et minuscules ne comptent pas)", *username)
	}
	if err != nil {
		return err
	}
	auditCLI(ctx, st, "user_create", "id", id, "user", *username, "role", *role)
	fmt.Printf("utilisateur %q créé (%s)\n", *username, *role)
	return nil
}

// runBackup writes a consistent copy of the database, safe while the server runs.
func runBackup(ctx context.Context, args []string) error {
	fs, o := newCommand("backup", false)
	out := fs.String("o", "", "fichier de sauvegarde à créer")
	if err := o.parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-o est obligatoire")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s existe déjà", *out)
	}
	// The copy is taken as is: no schema upgrade, even with a newer binary.
	if err := store.BackupFile(ctx, *o.db, *out); err != nil {
		return err
	}
	fmt.Printf("sauvegarde cohérente écrite et vérifiée : %s\n", *out)
	return nil
}

// runCheck verifies the integrity of a database or of a backup before a restore.
func runCheck(ctx context.Context, args []string) error {
	_, o := newCommand("check", false)
	if err := o.parse(args); err != nil {
		return err
	}
	dbPath := o.db
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

// auditCLI records a CLI action, its detail the key-value pairs kv (see
// store.AuditDetail) and source=cli, and warns if the audit log cannot be
// written.
func auditCLI(ctx context.Context, st *store.Store, action string, kv ...any) {
	if err := st.Audit(ctx, 0, action, store.AuditDetail(append(kv, "source", "cli")...)); err != nil {
		fmt.Fprintln(os.Stderr, "avertissement : journal d'audit non écrit :", err)
	}
}

// readPassword reads a password without echo from a terminal, or one line from stdin.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Mot de passe ("+auth.PasswordHelp+") : ")
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

// runUserChange lists the accounts or changes one of them. Disabling,
// changing the password or the role takes effect at once on open sessions.
func runUserChange(ctx context.Context, cmd string, args []string) error {
	fs, o := newCommand("user "+cmd, false)
	username := fs.String("username", "", "nom d'utilisateur")
	role := fs.String("role", "", "rôle : admin, analyst ou viewer")
	if err := o.parse(args); err != nil {
		return err
	}
	if cmd != "list" && *username == "" {
		return errors.New("-username est obligatoire")
	}
	if cmd == "set-role" && !auth.ValidRole(*role) {
		return errors.New("-role doit valoir admin, analyst ou viewer")
	}
	var hash string
	if cmd == "reset-password" {
		password, err := readPassword()
		if err != nil {
			return err
		}
		if hash, err = auth.HashPassword(password); err != nil {
			return err
		}
	}
	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if cmd == "list" {
		accounts, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			state := "actif"
			if a.Disabled {
				state = "désactivé"
			}
			totp := ""
			if a.TOTP {
				totp = ", double authentification"
			}
			fmt.Printf("%-24s %-8s %s%s\n", a.Username, a.Role, state, totp)
		}
		return nil
	}
	a, err := st.AnyUserByName(ctx, *username)
	if err != nil {
		return fmt.Errorf("utilisateur %q : %w", *username, err)
	}
	detail := []any{"id", a.ID, "user", a.Username}
	switch cmd {
	case "set-role":
		err, detail = st.SetRole(ctx, a.ID, *role), append(detail, "role", *role)
	case "disable":
		err = st.SetDisabled(ctx, a.ID, true)
	case "enable":
		err = st.SetDisabled(ctx, a.ID, false)
	case "reset-password":
		err = st.ResetPassword(ctx, a.ID, hash)
	}
	if errors.Is(err, store.ErrLastAdmin) {
		return errors.New("refusé : il doit rester au moins un administrateur actif")
	}
	if err != nil {
		return fmt.Errorf("utilisateur %q : %w", *username, err)
	}
	auditCLI(ctx, st, map[string]string{"set-role": "user_role", "disable": "user_disable", "enable": "user_enable",
		"reset-password": "password_reset"}[cmd], detail...)
	fmt.Printf("%s : fait pour %q\n", cmd, *username)
	return nil
}

// runResetTOTP disables the second factor of a user who lost their authenticator.
func runResetTOTP(ctx context.Context, args []string) error {
	fs, o := newCommand("user reset-totp", false)
	username := fs.String("username", "", "nom d'utilisateur")
	all := fs.Bool("all", false, "tous les comptes (après une fuite de la base ou d'une sauvegarde)")
	if err := o.parse(args); err != nil {
		return err
	}
	if *all == (*username != "") {
		return errors.New("indiquez -username nom ou -all")
	}
	st, err := o.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if *all {
		n, err := st.ResetAllTOTP(ctx)
		if err != nil {
			return err
		}
		auditCLI(ctx, st, "totp_reset_all", "count", n)
		fmt.Printf("double authentification retirée de %d compte(s), leurs sessions sont fermées : chacun la reconfigure à sa prochaine connexion\n", n)
		return nil
	}
	if err := st.ResetTOTPByName(ctx, *username); err != nil {
		return fmt.Errorf("utilisateur %q : %w", *username, err)
	}
	auditCLI(ctx, st, "totp_reset", "user", *username)
	fmt.Printf("double authentification désactivée pour %q\n", *username)
	return nil
}
