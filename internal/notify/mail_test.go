package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// fakeSMTP is a minimal SMTP server recording the messages it receives.
type fakeSMTP struct {
	addr     string
	starttls bool // advertise STARTTLS
	mu       sync.Mutex
	rcpts    []string
	data     []string
	auth     bool
}

func newFakeSMTP(t *testing.T, starttls bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeSMTP{addr: ln.Addr().String(), starttls: starttls}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	reply := func(line string) { io.WriteString(conn, line+"\r\n") }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if s.starttls {
				reply("250-fake")
				reply("250-STARTTLS")
			} else {
				reply("250-fake")
			}
			reply("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH"):
			s.mu.Lock()
			s.auth = true
			s.mu.Unlock()
			reply("235 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, strings.Trim(strings.TrimSpace(line[8:]), "<>"))
			s.mu.Unlock()
			reply("250 ok")
		case cmd == "DATA":
			reply("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = append(s.data, b.String())
			s.mu.Unlock()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func TestMailerSend(t *testing.T) {
	srv := newFakeSMTP(t, false)
	m, err := NewMailer(srv.addr, MailNoTLS, "vigil", "secret", "Vigil <vigil@example.org>")
	if err != nil {
		t.Fatal(err)
	}
	to, err := ParseRecipients("rssi@example.org; Équipe <soc@example.org>")
	if err != nil || len(to) != 2 {
		t.Fatalf("recipients: %v %v", to, err)
	}
	if err := m.Send(context.Background(), to, "[Vigil] Alerte : 2 vulnérabilités", "Ligne accentuée é\n- CVE-2024-3400"); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.data) != 1 || strings.Join(srv.rcpts, ",") != "rssi@example.org,soc@example.org" || !srv.auth {
		t.Fatalf("server got %v / %v / auth %v", srv.data, srv.rcpts, srv.auth)
	}
	head, body, _ := strings.Cut(srv.data[0], "\r\n\r\n")
	for _, want := range []string{"From: vigil@example.org", "Subject: =?utf-8?q?", "Auto-Submitted: auto-generated",
		"Content-Transfer-Encoding: quoted-printable"} {
		if !strings.Contains(head, want) {
			t.Errorf("header misses %q:\n%s", want, head)
		}
	}
	decoded, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if !strings.Contains(string(decoded), "accentuée é") || !strings.Contains(string(decoded), "CVE-2024-3400") {
		t.Errorf("body: %q", decoded)
	}
}

// SECURITY: a server that does not offer STARTTLS must not receive the
// credentials or the message in clear text.
func TestMailerRequiresSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, false)
	m, _ := NewMailer(srv.addr, "", "vigil", "secret", "vigil@example.org")
	err := m.Send(context.Background(), []string{"a@example.org"}, "s", "t")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("clear-text fallback: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.auth || len(srv.data) != 0 {
		t.Error("credentials or message sent without TLS")
	}
}

func TestMailerSettings(t *testing.T) {
	if m, err := NewMailer("", "", "", "", ""); m != nil || err != nil {
		t.Error("no address should disable e-mail")
	}
	for _, c := range [][3]string{{"smtp.example.org", "", "a@b.c"}, {"smtp.example.org:587", "ssl", "a@b.c"}, {"smtp.example.org:587", "", "pas une adresse"}} {
		if _, err := NewMailer(c[0], c[1], "", "", c[2]); err == nil {
			t.Errorf("accepted %v", c)
		}
	}
	if _, err := ParseRecipients("a@b.c\r\nBcc: x@y.z"); err == nil {
		t.Error("header injection accepted")
	}
	if _, err := ParseRecipients(strings.Repeat("a@b.c,", 21) + "a@b.c"); err == nil {
		t.Error("too many recipients accepted")
	}
}

func TestSendAlerts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var mu sync.Mutex
	bodies := map[string][]map[string]any{}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		bodies[r.URL.Path] = append(bodies[r.URL.Path], body)
		mu.Unlock()
	}))
	defer web.Close()
	mailSrv := newFakeSMTP(t, false)
	mailer, _ := NewMailer(mailSrv.addr, MailNoTLS, "", "", "vigil@example.org")
	for _, h := range []store.Webhook{
		{Name: "prio", Kind: "slack", URL: web.URL + "/prio", Enabled: true, Alerts: "priority"},
		{Name: "all", Kind: "generic", URL: web.URL + "/severe", Enabled: true, Alerts: "severe"},
		{Name: "digest-only", Kind: "slack", URL: web.URL + "/digest", Enabled: true, Digests: true},
		{Name: "mail", Kind: "email", URL: "rssi@example.org", Enabled: true, Alerts: "priority"},
	} {
		if _, err := st.CreateWebhook(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	assetID, _ := st.CreateAsset(ctx, store.Asset{Name: "fortios", Version: "7.2.4", Kind: "os", Criticality: "high", Source: "manual"})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-KEV", Severity: "CRITICAL", Summary: "Contournement d'authentification", EPSS: -1, CVSS: 9.8})
	st.UpsertVulnerability(ctx, store.Vulnerability{ID: "CVE-HIGH", Severity: "HIGH", EPSS: -1, CVSS: 7.5})
	st.SetExploitSignals(ctx, "CVE-KEV", true, "", 0.9)
	st.ObserveFinding(ctx, assetID, "CVE-KEV", time.Now())
	st.ObserveFinding(ctx, assetID, "CVE-HIGH", time.Now())

	n := &Notifier{Store: st, HTTP: web.Client(), Mail: mailer, BaseURL: "https://vigil.example.org/",
		UserAgent: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := n.SendAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	prio, severe, digest := bodies["/prio"], bodies["/severe"], bodies["/digest"]
	mu.Unlock()
	if len(prio) != 1 || len(severe) != 1 || len(digest) != 0 {
		t.Fatalf("deliveries: prio %d, severe %d, digest-only %d", len(prio), len(severe), len(digest))
	}
	text, _ := prio[0]["text"].(string)
	if !strings.Contains(text, "CVE-KEV") || strings.Contains(text, "CVE-HIGH") ||
		!strings.Contains(text, "exploitée (CISA KEV)") || !strings.Contains(text, "https://vigil.example.org/findings/") {
		t.Errorf("priority alert: %s", text)
	}
	if items, _ := severe[0]["findings"].([]any); severe[0]["event"] != "alert" || len(items) != 2 {
		t.Errorf("generic alert: %v", severe[0])
	}
	mailSrv.mu.Lock()
	if len(mailSrv.data) != 1 || !strings.Contains(mailSrv.data[0], "CVE-KEV") {
		t.Errorf("e-mail alert: %v", mailSrv.data)
	}
	mailSrv.mu.Unlock()

	// Nothing new: nothing sent.
	if err := n.SendAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies["/prio"]) != 1 || len(bodies["/severe"]) != 1 {
		t.Error("the same findings were alerted twice")
	}
}
