package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// TLS modes of the SMTP connection.
const (
	MailSTARTTLS = "starttls" // port 587: plain connection upgraded to TLS, required
	MailTLS      = "tls"      // port 465: TLS from the start
	MailNoTLS    = "none"     // local relay only: credentials are then refused by net/smtp
)

// maxRecipients bounds the recipients of one e-mail channel.
const maxRecipients = 20

// Mailer sends e-mail through the SMTP server configured by the operator.
type Mailer struct {
	Addr     string // host:port
	TLS      string
	Username string
	Password string
	From     string
	Timeout  time.Duration
}

// NewMailer checks the SMTP settings; it returns nil without an address.
func NewMailer(addr, mode, username, password, from string) (*Mailer, error) {
	if addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("serveur SMTP %q : attendu hôte:port", addr)
	}
	switch mode {
	case "":
		mode = MailSTARTTLS
	case MailSTARTTLS, MailTLS, MailNoTLS:
	default:
		return nil, fmt.Errorf("mode TLS SMTP %q : starttls, tls ou none", mode)
	}
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("expéditeur SMTP %q invalide", from)
	}
	return &Mailer{Addr: addr, TLS: mode, Username: username, Password: password,
		From: sender.Address, Timeout: 30 * time.Second}, nil
}

// ParseRecipients reads a comma- or semicolon-separated list of addresses.
func ParseRecipients(list string) ([]string, error) {
	parsed, err := mail.ParseAddressList(strings.ReplaceAll(list, ";", ","))
	if err != nil || len(parsed) == 0 {
		return nil, errors.New("adresses e-mail invalides (séparez-les par des virgules)")
	}
	if len(parsed) > maxRecipients {
		return nil, fmt.Errorf("%d destinataires au plus", maxRecipients)
	}
	out := make([]string, len(parsed))
	for i, a := range parsed {
		out[i] = a.Address
	}
	return out, nil
}

// Send delivers a plain-text message.
func (m *Mailer) Send(ctx context.Context, to []string, subject, text string) error {
	msg, err := buildMessage(m.From, to, subject, text, time.Now())
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(m.Addr)
	deadline := time.Now().Add(m.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", m.Addr)
	if err != nil {
		return fmt.Errorf("connexion SMTP : %w", err)
	}
	_ = conn.SetDeadline(deadline)
	// SECURITY: certificates are verified against the configured host name.
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if m.TLS == MailTLS {
		conn = tls.Client(conn, tlsConfig)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // the protocol error is the one to report
		return fmt.Errorf("SMTP : %w", err)
	}
	defer c.Close()
	if m.TLS == MailSTARTTLS {
		// SECURITY: never fall back to clear text when STARTTLS is expected.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("le serveur SMTP ne propose pas STARTTLS (utilisez -smtp-tls tls, ou none pour un relais local)")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS : %w", err)
		}
	}
	if m.Username != "" {
		// smtp.PlainAuth refuses to send credentials without TLS, except to localhost.
		if err := c.Auth(smtp.PlainAuth("", m.Username, m.Password, host)); err != nil {
			return fmt.Errorf("authentification SMTP : %w", err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM : %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("SMTP destinataire %s : %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA : %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP DATA : %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP DATA : %w", err)
	}
	return c.Quit()
}

// buildMessage writes a UTF-8 text message. Addresses come from
// ParseRecipients and NewMailer and the subject from Vigil itself; header
// values are still encoded so that no line break can reach the headers.
func buildMessage(from string, to []string, subject, text string, now time.Time) ([]byte, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	domain := "vigil.local"
	if _, d, ok := strings.Cut(from, "@"); ok {
		domain = d
	}
	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from)
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated") // RFC 3834: no auto-replies
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(text)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	if strings.ContainsAny(from+strings.Join(to, ""), "\r\n") {
		return nil, errors.New("adresse e-mail invalide")
	}
	return b.Bytes(), nil
}
