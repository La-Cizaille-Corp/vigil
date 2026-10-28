// Package notify delivers digests and immediate alerts to notification
// channels: chat webhooks and e-mail.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// Kinds of channel.
var Kinds = []inventory.Option{
	{Value: "slack", Label: "Slack"},
	{Value: "mattermost", Label: "Mattermost"},
	{Value: "teams", Label: "Microsoft Teams"},
	{Value: "generic", Label: "JSON générique"},
	{Value: "email", Label: "E-mail"},
}

// AlertOptions are the immediate alerts a channel can receive.
var AlertOptions = []inventory.Option{
	{Value: "", Label: "Aucune alerte immédiate"},
	{Value: "priority", Label: "Exploitées ou probables (KEV, EPSS ≥ 10 %)"},
	{Value: "severe", Label: "Exploitées, probables, critiques et élevées"},
}

const (
	// maxText keeps messages below the limits of chat platforms.
	maxText = 30000
	// maxAlertLines bounds the findings listed in one alert.
	maxAlertLines = 15
)

// Notifier sends digests and alerts to every enabled channel.
type Notifier struct {
	Store     *store.Store
	HTTP      *http.Client // must come from netsafe.NewClient: URLs are user input
	Mail      *Mailer      // nil when no SMTP server is configured
	BaseURL   string       // public address of the UI, for links; may be empty
	UserAgent string
	Log       *slog.Logger
}

// ValidateWebhook checks a channel before it is stored.
func ValidateWebhook(w store.Webhook) error {
	if w.Name == "" || len(w.Name) > 100 {
		return errors.New("nom invalide")
	}
	if inventory.Label(Kinds, w.Kind) == w.Kind {
		return errors.New("type de canal invalide")
	}
	if inventory.Label(AlertOptions, w.Alerts) == w.Alerts && w.Alerts != "" {
		return errors.New("niveau d'alerte invalide")
	}
	if w.Kind == "email" {
		_, err := ParseRecipients(w.URL)
		return err
	}
	return netsafe.ValidateURL(w.URL)
}

// Target is what the UI shows of a channel's destination: e-mail recipients
// in full, webhook URLs without their secret part.
func Target(w store.Webhook) string {
	if w.Kind == "email" {
		return w.URL
	}
	return MaskURL(w.URL)
}

// MaskURL hides the secret part of a webhook URL for display.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "…"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// message is one notification, rendered for each kind of channel.
type message struct {
	Subject string         // e-mail subject
	Text    string         // Markdown, for chats and e-mail
	Event   map[string]any // payload of generic JSON webhooks
}

// SendDigest delivers a digest; failures are recorded per channel and joined.
func (n *Notifier) SendDigest(ctx context.Context, d store.Digest, link string) error {
	text := d.Markdown
	if len(text) > maxText {
		text = text[:maxText] + "\n\n… (tronqué, voir le digest complet dans Vigil)"
	}
	if link != "" {
		text += "\n\n" + link
	}
	day := d.CreatedAt
	if day.IsZero() {
		day = time.Now()
	}
	m := message{
		Subject: "[Vigil] Digest de veille du " + day.Format("02/01/2006"),
		Text:    text,
		Event: map[string]any{
			"event":      "digest",
			"digest_id":  d.ID,
			"created_at": d.CreatedAt,
			"since":      d.Since,
			"markdown":   d.Markdown,
			"link":       link,
		},
	}
	return n.deliver(ctx, m, func(h store.Webhook) bool { return h.Digests })
}

// SendAlerts notifies the open findings that became urgent since the last
// call (see store.PendingAlerts), then marks them notified, delivered or not:
// a failing channel shows its error in the settings, and the next digest
// lists the findings anyway.
func (n *Notifier) SendAlerts(ctx context.Context) error {
	alerts, err := n.Store.PendingAlerts(ctx)
	if err != nil || len(alerts) == 0 {
		return err
	}
	var errs []error
	for level, class := range store.AlertLevels {
		selected := alerts[:0:0]
		for _, a := range alerts {
			if a.Class >= class {
				selected = append(selected, a)
			}
		}
		if len(selected) == 0 {
			continue
		}
		m := n.alertMessage(selected)
		errs = append(errs, n.deliver(ctx, m, func(h store.Webhook) bool { return h.Alerts == level }))
	}
	if err := n.Store.MarkAlerted(ctx, alerts); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (n *Notifier) alertMessage(alerts []store.Alert) message {
	base := strings.TrimRight(n.BaseURL, "/")
	title := fmt.Sprintf("%d vulnérabilité à traiter en priorité", len(alerts))
	if len(alerts) > 1 {
		title = fmt.Sprintf("%d vulnérabilités à traiter en priorité", len(alerts))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Vigil — %s**\n\n", title)
	var items []map[string]any
	for i, a := range alerts {
		link := ""
		if base != "" {
			link = fmt.Sprintf("%s/findings/%d", base, a.ID)
		}
		reason := alertReason(a)
		if i < maxAlertLines {
			fmt.Fprintf(&b, "- **%s** (%s) — %s", a.VulnID, reason, strings.TrimSpace(a.AssetName+" "+a.AssetVersion))
			if a.Summary != "" {
				fmt.Fprintf(&b, " : %s", truncate(a.Summary, 140))
			}
			if link != "" {
				fmt.Fprintf(&b, " — %s", link)
			}
			b.WriteString("\n")
		}
		items = append(items, map[string]any{
			"finding_id": a.ID, "vuln_id": a.VulnID, "aliases": a.Aliases, "severity": a.Severity,
			"cvss": a.CVSS, "kev": a.KEV, "epss": a.EPSS, "asset": a.AssetName, "asset_version": a.AssetVersion,
			"project": a.AssetProject, "reason": reason, "raised": a.Raised, "link": link,
		})
	}
	if len(alerts) > maxAlertLines {
		fmt.Fprintf(&b, "- … et %d autre(s)\n", len(alerts)-maxAlertLines)
	}
	if base != "" {
		fmt.Fprintf(&b, "\nÀ traiter : %s/findings?priority=1\n", base)
	}
	return message{
		Subject: "[Vigil] " + title,
		Text:    b.String(),
		Event:   map[string]any{"event": "alert", "findings": items},
	}
}

// alertReason says why a finding is urgent, in French.
func alertReason(a store.Alert) string {
	var parts []string
	if a.Severity != "" {
		parts = append(parts, strings.ToLower(tracking.SeverityLabel(a.Severity)))
	}
	switch {
	case a.KEV:
		parts = append(parts, "exploitée (CISA KEV)")
	case a.EPSS >= 0.1:
		parts = append(parts, fmt.Sprintf("EPSS %d %%", int(math.Round(a.EPSS*100))))
	}
	if a.Raised {
		parts = append(parts, "devenue plus urgente")
	}
	if len(parts) == 0 {
		return "gravité inconnue"
	}
	return strings.Join(parts, ", ")
}

// deliver sends m to every enabled channel accepted by want.
func (n *Notifier) deliver(ctx context.Context, m message, want func(store.Webhook) bool) error {
	hooks, err := n.Store.ListWebhooks(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hooks {
		if !h.Enabled || !want(h) {
			continue
		}
		sendErr := n.send(ctx, h, m)
		if sendErr != nil {
			n.Log.Warn("notification en erreur", "canal", h.Name, "err", sendErr)
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, sendErr))
		}
		if err := n.Store.RecordWebhookResult(ctx, h.ID, sendErr); err != nil {
			return err
		}
	}
	return errors.Join(errs...)
}

func (n *Notifier) send(ctx context.Context, h store.Webhook, m message) error {
	if h.Kind == "email" {
		if n.Mail == nil {
			return errors.New("aucun serveur SMTP configuré (option -smtp-addr)")
		}
		to, err := ParseRecipients(h.URL)
		if err != nil {
			return err
		}
		return n.Mail.Send(ctx, to, m.Subject, m.Text)
	}
	var payload any = m.Event
	if h.Kind != "generic" {
		// Slack, Mattermost and Teams accept a Markdown "text" field on incoming webhooks.
		payload = map[string]string{"text": truncate(m.Text, maxText)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", n.UserAgent)
	resp, err := n.HTTP.Do(req)
	if err != nil {
		// SECURITY: *url.Error embeds the full URL, which holds the webhook secret.
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // drain for connection reuse
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("réponse HTTP %d", resp.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
