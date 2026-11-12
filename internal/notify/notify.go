// Package notify delivers digests and immediate alerts to notification
// channels: chat webhooks and e-mail.
package notify

import (
	"bytes"
	"cmp"
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

	"github.com/La-Cizaille-Corp/vigil/internal/chattext"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
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

// AlertOptions are the immediate alerts a channel can receive: the levels of
// tracking.Levels they cover.
var AlertOptions = []inventory.Option{
	{Value: "", Label: "Aucune alerte immédiate"},
	{Value: "priority", Label: "Urgentes (exploitées, probables ou jugées exploitables)"},
	{Value: "severe", Label: "Urgentes et à planifier (critiques ou hautes)"},
}

const (
	// maxText keeps messages below the limits of chat platforms.
	maxText = 30000
	// maxTeamsText keeps a card below the 28 KB of a Teams message.
	maxTeamsText = 20000
	// maxAlertLines bounds the findings listed in one alert.
	maxAlertLines = 15
	// maxNameLen is the longest channel name, in characters, as for the
	// feeds and API tokens of the same settings page.
	maxNameLen = 100
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
	if w.Name == "" || !clip.Fits(w.Name, maxNameLen) {
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
	// Cut once, below the chat limit, so that the note and the link survive.
	tail := ""
	if link != "" {
		tail = "\n\n" + link
	}
	text := d.Markdown
	if len(text)+len(tail) > maxText {
		note := "\n\n… (tronqué, voir le digest complet dans Vigil)"
		text = clip.Bytes(text, maxText-len(tail)-len(note)-len("…")) + note
	}
	text += tail
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
	alerts, err := n.Store.PendingAlerts(ctx, store.Everything)
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
			// SECURITY: identifiers, names and summaries come from sources and
			// SBOMs; chattext keeps them from pinging a channel or hiding a link.
			fmt.Fprintf(&b, "- **%s** (%s) — %s", chattext.Text(a.VulnID), reason,
				chattext.Text(strings.TrimSpace(a.AssetName+" "+a.AssetVersion)))
			if a.Summary != "" {
				fmt.Fprintf(&b, " : %s", chattext.Text(clip.Bytes(a.Summary, 140)))
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
	case a.Status == "exploitable":
		parts = append(parts, "jugée exploitable")
	case a.EPSS >= store.LikelyEPSS:
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
			n.Log.Warn("notification failed", "channel", h.Name, "err", sendErr)
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
	var payload any
	switch h.Kind {
	case "generic":
		payload = m.Event
	case "teams":
		payload = teamsCard(m.Text)
	default:
		// Slack and Mattermost accept a Markdown "text" field on incoming webhooks.
		payload = map[string]string{"text": clip.Bytes(m.Text, maxText)}
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
		return netsafe.WithoutURL(err) // the URL holds the webhook secret
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // also drains for connection reuse
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return refusal(h, resp.StatusCode, reply)
	}
	return nil
}

// SendTest sends a short message to a channel, enabled or not, and records the
// result, to check its settings without waiting for an alert.
func (n *Notifier) SendTest(ctx context.Context, h store.Webhook) error {
	sendErr := n.send(ctx, h, message{
		Subject: "[Vigil] Test du canal",
		Text:    "**Vigil** : message de test du canal « " + chattext.Text(h.Name) + " ».",
		Event:   map[string]any{"event": "test"},
	})
	if err := n.Store.RecordWebhookResult(ctx, h.ID, sendErr); err != nil {
		return err
	}
	return sendErr
}

// teamsCard is a message as the workflows of Teams expect it: an Adaptive Card.
// The incoming webhooks of the former connectors take it too.
func teamsCard(text string) map[string]any {
	return map[string]any{"type": "message", "attachments": []map[string]any{{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"content": map[string]any{
			"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
			"type":    "AdaptiveCard",
			"version": "1.4",
			"msteams": map[string]string{"width": "Full"},
			"body":    []map[string]any{{"type": "TextBlock", "text": clip.Bytes(text, maxTeamsText), "wrap": true}},
		},
	}}}
}

// refusal says why a channel refused a message: its status, the reason it gives
// and, for Teams, what to change: it answers 401 without a word when the
// workflow does not accept anonymous calls or its address is no longer valid.
func refusal(h store.Webhook, status int, reply []byte) error {
	msg := fmt.Sprintf("réponse HTTP %d", status)
	if reason := replyReason(reply); reason != "" {
		msg += " (" + reason + ")"
	}
	if h.Kind == "teams" && status == http.StatusUnauthorized {
		msg += " : dans le workflow Teams, réglez « Qui peut déclencher le flux » sur « Tout le monde », puis copiez sa nouvelle URL" +
			" (les adresses logic.azure.com ne sont plus valides)"
	}
	return errors.New(msg)
}

// replyReason extracts the reason of a refusal: the code and message of a JSON
// answer, or a short plain text. SECURITY: anything quoting an address is left
// out, as it could hold the secret of the webhook.
func replyReason(reply []byte) string {
	var doc struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	text := strings.TrimSpace(string(reply))
	if json.Unmarshal(reply, &doc) == nil {
		text = strings.TrimSpace(cmp.Or(doc.Error.Code, doc.Code) + " " + cmp.Or(doc.Error.Message, doc.Message))
	}
	if text == "" || strings.ContainsAny(text, "<>\n") || strings.Contains(text, "://") || strings.Contains(text, "sig=") {
		return ""
	}
	return clip.Bytes(text, 200)
}
