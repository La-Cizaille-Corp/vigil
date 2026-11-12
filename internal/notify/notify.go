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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/chattext"
	"github.com/La-Cizaille-Corp/vigil/internal/choice"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// Kinds of channel.
var Kinds = []choice.Option{
	{Value: "slack", Label: "Slack"},
	{Value: "mattermost", Label: "Mattermost"},
	{Value: "teams", Label: "Microsoft Teams"},
	{Value: "generic", Label: "JSON générique"},
	{Value: "email", Label: "E-mail"},
}

// AlertOptions are the immediate alerts a channel can receive, named by the
// levels of tracking.Levels they cover (A84).
var AlertOptions = []choice.Option{
	{Value: "", Label: "Aucune alerte immédiate"},
	{Value: "priority", Label: "Urgentes seulement"},
	{Value: "severe", Label: "Urgentes et À planifier"},
}

const (
	// maxText keeps messages below the limits of chat platforms.
	maxText = 30000
	// maxTeamsText keeps a card below the 28 KB of a Teams message.
	maxTeamsText = 20000
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
	if w.Name == "" || !clip.Fits(w.Name, clip.MaxName) {
		return errors.New("nom invalide")
	}
	if !choice.Has(Kinds, w.Kind) {
		return errors.New("type de canal invalide")
	}
	if !choice.Has(AlertOptions, w.Alerts) {
		return errors.New("niveau d'alerte invalide")
	}
	if w.Kind == "email" {
		_, err := parseRecipients(w.URL)
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
	return netsafe.MaskURL(w.URL)
}

// message is one notification, rendered for each kind of channel.
type message struct {
	Subject string         // e-mail subject
	Text    string         // Markdown, for chats and e-mail
	Tail    string         // ends Text whatever the cut (fit): the link of a digest
	Event   map[string]any // payload of generic JSON webhooks
}

// truncated marks a text cut to fit a channel.
const truncated = "\n\n… (tronqué, voir le digest complet dans Vigil)"

// fit returns text and its tail within budget bytes, cut once for the
// channel that sends it: the cut is marked, the tail (the link of a digest)
// kept whole, and no character split. C4 of the 0.5.0 review: a digest cut
// for chats was cut again for Teams, which lost its note and its link.
func fit(text, tail string, budget int) string {
	if tail != "" {
		tail = "\n\n" + tail
	}
	if len(text)+len(tail) <= budget {
		return text + tail
	}
	return clip.Bytes(text, budget-len(tail)-len(truncated)-len("…")) + truncated + tail
}

// budget is the size of a message on a channel of kind, in bytes: a Teams
// card holds less than the text of a chat message.
func budget(kind string) int {
	if kind == "teams" {
		return maxTeamsText
	}
	return maxText
}

// link is the address of a page of the interface, or "" when the public
// address of the interface is unknown (-base-url).
func (n *Notifier) link(path string) string {
	if n.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(n.BaseURL, "/") + path
}

// SendDigest delivers a digest, with the link of its page, to the channels
// receiving digests of what it covers: the whole inventory, or its group (A68,
// store.Webhook.ReceivesDigest). It returns how many channels received it;
// failures are recorded per channel and joined.
func (n *Notifier) SendDigest(ctx context.Context, d store.Digest) (int, error) {
	link := n.link("/digests/" + strconv.FormatInt(d.ID, 10))
	day := d.CreatedAt
	if day.IsZero() {
		day = time.Now()
	}
	subject := "[Vigil] Digest de veille du " + fr.Date(day)
	if d.GroupName != "" {
		subject += " — " + d.GroupName
	}
	m := message{
		Subject: subject,
		Text:    d.Markdown,
		Tail:    link,
		Event: map[string]any{
			"event":      "digest",
			"digest_id":  d.ID,
			"created_at": d.CreatedAt,
			"since":      d.Since,
			"markdown":   d.Markdown,
			"link":       link,
			"group":      d.GroupName,
		},
	}
	return n.deliver(ctx, m, func(h store.Webhook) bool { return h.ReceivesDigest(d.Group) })
}

// SendAlerts notifies the open findings that became urgent since the last
// call (see store.PendingAlerts), then marks them notified, delivered or not:
// a failing channel shows its error in the settings, and the next digest
// lists the findings anyway. A channel limited to a group receives the
// alerts of that group only (A68); a finding is marked once for all, so that
// a channel added later does not receive the alerts already sent.
func (n *Notifier) SendAlerts(ctx context.Context) error {
	alerts, err := n.Store.PendingAlerts(ctx, store.Everything)
	if err != nil || len(alerts) == 0 {
		return err
	}
	hooks, err := n.Store.ListWebhooks(ctx)
	if err != nil {
		return err
	}
	// The scopes the channels receive: the whole inventory, and each group
	// that has an alert channel, with its own pending alerts.
	scopes := map[int64][]store.Alert{0: alerts}
	var errs []error
	for _, h := range hooks {
		if _, done := scopes[h.Group]; done || !h.Enabled || h.Alerts == "" {
			continue
		}
		mine, err := n.Store.PendingAlerts(ctx, store.InGroups(h.Group))
		if err != nil {
			return err
		}
		scopes[h.Group] = mine
	}
	for group, pending := range scopes {
		for level, class := range store.AlertLevels {
			selected := pending[:0:0]
			for _, a := range pending {
				if a.Class >= class {
					selected = append(selected, a)
				}
			}
			if len(selected) == 0 {
				continue
			}
			m := n.alertMessage(selected, group)
			_, err := n.deliver(ctx, m, func(h store.Webhook) bool { return h.Alerts == level && h.Group == group })
			errs = append(errs, err)
		}
	}
	if err := n.Store.MarkAlerted(ctx, alerts); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// alertMessage is the alert of findings of group, 0 for the whole inventory:
// the lists it leads to are those of the group, as in its digest (A87).
func (n *Notifier) alertMessage(alerts []store.Alert, group int64) message {
	byLevel := map[string]int{}
	for _, a := range alerts {
		byLevel[tracking.Level(a.Finding)]++
	}
	title := alertTitle(byLevel[tracking.LevelUrgent], byLevel[tracking.LevelPlan])
	var b strings.Builder
	fmt.Fprintf(&b, "**Vigil — %s**\n\n", title)
	var items []map[string]any
	for i, a := range alerts {
		link := n.link("/findings/" + strconv.FormatInt(a.ID, 10))
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
	if n.BaseURL != "" {
		// The lists of the levels the alert announces (A60), in its group.
		b.WriteString("\n")
		for _, l := range tracking.Levels[:2] {
			if byLevel[l.Value] > 0 {
				q := url.Values{"level": {l.Value}}
				if group != 0 {
					q.Set("group", strconv.FormatInt(group, 10))
				}
				fmt.Fprintf(&b, "%s : %s\n", l.Label, n.link("/findings?"+q.Encode()))
			}
		}
	}
	return message{
		Subject: "[Vigil] " + title,
		Text:    b.String(),
		Event:   map[string]any{"event": "alert", "findings": items},
	}
}

// alertTitle counts the findings of an alert by level, with the words of
// the levels: "3 vulnérabilités urgentes et 5 à planifier".
func alertTitle(urgent, plan int) string {
	noun := func(n int) string {
		if n > 1 {
			return strconv.Itoa(n) + " vulnérabilités"
		}
		return strconv.Itoa(n) + " vulnérabilité"
	}
	switch {
	case plan == 0 && urgent > 1:
		return noun(urgent) + " urgentes"
	case plan == 0:
		return noun(urgent) + " urgente"
	case urgent == 0:
		return noun(plan) + " à planifier"
	case urgent > 1:
		return noun(urgent) + " urgentes et " + strconv.Itoa(plan) + " à planifier"
	}
	return noun(urgent) + " urgente et " + strconv.Itoa(plan) + " à planifier"
}

// alertReason says why a finding is urgent or to plan, in French, with the
// words of its row in the lists (tracking.Reason).
func alertReason(a store.Alert) string {
	var parts []string
	if a.Severity != "" {
		parts = append(parts, strings.ToLower(tracking.SeverityLabel(a.Severity)))
	}
	if r := tracking.Reason(a.Finding); r != "" {
		parts = append(parts, r)
	}
	if a.Raised {
		parts = append(parts, "devenue plus urgente")
	}
	if len(parts) == 0 {
		return "gravité inconnue"
	}
	return strings.Join(parts, ", ")
}

// deliver sends m to every enabled channel accepted by want, and returns how
// many received it.
func (n *Notifier) deliver(ctx context.Context, m message, want func(store.Webhook) bool) (int, error) {
	hooks, err := n.Store.ListWebhooks(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	var errs []error
	for _, h := range hooks {
		if !h.Enabled || !want(h) {
			continue
		}
		sendErr := n.send(ctx, h, m)
		if sendErr != nil {
			n.Log.Warn("notification failed", "channel", h.Name, "err", sendErr)
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, sendErr))
		} else {
			sent++
		}
		if err := n.Store.RecordWebhookResult(ctx, h.ID, sendErr); err != nil {
			return sent, err
		}
	}
	return sent, errors.Join(errs...)
}

func (n *Notifier) send(ctx context.Context, h store.Webhook, m message) error {
	text := fit(m.Text, m.Tail, budget(h.Kind))
	if h.Kind == "email" {
		if n.Mail == nil {
			return errors.New("aucun serveur SMTP configuré (option -smtp-addr)")
		}
		to, err := parseRecipients(h.URL)
		if err != nil {
			return err
		}
		return n.Mail.Send(ctx, to, m.Subject, text)
	}
	var payload any
	switch h.Kind {
	case "generic":
		payload = m.Event
	case "teams":
		payload = teamsCard(text)
	default:
		// Slack and Mattermost accept a Markdown "text" field on incoming webhooks.
		payload = map[string]string{"text": text}
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

// teamsCard is a message as the workflows of Teams expect it: an Adaptive Card,
// its text already cut to the budget of Teams (fit). The incoming webhooks of
// the former connectors take it too.
func teamsCard(text string) map[string]any {
	return map[string]any{"type": "message", "attachments": []map[string]any{{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"content": map[string]any{
			"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
			"type":    "AdaptiveCard",
			"version": "1.4",
			"msteams": map[string]string{"width": "Full"},
			"body":    []map[string]any{{"type": "TextBlock", "text": text, "wrap": true}},
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
