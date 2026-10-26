// Package notify delivers digests to chat webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// Kinds of webhook.
var Kinds = []inventory.Option{
	{Value: "slack", Label: "Slack"},
	{Value: "mattermost", Label: "Mattermost"},
	{Value: "teams", Label: "Microsoft Teams"},
	{Value: "generic", Label: "JSON générique"},
}

// maxText keeps messages below the limits of chat platforms.
const maxText = 30000

// Notifier sends digests to every enabled webhook.
type Notifier struct {
	Store     *store.Store
	HTTP      *http.Client // must come from netsafe.NewClient: URLs are user input
	UserAgent string
	Log       *slog.Logger
}

// ValidateWebhook checks a webhook before it is stored.
func ValidateWebhook(w store.Webhook) error {
	if w.Name == "" || len(w.Name) > 100 {
		return errors.New("nom invalide")
	}
	if inventory.Label(Kinds, w.Kind) == w.Kind {
		return errors.New("type de webhook invalide")
	}
	return netsafe.ValidateURL(w.URL)
}

// MaskURL hides the secret part of a webhook URL for display.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "…"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// SendDigest delivers a digest; failures are recorded per webhook and joined.
func (n *Notifier) SendDigest(ctx context.Context, d store.Digest, link string) error {
	hooks, err := n.Store.ListWebhooks(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hooks {
		if !h.Enabled {
			continue
		}
		sendErr := n.send(ctx, h, d, link)
		if sendErr != nil {
			n.Log.Warn("webhook en erreur", "webhook", h.Name, "err", sendErr)
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, sendErr))
		}
		if err := n.Store.RecordWebhookResult(ctx, h.ID, sendErr); err != nil {
			return err
		}
	}
	return errors.Join(errs...)
}

func (n *Notifier) send(ctx context.Context, h store.Webhook, d store.Digest, link string) error {
	text := d.Markdown
	if len(text) > maxText {
		text = text[:maxText] + "\n\n… (tronqué, voir le digest complet dans Vigil)"
	}
	if link != "" {
		text += "\n\n" + link
	}
	var payload any
	switch h.Kind {
	case "slack", "mattermost", "teams":
		// All three accept a Markdown "text" field on incoming webhooks.
		payload = map[string]string{"text": text}
	default:
		payload = map[string]any{
			"event":      "digest",
			"digest_id":  d.ID,
			"created_at": d.CreatedAt,
			"since":      d.Since,
			"markdown":   d.Markdown,
			"link":       link,
		}
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
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
