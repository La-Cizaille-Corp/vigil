package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Webhook is a chat or HTTP endpoint receiving digests.
type Webhook struct {
	ID        int64
	Name      string
	Kind      string
	URL       string // secret: never displayed in full
	Enabled   bool
	LastError string
	CreatedAt time.Time
	Digests   bool   // receives the periodic digests
	Alerts    string // immediate alerts: "" none, "priority" or "severe"
}

// AlertLevels are the immediate alert settings of a channel, with the lowest
// alert class each one receives.
var AlertLevels = map[string]int{"priority": AlertPriority, "severe": AlertSevere}

// selectWebhook reads the columns of a Webhook (see scanWebhook).
const selectWebhook = `SELECT id, name, kind, url, enabled, last_error, created_at, digests, alerts FROM webhooks `

// scanWebhook reads a row of selectWebhook; no row is ErrNotFound.
func scanWebhook(row scanner) (Webhook, error) {
	var w Webhook
	var created string
	err := row.Scan(&w.ID, &w.Name, &w.Kind, &w.URL, &w.Enabled, &w.LastError, &created, &w.Digests, &w.Alerts)
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	w.CreatedAt = parseTime(created)
	return w, err
}

// ListWebhooks returns every webhook.
func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	return collect(ctx, s.q(ctx), "list webhooks", scanWebhook, selectWebhook+`ORDER BY name COLLATE NOCASE`)
}

// Webhook returns one webhook, ErrNotFound if none has this id.
func (s *Store) Webhook(ctx context.Context, id int64) (Webhook, error) {
	w, err := scanWebhook(s.q(ctx).QueryRowContext(ctx, selectWebhook+`WHERE id = ?`, id))
	if err != nil {
		return w, fmt.Errorf("webhook %d: %w", id, err)
	}
	return w, nil
}

// CreateWebhook adds a webhook.
func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (int64, error) {
	res, err := s.q(ctx).ExecContext(ctx,
		`INSERT INTO webhooks (name, kind, url, enabled, digests, alerts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		w.Name, w.Kind, w.URL, w.Enabled, w.Digests, w.Alerts, now())
	if err != nil {
		return 0, fmt.Errorf("create webhook: %w", err)
	}
	id, err := res.LastInsertId()
	return id, wrap("create webhook", err)
}

// DeleteWebhook removes a webhook.
func (s *Store) DeleteWebhook(ctx context.Context, id int64) error {
	return wrap("delete webhook", expectRow(s.q(ctx).ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)))
}

// RecordWebhookResult stores the last delivery error ("" on success).
func (s *Store) RecordWebhookResult(ctx context.Context, id int64, deliveryErr error) error {
	_, err := s.q(ctx).ExecContext(ctx, `UPDATE webhooks SET last_error = ? WHERE id = ?`, errText(deliveryErr), id)
	return wrap("record webhook result", err)
}

// SetWebhookDelivery chooses what a channel receives.
func (s *Store) SetWebhookDelivery(ctx context.Context, id int64, digests bool, alerts string) error {
	return wrap("set webhook delivery", expectRow(s.q(ctx).ExecContext(ctx, `UPDATE webhooks SET digests = ?, alerts = ? WHERE id = ?`, digests, alerts, id)))
}

// SetWebhookEnabled turns a webhook on or off.
func (s *Store) SetWebhookEnabled(ctx context.Context, id int64, enabled bool) error {
	return wrap("set webhook enabled", expectRow(s.q(ctx).ExecContext(ctx, `UPDATE webhooks SET enabled = ? WHERE id = ?`, enabled, id)))
}
