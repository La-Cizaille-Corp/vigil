package store

import (
	"context"
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

// ListWebhooks returns every webhook.
func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, kind, url, enabled, last_error, created_at, digests, alerts FROM webhooks ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		var created string
		if err := rows.Scan(&w.ID, &w.Name, &w.Kind, &w.URL, &w.Enabled, &w.LastError, &created, &w.Digests, &w.Alerts); err != nil {
			return nil, err
		}
		w.CreatedAt = parseTime(created)
		out = append(out, w)
	}
	return out, rows.Err()
}

// CreateWebhook adds a webhook.
func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO webhooks (name, kind, url, enabled, digests, alerts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		w.Name, w.Kind, w.URL, w.Enabled, w.Digests, w.Alerts, now())
	if err != nil {
		return 0, fmt.Errorf("create webhook: %w", err)
	}
	return res.LastInsertId()
}

// DeleteWebhook removes a webhook.
func (s *Store) DeleteWebhook(ctx context.Context, id int64) error {
	return expectRow(s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id))
}

// RecordWebhookResult stores the last delivery error ("" on success).
func (s *Store) RecordWebhookResult(ctx context.Context, id int64, deliveryErr error) error {
	msg := ""
	if deliveryErr != nil {
		msg = truncateString(deliveryErr.Error(), 300)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE webhooks SET last_error = ? WHERE id = ?`, msg, id)
	return err
}

// SetWebhookDelivery chooses what a channel receives.
func (s *Store) SetWebhookDelivery(ctx context.Context, id int64, digests bool, alerts string) error {
	return expectRow(s.db.ExecContext(ctx, `UPDATE webhooks SET digests = ?, alerts = ? WHERE id = ?`, digests, alerts, id))
}

// SetWebhookEnabled turns a webhook on or off.
func (s *Store) SetWebhookEnabled(ctx context.Context, id int64, enabled bool) error {
	return expectRow(s.db.ExecContext(ctx, `UPDATE webhooks SET enabled = ? WHERE id = ?`, enabled, id))
}
