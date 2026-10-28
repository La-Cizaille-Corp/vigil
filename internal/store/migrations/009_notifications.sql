-- Notification channels: webhooks become channels that may also be e-mail
-- recipients, and that receive digests, immediate alerts, or both. SQLite
-- cannot change a CHECK constraint: the table is rebuilt, rows kept as is.
CREATE TABLE webhooks_new (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('slack', 'mattermost', 'teams', 'generic', 'email')),
    url        TEXT    NOT NULL, -- webhook URL (secret), or comma-separated e-mail recipients
    enabled    INTEGER NOT NULL DEFAULT 1,
    last_error TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    digests    INTEGER NOT NULL DEFAULT 1,  -- receives the periodic digests
    alerts     TEXT    NOT NULL DEFAULT ''  -- immediate alerts: '' none, 'priority', 'severe'
);
INSERT INTO webhooks_new (id, name, kind, url, enabled, last_error, created_at)
    SELECT id, name, kind, url, enabled, last_error, created_at FROM webhooks;
DROP TABLE webhooks;
ALTER TABLE webhooks_new RENAME TO webhooks;

-- Highest alert class already notified for a finding (see store.AlertClass):
-- a finding is alerted once, and again only if it becomes more urgent.
ALTER TABLE findings ADD COLUMN alerted INTEGER NOT NULL DEFAULT 0;
-- Existing findings were already reported by digests: no flood of alerts
-- on the first sync after the upgrade.
UPDATE findings SET alerted = (
    SELECT CASE
        WHEN v.kev = 1 OR v.epss >= 0.1 THEN 2
        WHEN v.severity IN ('CRITICAL', 'HIGH') OR v.cvss >= 7 THEN 1
        ELSE 0 END
    FROM vulnerabilities v WHERE v.id = findings.vuln_id);

-- CVE identifiers cited by threat-intelligence news, to tell which news
-- concern the inventory. Filled for existing news by a Go step (store.go).
CREATE TABLE cti_mentions (
    item_id INTEGER NOT NULL REFERENCES cti_items (id) ON DELETE CASCADE,
    cve     TEXT    NOT NULL,
    PRIMARY KEY (item_id, cve)
);
CREATE INDEX cti_mentions_cve ON cti_mentions (cve);
