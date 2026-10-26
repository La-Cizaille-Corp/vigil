-- Exploitation signals on vulnerabilities.
ALTER TABLE vulnerabilities ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;    -- listed in CISA KEV
ALTER TABLE vulnerabilities ADD COLUMN kev_due TEXT NOT NULL DEFAULT '';  -- CISA remediation due date
ALTER TABLE vulnerabilities ADD COLUMN epss REAL NOT NULL DEFAULT -1;     -- FIRST EPSS probability, -1 = unknown

-- Assets imported from an SBOM are grouped by project.
ALTER TABLE assets ADD COLUMN project TEXT NOT NULL DEFAULT '';
CREATE INDEX assets_project ON assets (project);

-- Key/value settings (watched CTI sectors and countries...).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE cti_feeds (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    url          TEXT    NOT NULL UNIQUE,
    country      TEXT    NOT NULL DEFAULT '', -- ISO 3166 alpha-2 applied to every item
    sectors      TEXT    NOT NULL DEFAULT '', -- comma-separated, applied to every item
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_fetched TEXT    NOT NULL DEFAULT '',
    last_error   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE cti_items (
    id         INTEGER PRIMARY KEY,
    feed_id    INTEGER NOT NULL REFERENCES cti_feeds (id) ON DELETE CASCADE,
    guid       TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    link       TEXT    NOT NULL DEFAULT '',
    summary    TEXT    NOT NULL DEFAULT '',
    published  TEXT    NOT NULL,
    countries  TEXT    NOT NULL DEFAULT '', -- comma-separated, surrounded by commas for LIKE matching
    sectors    TEXT    NOT NULL DEFAULT '', -- idem
    created_at TEXT    NOT NULL,
    UNIQUE (feed_id, guid)
);
CREATE INDEX cti_items_published ON cti_items (published);

CREATE TABLE webhooks (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('slack', 'mattermost', 'teams', 'generic')),
    url        TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    last_error TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);

-- Default public feeds; they can be disabled or deleted from the UI.
INSERT INTO cti_feeds (name, url, country, sectors) VALUES
    ('CERT-FR – Alertes', 'https://www.cert.ssi.gouv.fr/alerte/feed/', 'FR', ''),
    ('CERT-FR – Avis', 'https://www.cert.ssi.gouv.fr/avis/feed/', 'FR', ''),
    ('CERT-FR – Menaces et incidents', 'https://www.cert.ssi.gouv.fr/cti/feed/', 'FR', ''),
    ('CISA – Advisories', 'https://www.cisa.gov/cybersecurity-advisories/all.xml', 'US', ''),
    ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/', '', ''),
    ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews', '', '');
