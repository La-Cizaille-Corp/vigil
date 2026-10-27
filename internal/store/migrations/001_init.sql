-- Initial schema. Timestamps are RFC 3339 strings in UTC.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at    TEXT    NOT NULL
);

-- Only the SHA-256 of the session token is stored, never the token itself.
CREATE TABLE sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);

CREATE TABLE assets (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('package', 'technology', 'product', 'os')),
    ecosystem   TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    purl        TEXT NOT NULL DEFAULT '',
    cpe         TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    owner       TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'manual',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE vulnerabilities (
    id         TEXT PRIMARY KEY,           -- OSV / GHSA / CVE identifier
    aliases    TEXT NOT NULL DEFAULT '[]', -- JSON array
    summary    TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',   -- label (CRITICAL, HIGH...) or CVSS vector
    published  TEXT NOT NULL DEFAULT '',
    modified   TEXT NOT NULL DEFAULT '',
    refs       TEXT NOT NULL DEFAULT '[]', -- JSON array of URLs
    raw        TEXT NOT NULL DEFAULT '{}', -- original record, kept for audit
    fetched_at TEXT NOT NULL
);

-- Statuses follow the CycloneDX / VEX analysis states.
CREATE TABLE findings (
    id            INTEGER PRIMARY KEY,
    asset_id      INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    vuln_id       TEXT    NOT NULL REFERENCES vulnerabilities (id),
    status        TEXT    NOT NULL DEFAULT 'in_triage'
                  CHECK (status IN ('in_triage', 'exploitable', 'resolved', 'false_positive', 'not_affected')),
    justification TEXT    NOT NULL DEFAULT '',
    comment       TEXT    NOT NULL DEFAULT '',
    auto_resolved INTEGER NOT NULL DEFAULT 0, -- 1 when closed because the source stopped reporting it
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    UNIQUE (asset_id, vuln_id)
);
CREATE INDEX findings_status ON findings (status);
CREATE INDEX findings_first_seen ON findings (first_seen);

CREATE TABLE finding_events (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL, -- NULL = system
    old_status TEXT    NOT NULL,
    new_status TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);

CREATE TABLE digests (
    id         INTEGER PRIMARY KEY,
    since      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    markdown   TEXT NOT NULL,
    html       TEXT NOT NULL
);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
