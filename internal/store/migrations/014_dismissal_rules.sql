-- Rules setting aside the vulnerabilities of an asset by a text they hold.
CREATE TABLE dismissal_rules (
    id         INTEGER PRIMARY KEY,
    asset_id   INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    text       TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (asset_id, text)
);

-- The rule that set a finding aside, 0 for none: deleting the rule restores it.
ALTER TABLE findings ADD COLUMN dismissed_by INTEGER NOT NULL DEFAULT 0;
