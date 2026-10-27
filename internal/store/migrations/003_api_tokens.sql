-- API tokens let a CI pipeline push the SBOM of one project.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    project      TEXT    NOT NULL,              -- the only project the token may write
    token_hash   TEXT    NOT NULL UNIQUE,       -- SHA-256 of the secret, never the secret
    created_by   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL,
    last_used_at TEXT    NOT NULL DEFAULT ''
);
