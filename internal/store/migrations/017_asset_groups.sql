-- Asset groups (A68). An asset belongs to a group when it carries one of the
-- group's tags or belongs to one of its projects (see store.Scope): nothing is
-- stored per asset. AUTOINCREMENT: the id of a deleted group is never given
-- again, so that nothing granted to it passes to a new group.
CREATE TABLE asset_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL
);

-- The rules of a group: exact values, compared with the tags and the project
-- of each asset.
CREATE TABLE group_rules (
    group_id INTEGER NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('tag', 'project')),
    value TEXT NOT NULL,
    PRIMARY KEY (group_id, kind, value)
);

-- What an account sees: 'all' every asset, 'groups' the assets of its groups
-- only, none without a group. Administrators see everything. The default
-- denies: an account created without an explicit choice sees nothing.
ALTER TABLE users ADD COLUMN access TEXT NOT NULL DEFAULT 'groups'
    CHECK (access IN ('all', 'groups'));

-- Every existing account keeps access to everything.
UPDATE users SET access = 'all';

CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES asset_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
