-- A channel restricted to a group receives the alerts and the digest of that
-- group only (A68). A group with channels cannot be deleted: they would then
-- receive the whole inventory. NULL = the whole inventory, as before.
ALTER TABLE webhooks ADD COLUMN group_id INTEGER
    REFERENCES asset_groups (id) ON DELETE RESTRICT;

-- The group a digest covers, NULL for the whole inventory: the digests of a
-- group go with it.
ALTER TABLE digests ADD COLUMN group_id INTEGER
    REFERENCES asset_groups (id) ON DELETE CASCADE;
