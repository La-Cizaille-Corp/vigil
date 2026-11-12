-- What the synchronisation keeps of a package too large for a batch answer of
-- OSV, read in full (A90): for each advisory reported, its id, date of
-- modification, date of publication and other identifiers, as JSON. A list
-- unchanged at OSV is not read again, a few advisories changed are read alone.
-- One row per OSV query (package, ecosystem, version): the assets that ask the
-- same share it. read_at is the last full read; a row is dropped a week after.
CREATE TABLE osv_lists (
    query TEXT PRIMARY KEY,
    read_at TEXT NOT NULL,
    advisories TEXT NOT NULL
);
