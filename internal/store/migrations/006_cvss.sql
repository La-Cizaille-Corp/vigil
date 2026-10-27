-- Numeric CVSS base score for filtering, -1 = unknown.
ALTER TABLE vulnerabilities ADD COLUMN cvss REAL NOT NULL DEFAULT -1;
CREATE INDEX vulnerabilities_cvss ON vulnerabilities (cvss);
-- Forget the "modified" marker so the next sync downloads every advisory
-- again and fills the score.
UPDATE vulnerabilities SET modified = '';
