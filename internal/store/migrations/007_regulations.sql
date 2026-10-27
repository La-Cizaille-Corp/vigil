-- Regulatory watch: items and feeds can be tagged with regulations and
-- standards (NIS2, CRA, DORA, GDPR...), stored like countries: ",nis2,cra,".
ALTER TABLE cti_items ADD COLUMN regulations TEXT NOT NULL DEFAULT '';
ALTER TABLE cti_feeds ADD COLUMN regulations TEXT NOT NULL DEFAULT ''; -- applied to every item, comma-separated

-- Default regulatory sources (official, checked to publish RSS).
INSERT OR IGNORE INTO cti_feeds (name, url, country, sectors, regulations) VALUES
    ('Commission européenne – Stratégie numérique', 'https://digital-strategy.ec.europa.eu/en/rss.xml', 'EU', '', ''),
    ('CNIL – Actualités', 'https://www.cnil.fr/fr/rss.xml', 'FR', '', 'gdpr'),
    ('EDPB – Actualités', 'https://www.edpb.europa.eu/feed/news_en', 'EU', '', 'gdpr'),
    ('EBA – Actualités', 'https://www.eba.europa.eu/rss.xml', 'EU', 'finance', '');
