BEGIN TRANSACTION;
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    project      TEXT    NOT NULL,              -- the only project the token may write
    token_hash   TEXT    NOT NULL UNIQUE,       -- SHA-256 of the secret, never the secret
    created_by   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL,
    last_used_at TEXT    NOT NULL DEFAULT ''
);
INSERT INTO "api_tokens" VALUES(1,'CI boutique','boutique','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1,'2026-11-02T09:44:54Z','');
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
, project TEXT NOT NULL DEFAULT '', cpe_mode TEXT NOT NULL DEFAULT '', cpe_from TEXT NOT NULL DEFAULT '', track_since TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '', retired_at TEXT NOT NULL DEFAULT '', older_vulns INTEGER NOT NULL DEFAULT 0);
INSERT INTO "assets" VALUES(1,'requests','package','','2.31.0','pkg:pypi/requests@2.31.0','','medium','','','sbom','2026-11-02T09:44:37Z','2026-11-02T09:44:37Z','boutique','','','2026-07-05','','',4);
INSERT INTO "assets" VALUES(2,'lodash','package','','4.17.15','pkg:npm/lodash@4.17.15','','medium','','','sbom','2026-11-02T09:44:37Z','2026-11-02T09:44:37Z','boutique','','','2026-07-05','','',6);
INSERT INTO "assets" VALUES(3,'minimist','package','','1.2.5','pkg:npm/minimist@1.2.5','','medium','','','sbom','2026-11-02T09:44:37Z','2026-11-02T09:45:36Z','boutique','','','2026-07-05','','2026-11-02T09:45:36Z',1);
INSERT INTO "assets" VALUES(4,'log4j-core','package','','2.14.1','pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1','','medium','','','sbom','2026-11-02T09:44:37Z','2026-11-02T09:44:37Z','boutique','','','2026-07-05','','',6);
INSERT INTO "assets" VALUES(5,'jinja2','package','','3.1.2','pkg:pypi/jinja2@3.1.2','','medium','','','sbom','2026-11-02T09:44:37Z','2026-11-02T09:44:37Z','boutique','','','2026-07-05','','',5);
INSERT INTO "assets" VALUES(6,'Fortinet FortiOS','os','','7.2.4','','cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*','critical','Équipe réseau','','manual','2026-11-02T09:44:38Z','2026-11-02T09:44:38Z','','','','2026-07-01',',prod,réseau,','',0);
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
INSERT INTO "audit_log" VALUES(1,1,'setup','compte administrateur initial créé','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(2,1,'login','ip=127.0.0.1','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(3,1,'user_create','id=2 lecteur role=viewer','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(4,1,'user_create','id=3 depart role=analyst','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(5,1,'user_disable','id=3','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(6,NULL,'sbom_import','boutique (CLI): CycloneDX +5 =0 -0','2026-11-02T09:44:37Z');
INSERT INTO "audit_log" VALUES(7,1,'asset_create','6','2026-11-02T09:44:38Z');
INSERT INTO "audit_log" VALUES(8,1,'watch_update','FR,BE,health,nis2','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(9,1,'feed_create','Flux maison https://example.org/…','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(10,1,'feed_toggle','id=6 enabled=false','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(11,1,'sla_update','10,30,90,180','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(12,1,'webhook_create','https://hooks.slack.com/…','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(13,1,'api_token_create','CI boutique → boutique','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(14,1,'sync','manuel','2026-11-02T09:44:54Z');
INSERT INTO "audit_log" VALUES(15,NULL,'sbom_import','boutique (CLI): CycloneDX +0 =4 -1','2026-11-02T09:45:36Z');
CREATE TABLE cti_feeds (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    url          TEXT    NOT NULL UNIQUE,
    country      TEXT    NOT NULL DEFAULT '', -- ISO 3166 alpha-2 applied to every item
    sectors      TEXT    NOT NULL DEFAULT '', -- comma-separated, applied to every item
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_fetched TEXT    NOT NULL DEFAULT '',
    last_error   TEXT    NOT NULL DEFAULT ''
, regulations TEXT NOT NULL DEFAULT '');
INSERT INTO "cti_feeds" VALUES(1,'CERT-FR – Alertes','https://www.cert.ssi.gouv.fr/alerte/feed/','FR','',1,'2026-11-02T09:45:16Z','','');
INSERT INTO "cti_feeds" VALUES(2,'CERT-FR – Avis','https://www.cert.ssi.gouv.fr/avis/feed/','FR','',1,'2026-11-02T09:45:17Z','','');
INSERT INTO "cti_feeds" VALUES(3,'CERT-FR – Menaces et incidents','https://www.cert.ssi.gouv.fr/cti/feed/','FR','',1,'2026-11-02T09:45:17Z','','');
INSERT INTO "cti_feeds" VALUES(4,'CISA – Advisories','https://www.cisa.gov/cybersecurity-advisories/all.xml','US','',1,'2026-11-02T09:45:17Z','','');
INSERT INTO "cti_feeds" VALUES(5,'BleepingComputer','https://www.bleepingcomputer.com/feed/','','',1,'2026-11-02T09:45:16Z','','');
INSERT INTO "cti_feeds" VALUES(6,'The Hacker News','https://feeds.feedburner.com/TheHackersNews','','',0,'','','');
INSERT INTO "cti_feeds" VALUES(7,'Commission européenne – Stratégie numérique','https://digital-strategy.ec.europa.eu/en/rss.xml','EU','',1,'2026-11-02T09:45:18Z','','');
INSERT INTO "cti_feeds" VALUES(8,'CNIL – Actualités','https://www.cnil.fr/fr/rss.xml','FR','',1,'2026-11-02T09:45:18Z','','gdpr');
INSERT INTO "cti_feeds" VALUES(9,'EDPB – Actualités','https://www.edpb.europa.eu/feed/news_en','EU','',1,'2026-11-02T09:45:18Z','','gdpr');
INSERT INTO "cti_feeds" VALUES(10,'EBA – Actualités','https://www.eba.europa.eu/rss.xml','EU','finance',1,'2026-11-02T09:45:18Z','','');
INSERT INTO "cti_feeds" VALUES(11,'Flux maison','https://example.org/flux.xml','BE','',1,'2026-11-02T09:45:19Z','réponse HTTP 404','');
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
    created_at TEXT    NOT NULL, regulations TEXT NOT NULL DEFAULT '',
    UNIQUE (feed_id, guid)
);
INSERT INTO "cti_items" VALUES(1,5,'https://www.bleepingcomputer.com/news/security/ivanti-patches-two-more-connect-secure-zero-days-chained-in-attacks/','Ivanti patches two more Connect Secure zero-days chained in attacks','https://www.bleepingcomputer.com/news/security/ivanti-patches-two-more-connect-secure-zero-days-chained-in-attacks/','Ivanti released security updates to patch two more Connect Secure (ICS) remote access gateway flaws that have been chained in zero-day attacks since at least October 1. [...]','2026-11-02T09:33:26Z','',',manufacturing,','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(2,5,'https://www.bleepingcomputer.com/news/security/fbi-links-63-billion-binance-crypto-heist-to-north-korean-hackers/','FBI links $6.3 billion Binance crypto heist to North Korean hackers','https://www.bleepingcomputer.com/news/security/fbi-links-63-billion-binance-crypto-heist-to-north-korean-hackers/','The FBI has confirmed that North Korean state-sponsored hackers known as TraderTraitor were behind the $6.3 billion crypto-theft attack on Binance, making it the largest cryptocurrency heist on record. [...]','2026-11-01T19:57:53Z',',KP,US,','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(3,5,'https://www.bleepingcomputer.com/news/security/alpine-linux-rebuilds-gitlab-after-attempted-rce-attack/','Alpine Linux rebuilds GitLab after attempted RCE attack','https://www.bleepingcomputer.com/news/security/alpine-linux-rebuilds-gitlab-after-attempted-rce-attack/','Hackers attempted to exploit a critical GitLab vulnerability in Alpine Linux''s development infrastructure on October 20-21, prompting the open-source project to rebuild its GitLab server and reset all passwords over concerns of a possible compromise. [...]','2026-11-01T15:11:21Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(4,5,'https://www.bleepingcomputer.com/news/artificial-intelligence/openai-says-its-doubling-pro-usage-limits-and-bringing-work-features-to-chat/','OpenAI says it''s doubling Pro usage limits and bringing Work features to Chat','https://www.bleepingcomputer.com/news/artificial-intelligence/openai-says-its-doubling-pro-usage-limits-and-bringing-work-features-to-chat/','OpenAI has just confirmed that it''s rolling out ChatGPT Work capabilities directly into regular Chat, while also combining usage allowances across ChatGPT and Codex. [...]','2026-11-01T13:53:11Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(5,5,'https://www.bleepingcomputer.com/news/security/northflank-security-breach-leads-to-abuse-of-customers-ai-api-keys/','Northflank security breach leads to abuse of customers'' AI API keys','https://www.bleepingcomputer.com/news/security/northflank-security-breach-leads-to-abuse-of-customers-ai-api-keys/','Cloud application hosting platform Northflank is warning customers to rotate all credentials and secrets stored on its platform after a security breach led to unauthorized use of customers'' AI API keys. [...]','2026-10-31T18:01:12Z','',',digital,','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(6,5,'https://www.bleepingcomputer.com/news/security/new-android-sms-of-death-exploit-can-remotely-crash-unpatched-phones/','New Android SMS of Death exploit can remotely crash unpatched phones','https://www.bleepingcomputer.com/news/security/new-android-sms-of-death-exploit-can-remotely-crash-unpatched-phones/','A security researcher has released a proof-of-concept exploit for a recently patched Android vulnerability, dubbed "SMS of Death" and tracked as CVE-2026-58882, that lets attackers remotely disrupt cellular service or crash phones by sending a specially crafted text message. [...]','2026-10-31T15:35:11Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(7,5,'https://www.bleepingcomputer.com/news/security/reddit-to-lock-content-behind-logins-to-fight-scrapers/','Reddit to lock content behind logins to fight scrapers','https://www.bleepingcomputer.com/news/security/reddit-to-lock-content-behind-logins-to-fight-scrapers/','Reddit announced in a post by co-founder Steve Huffman that the site will gradually become a "logged-in service," offering limited access to visitors without accounts. [...]','2026-10-31T14:05:15Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(8,5,'https://www.bleepingcomputer.com/news/security/from-beginner-to-bug-hunter-learning-cybersecurity-in-the-ai-era/','From Beginner to Bug Hunter: Learning Cybersecurity in the AI Era.','https://www.bleepingcomputer.com/news/security/from-beginner-to-bug-hunter-learning-cybersecurity-in-the-ai-era/','AI-generated vulnerability reports are overwhelming some bug bounty programs, making it harder for aspiring security researchers to know where to start. TryHackMe explains how beginners can build practical cybersecurity skills, use AI responsibly, and produce reproducible findings that stand up to scrutiny. [...]','2026-10-31T13:10:19Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(9,5,'https://www.bleepingcomputer.com/news/security/chainalysis-discloses-data-breach-from-offensive-agentic-techniques/','Chainalysis discloses data breach from "offensive agentic techniques"','https://www.bleepingcomputer.com/news/security/chainalysis-discloses-data-breach-from-offensive-agentic-techniques/','Blockchain analytics firm Chainalysis disclosed a data breach after attackers used "offensive agentic techniques" to access internal systems and tools, exposing customer names, email addresses, user IDs, and organizational roles. [...]','2026-10-31T12:50:09Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(10,5,'https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/','Critical Linux kernel flaw allows remote root attacks on MPTCP servers','https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/','Security researchers at Anthropic have developed an exploit for a critical Linux kernel vulnerability that allows unauthenticated attackers to remotely execute commands as root on servers running Multipath TCP (MPTCP) listeners. [...]','2026-10-30T21:09:46Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(11,5,'https://www.bleepingcomputer.com/news/security/trezor-warns-of-suspected-crypto-theft-implant-in-hardware-wallet/','Trezor warns of suspected crypto-theft implant in hardware wallet','https://www.bleepingcomputer.com/news/security/trezor-warns-of-suspected-crypto-theft-implant-in-hardware-wallet/','Hardware wallet device maker Trezor has received credible reports about a suspected hardware crypto-theft implant in a Trezor Safe 5 sold by its reseller CryptoBilis in Southeast Asia. [...]','2026-10-30T15:58:20Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(12,5,'https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/','Malicious Claude Code extension on Cursor planted SSH backdoors','https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/','A malicious version of Anthropic''s Claude Code VS Code extension was distributed through Cursor''s extension marketplace for approximately 11 hours on October 29, exposing up to 5,000 developers to malware designed to install persistent SSH backdoors. [...]','2026-10-30T14:36:54Z','','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(16,1,'https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-005/','[Màj] Vulnérabilité dans Microsoft Exchange Server (15 mai 2026)','https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-005/','[Mise à jour du 11 juin 2026] Le 9 juin 2026, Microsoft a publié des versions correctives. [Publication initiale] Le 14 mai 2026, Microsoft a publié un avis de sécurité concernant la vulnérabilité CVE-2026-42897 affectant Exchange Server. Elle permet à un attaquant non authentifié de provoquer...','2026-05-15T00:00:00Z',',FR,','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(17,1,'https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-006/','Multiples vulnérabilités dans Sonicwall Secure Mobile Access (15 juillet 2026)','https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-006/','Le 14 juillet 2026, Sonicwall a publié un avis de sécurité concernant deux vulnérabilités affectant les Secure Mobile Access (SMA) 1000. La vulnérabilité critique CVE-2026-15409 permet une falsification de requêtes côté serveur (SSRF) de la part d''un attaquant non authentifié. La vulnérabilité...','2026-07-15T00:00:00Z',',FR,','','2026-11-02T09:45:16Z','');
INSERT INTO "cti_items" VALUES(18,1,'https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-007/','Multiples vulnérabilités dans WordPress (20 juillet 2026)','https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-007/','Le 17 juillet 2026, WordPress a publié un correctif pour deux vulnérabilités : CVE-2026-60137 : une injection SQL (SQLi) ; CVE-2026-63030 : celle-ci permet un contournement de la politique de sécurité. Un attaquant peut exploiter ces deux vulnérabilités, de manière combinée, pour obtenir une...','2026-07-20T00:00:00Z',',FR,','','2026-11-02T09:45:16Z','');
CREATE TABLE cti_mentions (
    item_id INTEGER NOT NULL REFERENCES cti_items (id) ON DELETE CASCADE,
    cve     TEXT    NOT NULL,
    PRIMARY KEY (item_id, cve)
);
INSERT INTO "cti_mentions" VALUES(6,'CVE-2026-58882');
INSERT INTO "cti_mentions" VALUES(16,'CVE-2026-42897');
INSERT INTO "cti_mentions" VALUES(17,'CVE-2026-15409');
INSERT INTO "cti_mentions" VALUES(18,'CVE-2026-60137');
INSERT INTO "cti_mentions" VALUES(18,'CVE-2026-63030');
CREATE TABLE digests (
    id         INTEGER PRIMARY KEY,
    since      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    markdown   TEXT NOT NULL,
    html       TEXT NOT NULL
);
INSERT INTO "digests" VALUES(1,'2026-10-26T09:45:36Z','2026-11-02T09:45:36Z','# Digest de veille sécurité

Généré le 02/11/2026 10:45 — période depuis le 26/10/2026 10:45.

## Nouvelles vulnérabilités (25)

| Éditeur | Critiques | Hautes | Moyennes | Basses | Inconnues | Total | Exploitées (KEV) |
|---|--:|--:|--:|--:|--:|--:|--:|
| Fortinet | 5 | 1 | 8 | 2 | 0 | 16 | 8 |
| org.apache.logging.log4j | 2 | 0 | 0 | 0 | 0 | 2 | 2 |
| Paquets PyPI | 0 | 2 | 4 | 0 | 1 | 7 | 0 |
| **Total** | **7** | **3** | **12** | **2** | **1** | **25** | **10** |

### Fortinet (16) — 5 critiques, 1 haute, 8 moyennes, 2 basses, dont 8 exploitées

| Sévérité | Vulnérabilité | Actif | Statut | Résumé |
|---|---|---|---|---|
| **EXPLOITÉE (KEV)** Critique · CVSS 9.8 · EPSS 86.6 % | CVE-2026-24858 | Fortinet FortiOS 7.2.4 | À analyser | An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7… |
| **EXPLOITÉE (KEV)** Critique · CVSS 9.8 · EPSS 85.7 % | CVE-2023-27997 | Fortinet FortiOS 7.2.4 | À analyser | A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all v… |
| **EXPLOITÉE (KEV)** Critique · CVSS 9.8 · EPSS 84.6 % | CVE-2024-21762 | Fortinet FortiOS 7.2.4 | À analyser | A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0… |
| **EXPLOITÉE (KEV)** Critique · CVSS 9.8 · EPSS 68.3 % | CVE-2025-59718 | Fortinet FortiOS 7.2.4 | À analyser | A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiPr… |
| **EXPLOITÉE (KEV)** Critique · CVSS 9.8 · EPSS 61.7 % | CVE-2024-23113 | Fortinet FortiOS 7.2.4 | À analyser | A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitch… |
| **EXPLOITÉE (KEV)** Haute · CVSS 8.1 · EPSS 3.7 % | CVE-2025-25249 | Fortinet FortiOS 7.2.4 | À analyser | A heap-based buffer overflow vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiOS 6.4 all versions, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows attacker to exe… |
| **EXPLOITÉE (KEV)** Moyenne · CVSS 6.0 · EPSS 1.3 % | CVE-2025-61624 | Fortinet FortiOS 7.2.4 | À analyser | An Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'') [CWE-22] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.7.0, FortiPAM 1.6 all versions, Fort… |
| **EXPLOITÉE (KEV)** Moyenne · CVSS 5.9 · EPSS 29.5 % | CVE-2025-68686 | Fortinet FortiOS 7.2.4 | À analyser | An Exposure of Sensitive Information to an Unauthorized Actor vulnerability [CWE-200] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.1, FortiOS 7.4.0 through 7.4.6, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow a remote unauthenticated attacker to bypass… |
| Moyenne · CVSS 6.6 · EPSS 0.7 % | CVE-2026-59837 | Fortinet FortiOS 7.2.4 | À analyser | A stack-based buffer overflow vulnerability in Fortinet FortiOS 7.4.0 through 7.4.1, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0 through 1.8.2, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions,… |
| Moyenne · CVSS 6.1 · EPSS 0.4 % | CVE-2026-23573 | Fortinet FortiOS 7.2.4 | À analyser | An Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'') vulnerability [CWE-79] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiPAM 1.8.0, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5… |
| Moyenne · CVSS 5.5 · EPSS 0.3 % | CVE-2026-59839 | Fortinet FortiOS 7.2.4 | À analyser | A improper limitation of a pathname to a restricted directory (''path traversal'') vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0, FortiPAM 1.7.0 through 1.7.2, FortiPAM 1.… |
| Moyenne · CVSS 5.3 · EPSS 0.6 % | CVE-2026-71408 | Fortinet FortiOS 7.2.4 | À analyser | A allocation of resources without limits or throttling vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an unauthenticated attacker to perform a slow HTTP DoS attack on the web inte… |
| Moyenne · CVSS 4.3 · EPSS 0.4 % | CVE-2025-43892 | Fortinet FortiOS 7.2.4 | Non affecté | A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an authenticated remote attacker to return a portion of device memory in the redirect response via submitting … |
| Moyenne · CVSS 4.3 · EPSS 0.3 % | CVE-2026-59840 | Fortinet FortiOS 7.2.4 | À analyser | A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiProxy 7.6.0 through 7.6.5, FortiProxy 7.4.0 through 7.4.13, FortiProxy 7.2 all versions, FortiProxy 7.0 all versio… |
| Basse · CVSS 3.4 · EPSS 0.3 % | CVE-2025-62675 | Fortinet FortiOS 7.2.4 | Non affecté | An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all … |
| Basse · CVSS 3.1 · EPSS 0.4 % | CVE-2025-62826 | Fortinet FortiOS 7.2.4 | Non affecté | An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all … |

### org.apache.logging.log4j (2) — 2 critiques, dont 2 exploitées

| Sévérité | Vulnérabilité | Actif | Statut | Résumé |
|---|---|---|---|---|
| **EXPLOITÉE (KEV)** Critique · CVSS 10.0 · EPSS 100.0 % | GHSA-jfh8-c2jp-5v3q (CVE-2021-44228) | log4j-core 2.14.1 | À analyser | Remote code injection in Log4j |
| **EXPLOITÉE (KEV)** Critique · CVSS 9.0 · EPSS 100.0 % | GHSA-7rjr-3q55-vv33 (CVE-2021-45046) | log4j-core 2.14.1 | À analyser | Incomplete fix for Apache Log4j vulnerability |

### Paquets PyPI (7) — 2 hautes, 4 moyennes, 1 de sévérité inconnue

| Sévérité | Vulnérabilité | Actif | Statut | Résumé |
|---|---|---|---|---|
| Haute · CVSS 8.8 · EPSS 0.3 % | PYSEC-2026-1472 (CVE-2024-56201, GHSA-gmj6-6f8f-6699) | jinja2 3.1.2 | À analyser | Jinja has a sandbox breakout through malicious filenames |
| Haute · CVSS 7.8 · EPSS 0.5 % | PYSEC-2026-1475 (CVE-2024-56326, GHSA-q2x7-8rv6-6q7h) | jinja2 3.1.2 | À analyser | Jinja has a sandbox breakout through indirect reference to format method |
| Moyenne · CVSS 5.6 · EPSS 0.3 % | PYSEC-2026-1873 (CVE-2024-35195, GHSA-9wx4-h78v-vm56) | requests 2.31.0 | À analyser | Requests `Session` object does not verify requests after making first request with verify=False |
| Moyenne · CVSS 5.4 · EPSS 1.0 % | PYSEC-2026-1474 (CVE-2024-34064, GHSA-h75v-3vvj-5mfj) | jinja2 3.1.2 | À analyser | Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter |
| Moyenne · CVSS 5.4 · EPSS 0.9 % | PYSEC-2026-1473 (CVE-2024-22195, GHSA-h5c8-rqwp-cp95) | jinja2 3.1.2 | À analyser | Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter |
| Moyenne · CVSS 5.3 · EPSS 1.0 % | PYSEC-2026-1872 (CVE-2024-47081, GHSA-9hjg-9r4m-mvj7) | requests 2.31.0 | À analyser | Requests vulnerable to .netrc credentials leak via malicious URLs |
| Inconnue · EPSS 0.5 % | PYSEC-2026-1471 (CVE-2025-27516, GHSA-cpwx-vrp4-4pq7) | jinja2 3.1.2 | À analyser | Jinja2 vulnerable to sandbox breakout through attr filter selecting format method |

## Vulnérabilités ouvertes (22)

| Éditeur | Critiques | Hautes | Moyennes | Basses | Inconnues | Total | Exploitées (KEV) |
|---|--:|--:|--:|--:|--:|--:|--:|
| Fortinet | 5 | 1 | 7 | 0 | 0 | 13 | 8 |
| org.apache.logging.log4j | 2 | 0 | 0 | 0 | 0 | 2 | 2 |
| Paquets PyPI | 0 | 2 | 4 | 0 | 1 | 7 | 0 |
| **Total** | **7** | **3** | **11** | **0** | **1** | **22** | **10** |

### Fortinet (13) — 5 critiques, 1 haute, 7 moyennes, dont 8 exploitées

- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.8) (EPSS 86.6 %) CVE-2026-24858 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.8) (EPSS 85.7 %) CVE-2023-27997 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.8) (EPSS 84.6 %) CVE-2024-21762 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.8) (EPSS 68.3 %) CVE-2025-59718 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.8) (EPSS 61.7 %) CVE-2024-23113 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Haute** (CVSS 8.1) (EPSS 3.7 %) CVE-2025-25249 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Moyenne** (CVSS 6.0) (EPSS 1.3 %) CVE-2025-61624 — Fortinet FortiOS 7.2.4 — À analyser
- **EXPLOITÉE (KEV)** **Moyenne** (CVSS 5.9) (EPSS 29.5 %) CVE-2025-68686 — Fortinet FortiOS 7.2.4 — À analyser
- **Moyenne** (CVSS 6.6) (EPSS 0.7 %) CVE-2026-59837 — Fortinet FortiOS 7.2.4 — À analyser
- **Moyenne** (CVSS 6.1) (EPSS 0.4 %) CVE-2026-23573 — Fortinet FortiOS 7.2.4 — À analyser
- **Moyenne** (CVSS 5.5) (EPSS 0.3 %) CVE-2026-59839 — Fortinet FortiOS 7.2.4 — À analyser
- **Moyenne** (CVSS 5.3) (EPSS 0.6 %) CVE-2026-71408 — Fortinet FortiOS 7.2.4 — À analyser
- **Moyenne** (CVSS 4.3) (EPSS 0.3 %) CVE-2026-59840 — Fortinet FortiOS 7.2.4 — À analyser

### org.apache.logging.log4j (2) — 2 critiques, dont 2 exploitées

- **EXPLOITÉE (KEV)** **Critique** (CVSS 10.0) (EPSS 100.0 %) GHSA-jfh8-c2jp-5v3q — log4j-core 2.14.1 — À analyser
- **EXPLOITÉE (KEV)** **Critique** (CVSS 9.0) (EPSS 100.0 %) GHSA-7rjr-3q55-vv33 — log4j-core 2.14.1 — À analyser

### Paquets PyPI (7) — 2 hautes, 4 moyennes, 1 de sévérité inconnue

- **Haute** (CVSS 8.8) (EPSS 0.3 %) PYSEC-2026-1472 — jinja2 3.1.2 — À analyser
- **Haute** (CVSS 7.8) (EPSS 0.5 %) PYSEC-2026-1475 — jinja2 3.1.2 — À analyser
- **Moyenne** (CVSS 5.6) (EPSS 0.3 %) PYSEC-2026-1873 — requests 2.31.0 — À analyser
- **Moyenne** (CVSS 5.4) (EPSS 1.0 %) PYSEC-2026-1474 — jinja2 3.1.2 — À analyser
- **Moyenne** (CVSS 5.4) (EPSS 0.9 %) PYSEC-2026-1473 — jinja2 3.1.2 — À analyser
- **Moyenne** (CVSS 5.3) (EPSS 1.0 %) PYSEC-2026-1872 — requests 2.31.0 — À analyser
- **Inconnue** (EPSS 0.5 %) PYSEC-2026-1471 — jinja2 3.1.2 — À analyser

## Synthèse par statut

- À analyser : 22
- Exploitable – à traiter : 0
- Corrigé : 0
- Non affecté : 3
- Faux positif : 0

## Veille menaces (1) — pays : France, Belgique ; secteurs : Santé

- [Vulnérabilités de produits du secteur santé : Retour d''expérience du CERT Santé et du CERT-FR (02 octobre 2026)](https://www.cert.cyber.gouv.fr/cti/CERTFR-2026-CTI-007/) — CERT-FR – Menaces et incidents, 02/10/2026 02:00 · France · Santé


## Veille réglementaire (0) — NIS2

Aucune actualité réglementaire sur la période.

','<section class="digest">
<p>Généré le 02/11/2026 10:45 — période depuis le 26/10/2026 10:45.</p>

<h2>Nouvelles vulnérabilités (25)</h2>


<table class="breakdown">
<thead><tr><th>Éditeur</th><th class="num">Critiques</th><th class="num">Hautes</th><th class="num">Moyennes</th><th class="num">Basses</th><th class="num">Inconnues</th><th class="num">Total</th><th class="num">Exploitées (KEV)</th></tr></thead>
<tbody>
<tr><td>Fortinet</td><td class="num">5</td><td class="num">1</td><td class="num">8</td><td class="num">2</td><td class="num"><span class="muted">0</span></td><td class="num">16</td><td class="num">8</td></tr>
<tr><td>org.apache.logging.log4j</td><td class="num">2</td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num">2</td><td class="num">2</td></tr>
<tr><td>Paquets PyPI</td><td class="num"><span class="muted">0</span></td><td class="num">2</td><td class="num">4</td><td class="num"><span class="muted">0</span></td><td class="num">1</td><td class="num">7</td><td class="num"><span class="muted">0</span></td></tr>
</tbody>
<tfoot><tr><th>Total</th><th class="num">7</th><th class="num">3</th><th class="num">12</th><th class="num">2</th><th class="num">1</th><th class="num">25</th><th class="num">10</th></tr></tfoot>
</table>


<h3>Fortinet (16)</h3>
<p class="muted">5 critiques, 1 haute, 8 moyennes, 2 basses, dont 8 exploitées</p>
<table>
<thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Actif</th><th>Statut</th><th>Résumé</th></tr></thead>
<tbody>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small><br><small>EPSS 86.6 %</small></td>
<td><a href="/findings/14">CVE-2026-24858</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small><br><small>EPSS 85.7 %</small></td>
<td><a href="/findings/9">CVE-2023-27997</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all v…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small><br><small>EPSS 84.6 %</small></td>
<td><a href="/findings/10">CVE-2024-21762</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small><br><small>EPSS 68.3 %</small></td>
<td><a href="/findings/12">CVE-2025-59718</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiPr…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small><br><small>EPSS 61.7 %</small></td>
<td><a href="/findings/11">CVE-2024-23113</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitch…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-HIGH">Haute</span> <small>CVSS 8.1</small><br><small>EPSS 3.7 %</small></td>
<td><a href="/findings/13">CVE-2025-25249</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A heap-based buffer overflow vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiOS 6.4 all versions, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows attacker to exe…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.0</small><br><small>EPSS 1.3 %</small></td>
<td><a href="/findings/16">CVE-2025-61624</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>An Improper Limitation of a Pathname to a Restricted Directory (&#39;Path Traversal&#39;) [CWE-22] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.7.0, FortiPAM 1.6 all versions, Fort…</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.9</small><br><small>EPSS 29.5 %</small></td>
<td><a href="/findings/15">CVE-2025-68686</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>An Exposure of Sensitive Information to an Unauthorized Actor vulnerability [CWE-200] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.1, FortiOS 7.4.0 through 7.4.6, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow a remote unauthenticated attacker to bypass…</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.6</small><br><small>EPSS 0.7 %</small></td>
<td><a href="/findings/5">CVE-2026-59837</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A stack-based buffer overflow vulnerability in Fortinet FortiOS 7.4.0 through 7.4.1, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0 through 1.8.2, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions,…</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.1</small><br><small>EPSS 0.4 %</small></td>
<td><a href="/findings/4">CVE-2026-23573</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>An Improper Neutralization of Input During Web Page Generation (&#39;Cross-site Scripting&#39;) vulnerability [CWE-79] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiPAM 1.8.0, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5…</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.5</small><br><small>EPSS 0.3 %</small></td>
<td><a href="/findings/6">CVE-2026-59839</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A improper limitation of a pathname to a restricted directory (&#39;path traversal&#39;) vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0, FortiPAM 1.7.0 through 1.7.2, FortiPAM 1.…</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.3</small><br><small>EPSS 0.6 %</small></td>
<td><a href="/findings/8">CVE-2026-71408</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A allocation of resources without limits or throttling vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an unauthenticated attacker to perform a slow HTTP DoS attack on the web inte…</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 4.3</small><br><small>EPSS 0.4 %</small></td>
<td><a href="/findings/1">CVE-2025-43892</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>Non affecté</td>
<td>A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an authenticated remote attacker to return a portion of device memory in the redirect response via submitting …</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 4.3</small><br><small>EPSS 0.3 %</small></td>
<td><a href="/findings/7">CVE-2026-59840</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>À analyser</td>
<td>A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiProxy 7.6.0 through 7.6.5, FortiProxy 7.4.0 through 7.4.13, FortiProxy 7.2 all versions, FortiProxy 7.0 all versio…</td>
</tr>

<tr>
<td><span class="sev sev-LOW">Basse</span> <small>CVSS 3.4</small><br><small>EPSS 0.3 %</small></td>
<td><a href="/findings/2">CVE-2025-62675</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>Non affecté</td>
<td>An Improper Neutralization of CRLF Sequences in HTTP Headers (&#39;HTTP Response Splitting&#39;) vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all …</td>
</tr>

<tr>
<td><span class="sev sev-LOW">Basse</span> <small>CVSS 3.1</small><br><small>EPSS 0.4 %</small></td>
<td><a href="/findings/3">CVE-2025-62826</a></td>
<td><a href="/assets/6">Fortinet FortiOS 7.2.4</a></td>
<td>Non affecté</td>
<td>An Improper Neutralization of CRLF Sequences in HTTP Headers (&#39;HTTP Response Splitting&#39;) vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all …</td>
</tr>

</tbody>
</table>

<h3>org.apache.logging.log4j (2)</h3>
<p class="muted">2 critiques, dont 2 exploitées</p>
<table>
<thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Actif</th><th>Statut</th><th>Résumé</th></tr></thead>
<tbody>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 10.0</small><br><small>EPSS 100.0 %</small></td>
<td><a href="/findings/23">GHSA-jfh8-c2jp-5v3q</a><br><small>CVE-2021-44228</small></td>
<td><a href="/assets/4">log4j-core 2.14.1</a></td>
<td>À analyser</td>
<td>Remote code injection in Log4j</td>
</tr>

<tr>
<td><span class="kev">Exploitée</span><br><span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.0</small><br><small>EPSS 100.0 %</small></td>
<td><a href="/findings/22">GHSA-7rjr-3q55-vv33</a><br><small>CVE-2021-45046</small></td>
<td><a href="/assets/4">log4j-core 2.14.1</a></td>
<td>À analyser</td>
<td>Incomplete fix for Apache Log4j vulnerability</td>
</tr>

</tbody>
</table>

<h3>Paquets PyPI (7)</h3>
<p class="muted">2 hautes, 4 moyennes, 1 de sévérité inconnue</p>
<table>
<thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Actif</th><th>Statut</th><th>Résumé</th></tr></thead>
<tbody>

<tr>
<td><span class="sev sev-HIGH">Haute</span> <small>CVSS 8.8</small><br><small>EPSS 0.3 %</small></td>
<td><a href="/findings/18">PYSEC-2026-1472</a><br><small>CVE-2024-56201, GHSA-gmj6-6f8f-6699</small></td>
<td><a href="/assets/5">jinja2 3.1.2</a></td>
<td>À analyser</td>
<td>Jinja has a sandbox breakout through malicious filenames</td>
</tr>

<tr>
<td><span class="sev sev-HIGH">Haute</span> <small>CVSS 7.8</small><br><small>EPSS 0.5 %</small></td>
<td><a href="/findings/21">PYSEC-2026-1475</a><br><small>CVE-2024-56326, GHSA-q2x7-8rv6-6q7h</small></td>
<td><a href="/assets/5">jinja2 3.1.2</a></td>
<td>À analyser</td>
<td>Jinja has a sandbox breakout through indirect reference to format method</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.6</small><br><small>EPSS 0.3 %</small></td>
<td><a href="/findings/25">PYSEC-2026-1873</a><br><small>CVE-2024-35195, GHSA-9wx4-h78v-vm56</small></td>
<td><a href="/assets/1">requests 2.31.0</a></td>
<td>À analyser</td>
<td>Requests `Session` object does not verify requests after making first request with verify=False</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.4</small><br><small>EPSS 1.0 %</small></td>
<td><a href="/findings/20">PYSEC-2026-1474</a><br><small>CVE-2024-34064, GHSA-h75v-3vvj-5mfj</small></td>
<td><a href="/assets/5">jinja2 3.1.2</a></td>
<td>À analyser</td>
<td>Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.4</small><br><small>EPSS 0.9 %</small></td>
<td><a href="/findings/19">PYSEC-2026-1473</a><br><small>CVE-2024-22195, GHSA-h5c8-rqwp-cp95</small></td>
<td><a href="/assets/5">jinja2 3.1.2</a></td>
<td>À analyser</td>
<td>Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter</td>
</tr>

<tr>
<td><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.3</small><br><small>EPSS 1.0 %</small></td>
<td><a href="/findings/24">PYSEC-2026-1872</a><br><small>CVE-2024-47081, GHSA-9hjg-9r4m-mvj7</small></td>
<td><a href="/assets/1">requests 2.31.0</a></td>
<td>À analyser</td>
<td>Requests vulnerable to .netrc credentials leak via malicious URLs</td>
</tr>

<tr>
<td><span class="sev sev-UNKNOWN">Inconnue</span><br><small>EPSS 0.5 %</small></td>
<td><a href="/findings/17">PYSEC-2026-1471</a><br><small>CVE-2025-27516, GHSA-cpwx-vrp4-4pq7</small></td>
<td><a href="/assets/5">jinja2 3.1.2</a></td>
<td>À analyser</td>
<td>Jinja2 vulnerable to sandbox breakout through attr filter selecting format method</td>
</tr>

</tbody>
</table>







<h2>Vulnérabilités ouvertes (22)</h2>


<table class="breakdown">
<thead><tr><th>Éditeur</th><th class="num">Critiques</th><th class="num">Hautes</th><th class="num">Moyennes</th><th class="num">Basses</th><th class="num">Inconnues</th><th class="num">Total</th><th class="num">Exploitées (KEV)</th></tr></thead>
<tbody>
<tr><td>Fortinet</td><td class="num">5</td><td class="num">1</td><td class="num">7</td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num">13</td><td class="num">8</td></tr>
<tr><td>org.apache.logging.log4j</td><td class="num">2</td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num"><span class="muted">0</span></td><td class="num">2</td><td class="num">2</td></tr>
<tr><td>Paquets PyPI</td><td class="num"><span class="muted">0</span></td><td class="num">2</td><td class="num">4</td><td class="num"><span class="muted">0</span></td><td class="num">1</td><td class="num">7</td><td class="num"><span class="muted">0</span></td></tr>
</tbody>
<tfoot><tr><th>Total</th><th class="num">7</th><th class="num">3</th><th class="num">11</th><th class="num">0</th><th class="num">1</th><th class="num">22</th><th class="num">10</th></tr></tfoot>
</table>


<h3>Fortinet (13)</h3>
<p class="muted">5 critiques, 1 haute, 7 moyennes, dont 8 exploitées</p>
<ul>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small> <small>EPSS 86.6 %</small> <a href="/findings/14">CVE-2026-24858</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small> <small>EPSS 85.7 %</small> <a href="/findings/9">CVE-2023-27997</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small> <small>EPSS 84.6 %</small> <a href="/findings/10">CVE-2024-21762</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small> <small>EPSS 68.3 %</small> <a href="/findings/12">CVE-2025-59718</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.8</small> <small>EPSS 61.7 %</small> <a href="/findings/11">CVE-2024-23113</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-HIGH">Haute</span> <small>CVSS 8.1</small> <small>EPSS 3.7 %</small> <a href="/findings/13">CVE-2025-25249</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.0</small> <small>EPSS 1.3 %</small> <a href="/findings/16">CVE-2025-61624</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.9</small> <small>EPSS 29.5 %</small> <a href="/findings/15">CVE-2025-68686</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.6</small> <small>EPSS 0.7 %</small> <a href="/findings/5">CVE-2026-59837</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 6.1</small> <small>EPSS 0.4 %</small> <a href="/findings/4">CVE-2026-23573</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.5</small> <small>EPSS 0.3 %</small> <a href="/findings/6">CVE-2026-59839</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.3</small> <small>EPSS 0.6 %</small> <a href="/findings/8">CVE-2026-71408</a> — Fortinet FortiOS 7.2.4 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 4.3</small> <small>EPSS 0.3 %</small> <a href="/findings/7">CVE-2026-59840</a> — Fortinet FortiOS 7.2.4 — À analyser</li>


</ul>

<h3>org.apache.logging.log4j (2)</h3>
<p class="muted">2 critiques, dont 2 exploitées</p>
<ul>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 10.0</small> <small>EPSS 100.0 %</small> <a href="/findings/23">GHSA-jfh8-c2jp-5v3q</a> — log4j-core 2.14.1 — À analyser</li>

<li><span class="kev">Exploitée</span> <span class="sev sev-CRITICAL">Critique</span> <small>CVSS 9.0</small> <small>EPSS 100.0 %</small> <a href="/findings/22">GHSA-7rjr-3q55-vv33</a> — log4j-core 2.14.1 — À analyser</li>


</ul>

<h3>Paquets PyPI (7)</h3>
<p class="muted">2 hautes, 4 moyennes, 1 de sévérité inconnue</p>
<ul>

<li><span class="sev sev-HIGH">Haute</span> <small>CVSS 8.8</small> <small>EPSS 0.3 %</small> <a href="/findings/18">PYSEC-2026-1472</a> — jinja2 3.1.2 — À analyser</li>

<li><span class="sev sev-HIGH">Haute</span> <small>CVSS 7.8</small> <small>EPSS 0.5 %</small> <a href="/findings/21">PYSEC-2026-1475</a> — jinja2 3.1.2 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.6</small> <small>EPSS 0.3 %</small> <a href="/findings/25">PYSEC-2026-1873</a> — requests 2.31.0 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.4</small> <small>EPSS 1.0 %</small> <a href="/findings/20">PYSEC-2026-1474</a> — jinja2 3.1.2 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.4</small> <small>EPSS 0.9 %</small> <a href="/findings/19">PYSEC-2026-1473</a> — jinja2 3.1.2 — À analyser</li>

<li><span class="sev sev-MEDIUM">Moyenne</span> <small>CVSS 5.3</small> <small>EPSS 1.0 %</small> <a href="/findings/24">PYSEC-2026-1872</a> — requests 2.31.0 — À analyser</li>

<li><span class="sev sev-UNKNOWN">Inconnue</span> <small>EPSS 0.5 %</small> <a href="/findings/17">PYSEC-2026-1471</a> — jinja2 3.1.2 — À analyser</li>


</ul>



<h2>Synthèse par statut</h2>
<ul>
<li>À analyser : 22</li><li>Exploitable – à traiter : 0</li><li>Corrigé : 0</li><li>Non affecté : 3</li><li>Faux positif : 0</li>
</ul>

<h2>Veille menaces (1)</h2>
<p class="muted">pays : France, Belgique ; secteurs : Santé</p>

<ul>

<li><a href="https://www.cert.cyber.gouv.fr/cti/CERTFR-2026-CTI-007/" rel="noopener noreferrer" target="_blank">Vulnérabilités de produits du secteur santé : Retour d&#39;expérience du CERT Santé et du CERT-FR (02 octobre 2026)</a>
<small class="muted">— CERT-FR – Menaces et incidents, 02/10/2026 02:00 · France · Santé</small></li>

</ul>


<h2>Veille réglementaire (0)</h2>
<p class="muted">NIS2</p>

<p>Aucune actualité réglementaire sur la période.</p>

</section>


');
CREATE TABLE finding_events (
    id         INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL, -- NULL = system
    old_status TEXT    NOT NULL,
    new_status TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
);
INSERT INTO "finding_events" VALUES(1,1,1,'in_triage','not_affected','Analyse « manuelle » : composant non chargé en production','2026-11-02T09:45:36Z');
INSERT INTO "finding_events" VALUES(2,2,1,'in_triage','not_affected','Analyse « manuelle » : composant non chargé en production','2026-11-02T09:45:36Z');
INSERT INTO "finding_events" VALUES(3,3,1,'in_triage','not_affected','Analyse « manuelle » : composant non chargé en production','2026-11-02T09:45:36Z');
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
    updated_at    TEXT    NOT NULL, alerted INTEGER NOT NULL DEFAULT 0,
    UNIQUE (asset_id, vuln_id)
);
INSERT INTO "findings" VALUES(1,6,'CVE-2025-43892','not_affected','code_not_present','Analyse « manuelle » : composant non chargé en production',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:45:36Z',0);
INSERT INTO "findings" VALUES(2,6,'CVE-2025-62675','not_affected','code_not_present','Analyse « manuelle » : composant non chargé en production',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:45:36Z',0);
INSERT INTO "findings" VALUES(3,6,'CVE-2025-62826','not_affected','code_not_present','Analyse « manuelle » : composant non chargé en production',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:45:36Z',0);
INSERT INTO "findings" VALUES(4,6,'CVE-2026-23573','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',0);
INSERT INTO "findings" VALUES(5,6,'CVE-2026-59837','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',0);
INSERT INTO "findings" VALUES(6,6,'CVE-2026-59839','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',0);
INSERT INTO "findings" VALUES(7,6,'CVE-2026-59840','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',0);
INSERT INTO "findings" VALUES(8,6,'CVE-2026-71408','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',0);
INSERT INTO "findings" VALUES(9,6,'CVE-2023-27997','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(10,6,'CVE-2024-21762','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(11,6,'CVE-2024-23113','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(12,6,'CVE-2025-59718','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(13,6,'CVE-2025-25249','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(14,6,'CVE-2026-24858','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(15,6,'CVE-2025-68686','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(16,6,'CVE-2025-61624','in_triage','','',0,'2026-11-02T09:44:38Z','2026-11-02T09:44:54Z','2026-11-02T09:44:38Z',2);
INSERT INTO "findings" VALUES(17,5,'PYSEC-2026-1471','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',0);
INSERT INTO "findings" VALUES(18,5,'PYSEC-2026-1472','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',1);
INSERT INTO "findings" VALUES(19,5,'PYSEC-2026-1473','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',0);
INSERT INTO "findings" VALUES(20,5,'PYSEC-2026-1474','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',0);
INSERT INTO "findings" VALUES(21,5,'PYSEC-2026-1475','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',1);
INSERT INTO "findings" VALUES(22,4,'GHSA-7rjr-3q55-vv33','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',2);
INSERT INTO "findings" VALUES(23,4,'GHSA-jfh8-c2jp-5v3q','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',2);
INSERT INTO "findings" VALUES(24,1,'PYSEC-2026-1872','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',0);
INSERT INTO "findings" VALUES(25,1,'PYSEC-2026-1873','in_triage','','',0,'2026-11-02T09:44:54Z','2026-11-02T09:44:54Z','2026-11-02T09:44:54Z',0);
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
INSERT INTO "schema_migrations" VALUES(1);
INSERT INTO "schema_migrations" VALUES(2);
INSERT INTO "schema_migrations" VALUES(3);
INSERT INTO "schema_migrations" VALUES(4);
INSERT INTO "schema_migrations" VALUES(5);
INSERT INTO "schema_migrations" VALUES(6);
INSERT INTO "schema_migrations" VALUES(7);
INSERT INTO "schema_migrations" VALUES(8);
INSERT INTO "schema_migrations" VALUES(9);
INSERT INTO "schema_migrations" VALUES(10);
INSERT INTO "schema_migrations" VALUES(11);
INSERT INTO "schema_migrations" VALUES(12);
CREATE TABLE sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO "settings" VALUES('cti_countries','FR,BE');
INSERT INTO "settings" VALUES('cti_regulations','nis2');
INSERT INTO "settings" VALUES('cti_sectors','health');
INSERT INTO "settings" VALUES('sla','10,30,90,180');
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at    TEXT    NOT NULL
, totp_secret    TEXT    NOT NULL DEFAULT '', totp_pending   TEXT    NOT NULL DEFAULT '', totp_last_step INTEGER NOT NULL DEFAULT 0, disabled_at TEXT NOT NULL DEFAULT '');
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=2$2l5hkB++Qx1DJfryFuc4pw$cFdxYLDP3kX6xQeJLASEgOWcsu+Jy5lM2vaYQ69crF8','admin','2026-11-02T09:44:37Z','','',0,'');
INSERT INTO "users" VALUES(2,'lecteur','$argon2id$v=19$m=65536,t=3,p=2$dQLpdp1V5pkOvEqe/3ZNow$hAYMDiXFzWuGBKIZEq+sNww7VvGHihAqmWug2/S3Dfc','viewer','2026-11-02T09:44:37Z','','',0,'');
INSERT INTO "users" VALUES(3,'depart','$argon2id$v=19$m=65536,t=3,p=2$8mvb0mpD8KRMMn7sxab0DA$+/C190CP2tiRA+QJ+23W+4FE1BcHRv4wtT7pUInDn0Y','analyst','2026-11-02T09:44:37Z','','',0,'2026-11-02T09:44:37Z');
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
, kev INTEGER NOT NULL DEFAULT 0, kev_due TEXT NOT NULL DEFAULT '', epss REAL NOT NULL DEFAULT -1, cvss REAL NOT NULL DEFAULT -1);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-43892','[]','A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an authenticated remote attacker to return a portion of device memory in the redirect response via submitting …','A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an authenticated remote attacker to return a portion of device memory in the redirect response via submitting a specially crafted request.','MEDIUM','2026-07-14T16:16:42.340','2026-09-29T14:10:00.117','["https://fortiguard.fortinet.com/psirt/#5944","https://cert-portal.siemens.com/productcert/html/ssa-864900.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00381,4.3);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-62675','[]','An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all …','An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all versions may allow an attacker in possession of a valid web filter override token to inject arbitrary headers via tricking a user into clicking on a crafted link.','LOW','2026-07-14T16:16:42.617','2026-09-29T15:10:00.193','["https://fortiguard.fortinet.com/psirt/FG-IR-26-152","https://cert-portal.siemens.com/productcert/html/ssa-864900.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00271,3.4);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-62826','[]','An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all …','An Improper Neutralization of CRLF Sequences in HTTP Headers (''HTTP Response Splitting'') vulnerability [CWE-113] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4 all versions, FortiProxy 7.2 all versions may allow an attacker able to intercept and modify a user''s captive portal authentication request to inject arbitrary headers via crafted HTTP requests.','LOW','2026-07-14T16:16:42.850','2026-09-29T15:10:00.193','["https://fortiguard.fortinet.com/psirt/FG-IR-26-153","https://cert-portal.siemens.com/productcert/html/ssa-864900.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00372,3.1);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-23573','[]','An Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'') vulnerability [CWE-79] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiPAM 1.8.0, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5…','An Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'') vulnerability [CWE-79] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiPAM 1.8.0, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions, FortiPAM 1.3 all versions, FortiPAM 1.2 all versions, FortiPAM 1.1 all versions, FortiPAM 1.0 all versions, FortiProxy 7.4.0 through 7.4.3, FortiProxy 7.2.0 through 7.2.9 may allow an authenticated remote user to execute code or commands via crafted requests.','MEDIUM','2026-07-14T16:16:51.823','2026-10-24T21:10:00.130','["https://fortiguard.fortinet.com/psirt/FG-IR-26-150","https://cert-portal.siemens.com/productcert/html/ssa-127084.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00385,6.1);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-59837','[]','A stack-based buffer overflow vulnerability in Fortinet FortiOS 7.4.0 through 7.4.1, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0 through 1.8.2, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions,…','A stack-based buffer overflow vulnerability in Fortinet FortiOS 7.4.0 through 7.4.1, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0 through 1.8.2, FortiPAM 1.7 all versions, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions, FortiPAM 1.3 all versions, FortiPAM 1.2 all versions, FortiPAM 1.1 all versions, FortiPAM 1.0 all versions, FortiProxy 7.4.0 through 7.4.13, FortiProxy 7.2 all versions may allow a privileged authenticated attacker who can bypass stack protection and ASLR to execute arbitrary code or commands via crafted HTTP requests.','MEDIUM','2026-07-14T16:17:02.853','2026-10-29T17:18:09.923','["https://fortiguard.fortinet.com/psirt/FG-IR-26-148","https://cert-portal.siemens.com/productcert/html/ssa-864900.html"]','{}','2026-11-02T09:45:13Z',0,'',0.0067,6.6);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-59839','[]','A improper limitation of a pathname to a restricted directory (''path traversal'') vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0, FortiPAM 1.7.0 through 1.7.2, FortiPAM 1.…','A improper limitation of a pathname to a restricted directory (''path traversal'') vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.8.0, FortiPAM 1.7.0 through 1.7.2, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions, FortiPAM 1.3 all versions, FortiPAM 1.2 all versions, FortiPAM 1.1 all versions, FortiPAM 1.0 all versions, FortiProxy 7.6.0 through 7.6.5, FortiProxy 7.4 through 7.4.13, FortiProxy 7.2 all versions, FortiProxy 7.0 all versions may allow attacker to execute unauthorized code or commands via <insert attack vector here>','MEDIUM','2026-07-14T16:17:03.047','2026-10-24T21:10:00.130','["https://fortiguard.fortinet.com/psirt/FG-IR-26-151","https://cert-portal.siemens.com/productcert/html/ssa-127084.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00251,5.5);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-59840','[]','A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiProxy 7.6.0 through 7.6.5, FortiProxy 7.4.0 through 7.4.13, FortiProxy 7.2 all versions, FortiProxy 7.0 all versio…','A buffer over-read vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiProxy 7.6.0 through 7.6.5, FortiProxy 7.4.0 through 7.4.13, FortiProxy 7.2 all versions, FortiProxy 7.0 all versions may allow attacker to information disclosure via <insert attack vector here>','MEDIUM','2026-07-14T16:17:03.297','2026-10-24T21:10:00.130','["https://fortiguard.fortinet.com/psirt/FG-IR-26-154","https://cert-portal.siemens.com/productcert/html/ssa-864900.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00313,4.3);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-71408','[]','A allocation of resources without limits or throttling vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an unauthenticated attacker to perform a slow HTTP DoS attack on the web inte…','A allocation of resources without limits or throttling vulnerability in Fortinet FortiOS 7.6.0 through 7.6.6, FortiOS 7.4 all versions, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow an unauthenticated attacker to perform a slow HTTP DoS attack on the web interface via crafted HTTP requests.','MEDIUM','2026-08-12T13:17:25.677','2026-10-29T17:18:10.297','["https://fortiguard.fortinet.com/psirt/FG-IR-26-162","https://cert-portal.siemens.com/productcert/html/ssa-127084.html"]','{}','2026-11-02T09:45:13Z',0,'',0.00624,5.3);
INSERT INTO "vulnerabilities" VALUES('CVE-2023-27997','[]','A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all v…','A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.','CRITICAL','2023-06-13T09:15:16.613','2026-07-31T04:16:43.707','["https://fortiguard.com/psirt/FG-IR-23-097","https://fortiguard.com/psirt/FG-IR-23-097","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-27997"]','{"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionStartIncluding":"1.1.0","versionEndIncluding":"1.1.6","matchCriteriaId":"E6BBF05F-4967-4A2E-A8F8-C2086097148B"},{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionStartIncluding":"1.2.0","versionEndIncluding":"1.2.13","matchCriteriaId":"33B84D9A-55E3-4146-A55A-ACB507E61B05"},{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0.0","versionEndIncluding":"2.0.12","matchCriteriaId":"7C1D5E6B-A23E-4A92-B53C-720AFEB1B951"},{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionStartIncluding":"7.0.0","versionEndIncluding":"7.0.9","matchCriteriaId":"DAC18F7E-5242-4F36-BB42-FEC33B3AC075"},{"vulnerable":true,"criteria":"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndIncluding":"7.2.3","matchCriteriaId":"3A99FF48-370E-4D2A-B5CC-889EA21AB213"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"6.0.0","versionEndIncluding":"6.0.16","matchCriteriaId":"8EA5512D-6EE5-4DF3-A960-C02394F25225"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"6.2.0","versionEndIncluding":"6.2.13","matchCriteriaId":"3CD57A5A-2B13-495A-8530-8F97E1720602"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"6.4.0","versionEndIncluding":"6.4.12","matchCriteriaId":"5E99B6E5-7EC3-406C-AFAC-A5E32DE266DF"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.0.0","versionEndIncluding":"7.0.11","matchCriteriaId":"C2573C90-BE6A-4D5D-A223-F09213318909"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndIncluding":"7.2.4","matchCriteriaId":"4AB643A8-B52F-4D54-B816-28A6401BAA25"}]}]},{"operator":"AND","nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"6.0.12","versionEndIncluding":"6.0.16","matchCriteriaId":"6D997493-24C2-4A78-9DF0-6438E9415A3C"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"6.2.9","versionEndIncluding":"6.2.13","matchCriteriaId":"0A0D0D55-1A51-454D-A8B1-D7100D453102"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.0.10:*:*:*:*:*:*:*","matchCriteriaId":"FA6AF1FA-A034-439A-876B-BFA1BE7DE15E"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.2.4:*:*:*:*:*:*:*","matchCriteriaId":"9694FC0C-408A-4892-ADD1-F36F4BBBD9EF"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.2.6:*:*:*:*:*:*:*","matchCriteriaId":"2B8A132F-601F-4129-BFCA-3A976A711D5A"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.2.7:*:*:*:*:*:*:*","matchCriteriaId":"90600B14-07C4-455D-9FC1-17034D91B987"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.4.2:*:*:*:*:*:*:*","matchCriteriaId":"B28478DA-8D10-4A8E-81EA-D3DF421E5089"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.4.6:*:*:*:*:*:*:*","matchCriteriaId":"C2F935F9-5B6A-47C2-8F65-7A1E8BB061FF"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.4.8:*:*:*:*:*:*:*","matchCriteriaId":"751D2FC7-482F-4C6B-95DB-244004A2738E"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.4.10:*:*:*:*:*:*:*","matchCriteriaId":"EEE44B20-6F00-4962-9929-5A5054BBA94C"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:6.4.12:*:*:*:*:*:*:*","matchCriteriaId":"EB2FF1DA-001B-4CA1-9F46-427D9C92CBC6"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:7.0.5:*:*:*:*:*:*:*","matchCriteriaId":"48D0E8CC-3815-4697-86D0-DC7F66E70520"},{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:7.0.10:*:*:*:*:*:*:*","matchCriteriaId":"78C6C937-4477-438D-A252-E4102D758120"}]},{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:h:fortinet:fortigate_6000:-:*:*:*:*:*:*:*","matchCriteriaId":"3BB410C9-CDD4-4068-97E0-6D83AE62B7F1"},{"vulnerable":false,"criteria":"cpe:2.3:h:fortinet:fortigate_7000:-:*:*:*:*:*:*:*","matchCriteriaId":"E0CBA773-10C1-410D-BB01-771F454ABEBA"}]}]}]}','2026-11-02T09:45:13Z',1,'2023-07-04',0.85689,9.8);
INSERT INTO "vulnerabilities" VALUES('CVE-2024-21762','[]','A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0…','A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0.0 through 7.0.14, FortiProxy 2.0.0 through 2.0.13, FortiProxy 01.02 all versions, FortiProxy 1.2 all versions, FortiProxy 01.01 all versions, FortiProxy 1.1 all versions, FortiProxy 01.00 all versions allows attacker to execute unauthorized code or commands via specifically crafted requests','CRITICAL','2024-02-09T09:15:08.087','2026-10-22T19:20:41.990','["https://fortiguard.com/psirt/FG-IR-24-015","https://fortiguard.com/psirt/FG-IR-24-015","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762"]','{}','2026-11-02T09:45:13Z',1,'2024-02-16',0.84589,9.8);
INSERT INTO "vulnerabilities" VALUES('CVE-2024-23113','[]','A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitch…','A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitchManager versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.3 allows attacker to execute unauthorized code or commands via specially crafted packets.','CRITICAL','2024-02-15T14:15:46.503','2026-06-17T07:12:03.503','["https://fortiguard.com/psirt/FG-IR-24-029","https://fortiguard.com/psirt/FG-IR-24-029","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-23113"]','{}','2026-11-02T09:45:13Z',1,'2024-10-30',0.61725,9.8);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-59718','[]','A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiPr…','A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiProxy 7.0.0 through 7.0.21, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.','CRITICAL','2025-12-09T18:15:54.983','2026-06-17T09:46:35.807','["https://fortiguard.fortinet.com/psirt/FG-IR-25-647","https://arcticwolf.com/resources/blog/arctic-wolf-observes-malicious-sso-logins-following-disclosure-cve-2025-59718-cve-2025-59719/","https://cert-portal.siemens.com/productcert/html/ssa-864900.html","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-59718"]','{}','2026-11-02T09:45:13Z',1,'2025-12-23',0.68293,9.8);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-25249','[]','A heap-based buffer overflow vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiOS 6.4 all versions, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows attacker to exe…','A heap-based buffer overflow vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiOS 6.4 all versions, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows attacker to execute unauthorized code or commands via specially crafted packets','HIGH','2026-01-13T17:15:56.910','2026-10-07T18:17:13.180','["https://fortiguard.fortinet.com/psirt/FG-IR-25-084","https://cert-portal.siemens.com/productcert/html/ssa-864900.html","https://socradar.io/blog/cve-2025-25249-pivotc2-fortigate-rat/","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-25249"]','{}','2026-11-02T09:45:13Z',1,'2026-09-12',0.03742,8.1);
INSERT INTO "vulnerabilities" VALUES('CVE-2026-24858','[]','An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7…','An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiNAC-F 7.6.3 through 7.6.5, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.','CRITICAL','2026-01-27T20:16:24.477','2026-06-17T10:23:43.040','["https://fortiguard.fortinet.com/psirt/FG-IR-26-060","https://cert-portal.siemens.com/productcert/html/ssa-975644.html","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-24858","https://www.fortinet.com/blog/psirt-blogs/analysis-of-sso-abuse-on-fortios"]','{}','2026-11-02T09:45:13Z',1,'2026-01-30',0.86592,9.8);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-68686','[]','An Exposure of Sensitive Information to an Unauthorized Actor vulnerability [CWE-200] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.1, FortiOS 7.4.0 through 7.4.6, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow a remote unauthenticated attacker to bypass…','An Exposure of Sensitive Information to an Unauthorized Actor vulnerability [CWE-200] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.1, FortiOS 7.4.0 through 7.4.6, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism observed in some post-exploit cases, via crafted HTTP requests. An attacker would need first to have compromised the product via another vulnerability, at filesystem level.','MEDIUM','2026-02-10T16:16:09.630','2026-07-28T05:17:04.113','["https://fortiguard.fortinet.com/psirt/FG-IR-25-934","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-68686"]','{}','2026-11-02T09:45:13Z',1,'2026-08-10',0.29499,5.9);
INSERT INTO "vulnerabilities" VALUES('CVE-2025-61624','[]','An Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'') [CWE-22] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.7.0, FortiPAM 1.6 all versions, Fort…','An Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'') [CWE-22] vulnerability in Fortinet FortiOS 7.6.0 through 7.6.4, FortiOS 7.4.0 through 7.4.9, FortiOS 7.2 all versions, FortiOS 7.0 all versions, FortiOS 6.4 all versions, FortiPAM 1.7.0, FortiPAM 1.6 all versions, FortiPAM 1.5 all versions, FortiPAM 1.4 all versions, FortiPAM 1.3 all versions, FortiPAM 1.2 all versions, FortiPAM 1.1 all versions, FortiPAM 1.0 all versions, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.11, FortiProxy 7.2 all versions, FortiProxy 7.0 all versions, FortiSwitchManager 7.2.0 through 7.2.7, FortiSwitchManager 7.0.0 through 7.0.6 may allow an authenticated attacker with admin profile and at least read-write permissions to write or delete arbitrary files via specific CLI commands.','MEDIUM','2026-04-14T16:16:31.300','2026-10-17T04:16:43.363','["https://fortiguard.fortinet.com/psirt/FG-IR-26-122","https://cert-portal.siemens.com/productcert/html/ssa-975644.html","https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/#post-188095-_guyq53ar8k05","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-61624"]','{}','2026-11-02T09:45:13Z',1,'2026-10-19',0.01343,6.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-cpwx-vrp4-4pq7','["CVE-2025-27516","PYSEC-2026-1471"]','Jinja2 vulnerable to sandbox breakout through attr filter selecting format method','An oversight in how the Jinja sandboxed environment interacts with the `|attr` filter allows an attacker that controls the content of a template to execute arbitrary Python code.

To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.

Jinja''s sandbox does catch calls to `str.format` and ensures they don''t escape the sandbox. However, it''s possible to use the `|attr` filter to get a reference to a string''s plain format method, bypassing the sandbox. After the fix, the `|attr` filter no longer bypasses the environment''s attribute lookup.','MEDIUM','2025-03-05T20:40:14Z','2026-09-10T03:49:48.526758681Z','["https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7","https://nvd.nist.gov/vuln/detail/CVE-2025-27516","https://github.com/pallets/jinja/commit/90457bbf33b8662926ae65cdde4c4c32e756e403","https://github.com/pallets/jinja","https://lists.debian.org/debian-lts-announce/2025/04/msg00022.html","https://lists.debian.org/debian-lts-announce/2025/04/msg00045.html"]','{}','2026-11-02T09:44:54Z',0,'',0.00507,-1.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-gmj6-6f8f-6699','["CVE-2024-56201","PYSEC-2026-1472"]','Jinja has a sandbox breakout through malicious filenames','A bug in the Jinja compiler allows an attacker that controls both the content and filename of a template to execute arbitrary Python code, regardless of if Jinja''s sandbox is used.

To exploit the vulnerability, an attacker needs to control both the filename and the contents of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates where the template author can also choose the template filename.','MEDIUM','2024-12-23T17:54:12Z','2026-09-10T03:50:56.152882717Z','["https://github.com/pallets/jinja/security/advisories/GHSA-gmj6-6f8f-6699","https://nvd.nist.gov/vuln/detail/CVE-2024-56201","https://github.com/pallets/jinja/issues/1792","https://github.com/pallets/jinja/commit/767b23617628419ae3709ccfb02f9602ae9fe51f","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.5"]','{}','2026-11-02T09:44:54Z',0,'',0.00307,8.8);
INSERT INTO "vulnerabilities" VALUES('GHSA-h5c8-rqwp-cp95','["CVE-2024-22195","PYSEC-2026-1473"]','Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter','The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted as a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. Note that accepting keys as user input is not common or a particularly intended use case of the `xmlattr` filter, and an application doing so should already be verifying what keys are provided regardless of this fix.','MEDIUM','2024-01-11T15:20:48Z','2026-09-10T03:50:00.236017440Z','["https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95","https://nvd.nist.gov/vuln/detail/CVE-2024-22195","https://github.com/pallets/jinja/commit/716795349a41d4983a9a4771f7d883c96ea17be7","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.3","https://lists.debian.org/debian-lts-announce/2024/01/msg00010.html","https://lists.debian.org/debian-lts-announce/2024/12/msg00009.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5XCWZD464AJJJUBOO7CMPXQ4ROBC6JX2","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DELCVUUYX75I5K4Q5WMJG4MUZJA6VAIP","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/O7YWRBX6JQCWC2XXCTZ55C7DPMGICCN3"]','{}','2026-11-02T09:44:55Z',0,'',0.00892,5.4);
INSERT INTO "vulnerabilities" VALUES('GHSA-h75v-3vvj-5mfj','["CVE-2024-34064","PYSEC-2026-1474"]','Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter','The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, `>`, or `=`, as each would then be interpreted as starting a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. The fix for the previous GHSA-h5c8-rqwp-cp95 CVE-2024-22195 only addressed spaces but not other characters.

Accepting keys as user input is now explicitly considered an unintended use case of the `xmlattr` filter, and code that does so without otherwise validating the input should be flagged as insecure, regardless of Jinja version. Accepting _values_ as user input continues to be safe.','MEDIUM','2024-05-06T14:20:59Z','2026-09-10T03:50:13.786450101Z','["https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj","https://nvd.nist.gov/vuln/detail/CVE-2024-34064","https://github.com/pallets/jinja/commit/0668239dc6b44ef38e7a6c9f91f312fd4ca581cb","https://github.com/pallets/jinja","https://lists.debian.org/debian-lts-announce/2024/12/msg00009.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/567XIGSZMABG6TSMYWD7MIYNJSUQQRUC","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GCLF44KY43BSVMTE6S53B4V5WP3FRRSE","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SSCBHIL6BYKR5NRCBXP4XMP2CEEKGFVS","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZALNWE3TXPPHVPSI3AZ5CTMSTAVN5UMS"]','{}','2026-11-02T09:44:55Z',0,'',0.00979,5.4);
INSERT INTO "vulnerabilities" VALUES('GHSA-q2x7-8rv6-6q7h','["CVE-2024-56326","PYSEC-2026-1475"]','Jinja has a sandbox breakout through indirect reference to format method','An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrary Python code.

To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.

Jinja''s sandbox does catch calls to `str.format` and ensures they don''t escape the sandbox. However, it''s possible to store a reference to a malicious string''s `format` method, then pass that to a filter that calls it. No such filters are built-in to Jinja, but could be present through custom filters in an application. After the fix, such indirect calls are also handled by the sandbox.','MEDIUM','2024-12-23T17:56:08Z','2026-09-10T03:50:21.662855250Z','["https://github.com/pallets/jinja/security/advisories/GHSA-q2x7-8rv6-6q7h","https://nvd.nist.gov/vuln/detail/CVE-2024-56326","https://github.com/pallets/jinja/commit/48b0687e05a5466a91cd5812d604fa37ad0943b4","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.5","https://lists.debian.org/debian-lts-announce/2025/04/msg00022.html"]','{}','2026-11-02T09:44:55Z',0,'',0.00522,7.8);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1471','["CVE-2025-27516","GHSA-cpwx-vrp4-4pq7"]','Jinja2 vulnerable to sandbox breakout through attr filter selecting format method','An oversight in how the Jinja sandboxed environment interacts with the `|attr` filter allows an attacker that controls the content of a template to execute arbitrary Python code.

To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.

Jinja''s sandbox does catch calls to `str.format` and ensures they don''t escape the sandbox. However, it''s possible to use the `|attr` filter to get a reference to a string''s plain format method, bypassing the sandbox. After the fix, the `|attr` filter no longer bypasses the environment''s attribute lookup.','','2026-07-07T14:34:50.446969Z','2026-07-07T17:46:43.358335981Z','["https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7","https://nvd.nist.gov/vuln/detail/CVE-2025-27516","https://github.com/pallets/jinja/commit/90457bbf33b8662926ae65cdde4c4c32e756e403","https://github.com/pallets/jinja","https://lists.debian.org/debian-lts-announce/2025/04/msg00022.html","https://lists.debian.org/debian-lts-announce/2025/04/msg00045.html","https://pypi.org/project/jinja2","https://github.com/advisories/GHSA-cpwx-vrp4-4pq7"]','{}','2026-11-02T09:44:55Z',0,'',0.00507,-1.0);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1472','["CVE-2024-56201","GHSA-gmj6-6f8f-6699"]','Jinja has a sandbox breakout through malicious filenames','A bug in the Jinja compiler allows an attacker that controls both the content and filename of a template to execute arbitrary Python code, regardless of if Jinja''s sandbox is used.

To exploit the vulnerability, an attacker needs to control both the filename and the contents of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates where the template author can also choose the template filename.','HIGH','2026-07-07T14:34:47.677447Z','2026-07-07T17:46:46.013371684Z','["https://github.com/pallets/jinja/security/advisories/GHSA-gmj6-6f8f-6699","https://nvd.nist.gov/vuln/detail/CVE-2024-56201","https://github.com/pallets/jinja/issues/1792","https://github.com/pallets/jinja/commit/767b23617628419ae3709ccfb02f9602ae9fe51f","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.5","https://pypi.org/project/jinja2","https://github.com/advisories/GHSA-gmj6-6f8f-6699"]','{}','2026-11-02T09:44:55Z',0,'',0.00307,8.8);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1473','["CVE-2024-22195","GHSA-h5c8-rqwp-cp95"]','Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter','The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted as a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. Note that accepting keys as user input is not common or a particularly intended use case of the `xmlattr` filter, and an application doing so should already be verifying what keys are provided regardless of this fix.','MEDIUM','2026-07-07T11:45:29.949639Z','2026-07-07T17:46:13.853151947Z','["https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95","https://nvd.nist.gov/vuln/detail/CVE-2024-22195","https://github.com/pallets/jinja/commit/716795349a41d4983a9a4771f7d883c96ea17be7","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.3","https://lists.debian.org/debian-lts-announce/2024/01/msg00010.html","https://lists.debian.org/debian-lts-announce/2024/12/msg00009.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5XCWZD464AJJJUBOO7CMPXQ4ROBC6JX2","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DELCVUUYX75I5K4Q5WMJG4MUZJA6VAIP","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/O7YWRBX6JQCWC2XXCTZ55C7DPMGICCN3","https://pypi.org/project/jinja2","https://github.com/advisories/GHSA-h5c8-rqwp-cp95"]','{}','2026-11-02T09:44:55Z',0,'',0.00892,5.4);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1474','["CVE-2024-34064","GHSA-h75v-3vvj-5mfj"]','Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter','The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, `>`, or `=`, as each would then be interpreted as starting a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. The fix for the previous GHSA-h5c8-rqwp-cp95 CVE-2024-22195 only addressed spaces but not other characters.

Accepting keys as user input is now explicitly considered an unintended use case of the `xmlattr` filter, and code that does so without otherwise validating the input should be flagged as insecure, regardless of Jinja version. Accepting _values_ as user input continues to be safe.','MEDIUM','2026-07-07T11:45:41.875280Z','2026-07-07T17:46:13.832160246Z','["https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj","https://nvd.nist.gov/vuln/detail/CVE-2024-34064","https://github.com/pallets/jinja/commit/0668239dc6b44ef38e7a6c9f91f312fd4ca581cb","https://github.com/pallets/jinja","https://lists.debian.org/debian-lts-announce/2024/12/msg00009.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/567XIGSZMABG6TSMYWD7MIYNJSUQQRUC","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GCLF44KY43BSVMTE6S53B4V5WP3FRRSE","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SSCBHIL6BYKR5NRCBXP4XMP2CEEKGFVS","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZALNWE3TXPPHVPSI3AZ5CTMSTAVN5UMS","https://pypi.org/project/jinja2","https://github.com/advisories/GHSA-h75v-3vvj-5mfj"]','{}','2026-11-02T09:44:56Z',0,'',0.00979,5.4);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1475','["CVE-2024-56326","GHSA-q2x7-8rv6-6q7h"]','Jinja has a sandbox breakout through indirect reference to format method','An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrary Python code.

To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.

Jinja''s sandbox does catch calls to `str.format` and ensures they don''t escape the sandbox. However, it''s possible to store a reference to a malicious string''s `format` method, then pass that to a filter that calls it. No such filters are built-in to Jinja, but could be present through custom filters in an application. After the fix, such indirect calls are also handled by the sandbox.','HIGH','2026-07-07T14:34:47.732576Z','2026-07-07T17:46:13.842466429Z','["https://github.com/pallets/jinja/security/advisories/GHSA-q2x7-8rv6-6q7h","https://nvd.nist.gov/vuln/detail/CVE-2024-56326","https://github.com/pallets/jinja/commit/48b0687e05a5466a91cd5812d604fa37ad0943b4","https://github.com/pallets/jinja","https://github.com/pallets/jinja/releases/tag/3.1.5","https://lists.debian.org/debian-lts-announce/2025/04/msg00022.html","https://pypi.org/project/jinja2","https://github.com/advisories/GHSA-q2x7-8rv6-6q7h"]','{}','2026-11-02T09:44:56Z',0,'',0.00522,7.8);
INSERT INTO "vulnerabilities" VALUES('GHSA-29mw-wpgm-hmr9','["CVE-2020-28500"]','Regular Expression Denial of Service (ReDoS) in lodash','All versions of package lodash prior to 4.17.21 are vulnerable to Regular Expression Denial of Service (ReDoS) via the `toNumber`, `trim` and `trimEnd` functions. 

Steps to reproduce (provided by reporter Liyuan Chen):
```js
var lo = require(''lodash'');

function build_blank(n) {
    var ret = "1"
    for (var i = 0; i < n; i++) {
        ret += " "
    }
    return ret + "1";
}
var s = build_blank(50000) var time0 = Date.now();
lo.trim(s) 
var time_cost0 = Date.now() - time0;
console.log("time_cost0: " + time_cost0);
var time1 = Date.now();
lo.toNumber(s) var time_cost1 = Date.now() - time1;
console.log("time_cost1: " + time_cost1);
var time2 = Date.now();
lo.trimEnd(s);
var time_cost2 = Date.now() - time2;
console.log("time_cost2: " + time_cost2);
```','MEDIUM','2022-01-06T20:30:46Z','2025-09-29T21:12:31.102523Z','["https://nvd.nist.gov/vuln/detail/CVE-2020-28500","https://github.com/github/advisory-database/pull/6139","https://github.com/lodash/lodash/pull/5065","https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7","https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a","https://www.oracle.com/security-alerts/cpuoct2021.html","https://www.oracle.com/security-alerts/cpujul2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://www.oracle.com//security-alerts/cpujul2021.html","https://snyk.io/vuln/SNYK-JS-LODASH-1018905","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894","https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896","https://security.netapp.com/advisory/ntap-20210312-0006","https://github.com/rubysec/ruby-advisory-db/blob/master/gems/lodash-rails/CVE-2020-28500.yml","https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8","https://github.com/lodash/lodash","https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf"]','{}','2026-11-02T09:44:56Z',0,'',0.07336,5.3);
INSERT INTO "vulnerabilities" VALUES('GHSA-35jh-r3h4-6jhm','["CVE-2021-23337"]','Command Injection in lodash','`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.','HIGH','2021-05-06T16:05:51Z','2026-10-17T02:55:38.085813876Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-23337","https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c","https://www.oracle.com/security-alerts/cpuoct2021.html","https://www.oracle.com/security-alerts/cpujul2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://www.oracle.com//security-alerts/cpujul2021.html","https://snyk.io/vuln/SNYK-JS-LODASH-1040724","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928","https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930","https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932","https://security.netapp.com/advisory/ntap-20210312-0006","https://github.com/rubysec/ruby-advisory-db/blob/master/gems/lodash-rails/CVE-2021-23337.yml","https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851","https://github.com/lodash/lodash","https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf"]','{}','2026-11-02T09:44:56Z',0,'',0.21333,7.2);
INSERT INTO "vulnerabilities" VALUES('GHSA-f23m-r3pf-42rh','["CVE-2026-2950"]','lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`','### Impact

Lodash versions 4.17.23 and earlier are vulnerable to prototype pollution in the `_.unset` and `_.omit` functions. The fix for [CVE-2025-13465](https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg) only guards against string key members, so an attacker can bypass the check by passing array-wrapped path segments. This allows deletion of properties from built-in prototypes such as `Object.prototype`, `Number.prototype`, and `String.prototype`.

The issue permits deletion of prototype properties but does not allow overwriting their original behavior.

### Patches

This issue is patched in 4.18.0.

### Workarounds

None. Upgrade to the patched version.','MEDIUM','2026-04-01T23:50:27Z','2026-10-17T02:56:13.084362346Z','["https://github.com/lodash/lodash/security/advisories/GHSA-f23m-r3pf-42rh","https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg","https://nvd.nist.gov/vuln/detail/CVE-2026-2950","https://github.com/lodash/lodash"]','{}','2026-11-02T09:44:56Z',0,'',0.00337,6.5);
INSERT INTO "vulnerabilities" VALUES('GHSA-p6mc-m468-83gw','["CVE-2020-8203"]','Prototype Pollution in lodash','Versions of lodash prior to 4.17.19 are vulnerable to Prototype Pollution. The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` allow a malicious user to modify the prototype of Object if the property identifiers are user-supplied. Being affected by this issue requires manipulating objects based on user-provided property values or arrays.

This vulnerability causes the addition or modification of an existing property that will exist on all objects and may lead to Denial of Service or Code Execution under specific circumstances.','HIGH','2020-07-15T19:15:48Z','2025-08-12T21:56:17.174859Z','["https://nvd.nist.gov/vuln/detail/CVE-2020-8203","https://github.com/lodash/lodash/issues/4744","https://github.com/lodash/lodash/issues/4874","https://github.com/github/advisory-database/pull/2884","https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12","https://hackerone.com/reports/712065","https://hackerone.com/reports/864701","https://github.com/lodash/lodash","https://github.com/lodash/lodash/wiki/Changelog#v41719","https://github.com/rubysec/ruby-advisory-db/blob/master/gems/lodash-rails/CVE-2020-8203.yml","https://security.netapp.com/advisory/ntap-20200724-0006","https://web.archive.org/web/20210914001339/https://github.com/lodash/lodash/issues/4744"]','{}','2026-11-02T09:44:57Z',0,'',0.05213,7.4);
INSERT INTO "vulnerabilities" VALUES('GHSA-r5fr-rjxr-66jc','["CVE-2026-4800"]','lodash vulnerable to Code Injection via `_.template` imports key names','### Impact

The fix for [CVE-2021-23337](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) added validation for the `variable` option in `_.template` but did not apply the same validation to `options.imports` key names. Both paths flow into the same `Function()` constructor sink.

When an application passes untrusted input as `options.imports` key names, an attacker can inject default-parameter expressions that execute arbitrary code at template compilation time.

Additionally, `_.template` uses `assignInWith` to merge imports, which enumerates inherited properties via `for..in`. If `Object.prototype` has been polluted by any other vector, the polluted keys are copied into the imports object and passed to `Function()`.

### Patches

Users should upgrade to version 4.18.0.

The fix applies two changes:
1. Validate `importsKeys` against the existing `reForbiddenIdentifierChars` regex (same check already used for the `variable` option)
2. Replace `assignInWith` with `assignWith` when merging imports, so only own properties are enumerated

### Workarounds

Do not pass untrusted input as key names in `options.imports`. Only use developer-controlled, static key names.','HIGH','2026-04-01T23:51:12Z','2026-10-17T02:56:15.633068434Z','["https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc","https://nvd.nist.gov/vuln/detail/CVE-2026-4800","https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c","https://cna.openjsf.org/security-advisories.html","https://github.com/advisories/GHSA-35jh-r3h4-6jhm","https://github.com/lodash/lodash"]','{}','2026-11-02T09:44:57Z',0,'',0.02808,8.1);
INSERT INTO "vulnerabilities" VALUES('GHSA-xxjr-mmjv-4gpg','["CVE-2025-13465"]','Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions','### Impact

Lodash versions 4.0.0 through 4.17.22 are vulnerable to prototype pollution in the `_.unset` and `_.omit` functions. An attacker can pass crafted paths which cause Lodash to delete methods from global prototypes. 

The issue permits deletion of properties but does not allow overwriting their original behavior.  

### Patches

This issue is patched on 4.17.23.','MEDIUM','2026-01-21T23:01:22Z','2026-10-17T02:55:54.229635593Z','["https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg","https://nvd.nist.gov/vuln/detail/CVE-2025-13465","https://github.com/lodash/lodash/commit/edadd452146f7e4bad4ea684e955708931d84d81","https://cert-portal.siemens.com/productcert/html/ssa-253495.html","https://github.com/lodash/lodash"]','{}','2026-11-02T09:44:57Z',0,'',0.01823,6.5);
INSERT INTO "vulnerabilities" VALUES('GHSA-3pxv-7cmr-fjr4','["CVE-2026-34480"]','Apache Log4j Core: Silent log event loss in XmlLayout due to unescaped XML 1.0 forbidden characters','Apache Log4j Core''s [`XmlLayout`](https://logging.apache.org/log4j/2.x/manual/layouts.html#XmlLayout), in versions up to and including 2.25.3, fails to sanitize characters forbidden by the [XML 1.0 specification](https://www.w3.org/TR/xml/#charsets), producing invalid XML output whenever a log message or MDC value contains such characters.

The impact depends on the StAX implementation in use:

  *  **JRE built-in StAX**: Forbidden characters are silently written to the output, producing malformed XML. Conforming parsers must reject such documents with a fatal error, which may cause downstream log-processing systems to drop the affected records.
  *  **Alternative StAX implementations** (e.g., [Woodstox](https://github.com/FasterXML/woodstox), a transitive dependency of the Jackson XML Dataformat module): An exception is thrown during the logging call, and the log event is never delivered to its intended appender, only to Log4j''s internal status logger.

Users are advised to upgrade to Apache Log4j Core 2.25.4, which corrects this issue by sanitizing forbidden characters before XML output.','MEDIUM','2026-04-10T18:31:17Z','2026-09-10T03:50:42.492278990Z','["https://nvd.nist.gov/vuln/detail/CVE-2026-34480","https://github.com/apache/logging-log4j2/pull/4077","https://github.com/apache/logging-log4j2","https://lists.apache.org/thread/5x0hcnng0chhghp6jgjdp3qmbbhfjzhb","https://logging.apache.org/cyclonedx/vdr.xml","https://logging.apache.org/log4j/2.x/manual/layouts.html#XmlLayout","https://logging.apache.org/security.html#CVE-2026-34480","http://www.openwall.com/lists/oss-security/2026/04/10/9"]','{}','2026-11-02T09:44:57Z',0,'',0.01046,-1.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-6hg6-v5c8-fphq','["CVE-2026-34477"]','Apache Log4j Core: `verifyHostName` attribute silently ignored in TLS configuration','The fix for  CVE-2025-68161 was incomplete: it addressed hostname verification only when enabled via the  [`log4j2.sslVerifyHostName`](https://logging.apache.org/log4j/2.x/manual/systemproperties.html#log4j2.sslVerifyHostName) system property, but not when configured through the [`verifyHostName`](https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName) attribute of the `<Ssl>` element.

Although the `verifyHostName` configuration attribute was introduced in Log4j Core 2.12.0, it was silently ignored in all versions through 2.25.3, leaving TLS connections vulnerable to interception regardless of the configured value.

A network-based attacker may be able to perform a man-in-the-middle attack when all of the following conditions are met:

  *  An SMTP, Socket, or Syslog appender is in use.
  *  TLS is configured via a nested <Ssl> element.
  *  The attacker can present a certificate issued by a CA trusted by the appender''s configured trust store, or by the default Java trust store if none is configured.

This issue does not affect users of the HTTP appender, which uses a separate [`verifyHostname`](https://logging.apache.org/log4j/2.x/manual/appenders/network.html#HttpAppender-attr-verifyHostName) attribute that was not subject to this bug and verifies host names by default.

Users are advised to upgrade to Apache Log4j Core 2.25.4, which corrects this issue.','MEDIUM','2026-04-10T18:31:17Z','2026-09-10T03:50:43.570169134Z','["https://nvd.nist.gov/vuln/detail/CVE-2026-34477","https://github.com/apache/logging-log4j2/pull/4075","https://github.com/apache/logging-log4j2","https://lists.apache.org/thread/lkx8cl46t2bvkcwfcb2pd43ygc097lq4","https://logging.apache.org/cyclonedx/vdr.xml","https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName","https://logging.apache.org/security.html#CVE-2026-34477"]','{}','2026-11-02T09:44:57Z',0,'',0.0056,-1.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-7rjr-3q55-vv33','["CVE-2021-45046"]','Incomplete fix for Apache Log4j vulnerability','# Impact

The fix to address [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allow attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a remote code execution (RCE) attack. 

## Affected packages
Only the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.

# Mitigation

Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default. This issue can be mitigated in prior releases (< 2.16.0) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).

Log4j 2.15.0 restricts JNDI LDAP lookups to localhost by default. Note that previous mitigations involving configuration such as to set the system property `log4j2.formatMsgNoLookups` to `true` do NOT mitigate this specific vulnerability.','CRITICAL','2021-12-14T18:01:28Z','2026-10-02T20:30:05.438504645Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-45046","https://www.oracle.com/security-alerts/cpujul2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://www.oracle.com/security-alerts/cpuapr2022.html","https://www.oracle.com/security-alerts/alert-cve-2021-44228.html","https://www.openwall.com/lists/oss-security/2021/12/18/1","https://www.openwall.com/lists/oss-security/2021/12/15/3","https://www.openwall.com/lists/oss-security/2021/12/14/4","https://www.kb.cert.org/vuls/id/930724","https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html","https://www.debian.org/security/2021/dsa-5022","https://www.cve.org/CVERecord?id=CVE-2021-44228","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-45046","https://security.gentoo.org/glsa/202310-16","https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032","https://logging.apache.org/security.html#CVE-2021-45046","https://logging.apache.org/log4j/2.x/security.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SIG7FZULMNK2XF6FZRU4VWYDQXNMUGAJ","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EOKPQGV24RRBBI4TBZUDQMM4MEH7MXCY","https://github.com/apache/logging-log4j2/compare/rel/2.3...rel/2.3.1","https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf"]','{}','2026-11-02T09:44:57Z',1,'2023-05-22',0.99977,9.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-8489-44mv-ggj8','["CVE-2021-44832"]','Improper Input Validation and Injection in Apache Log4j2','Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to an attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data source referencing a JNDI URI which can execute remote code. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.


# Affected packages
Only the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.

This issue does not impact default configurations of Log4j2 and requires an attacker to have control over the Log4j2 configuration, which reduces the likelihood of being exploited.','MEDIUM','2022-01-04T16:14:20Z','2026-06-09T10:45:14.253296471Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-44832","https://cert-portal.siemens.com/productcert/pdf/ssa-784507.pdf","https://github.com/apache/logging-log4j2","https://issues.apache.org/jira/browse/LOG4J2-3293","https://lists.apache.org/thread/s1o5vlo78ypqxnzn6p8zf6t9shtq5143","https://lists.debian.org/debian-lts-announce/2021/12/msg00036.html","https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EVV25FXL4FU5X6X5BSL7RLQ7T6F65MRA","https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T57MPJUW3MA6QGWZRTMCHHMMPQNVKGFC","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EVV25FXL4FU5X6X5BSL7RLQ7T6F65MRA","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/T57MPJUW3MA6QGWZRTMCHHMMPQNVKGFC","https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://security.netapp.com/advisory/ntap-20220104-0001","https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://www.oracle.com/security-alerts/cpuapr2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://www.oracle.com/security-alerts/cpujul2022.html","http://www.openwall.com/lists/oss-security/2021/12/28/1"]','{}','2026-11-02T09:44:58Z',0,'',0.97906,6.6);
INSERT INTO "vulnerabilities" VALUES('GHSA-h383-gmxw-35v2','["CVE-2026-34479"]','Apache Log4j 1 to Log4j 2 bridge: silent log event loss in Log4j1XmlLayout due to unescaped XML 1.0 forbidden characters','The `Log4j1XmlLayout` from the Apache Log4j 1-to-Log4j 2 bridge fails to escape characters forbidden by the XML 1.0 standard, producing malformed XML output. Conforming XML parsers are required to reject documents containing such characters with a fatal error, which may cause downstream log processing systems to drop or fail to index affected records.

Two groups of users are affected:

* Those using `Log4j1XmlLayout` directly in a Log4j Core 2 configuration file.
* Those using the Log4j 1 configuration compatibility layer with `org.apache.log4j.xml.XMLLayout` specified as the layout class.

Users are advised to upgrade to Apache Log4j 1-to-Log4j 2 bridge version `2.25.4`, which corrects this issue.

> [!NOTE]
> The Apache Log4j 1-to-Log4j 2 bridge is deprecated and will not be present in Log4j 3. Users are encouraged to consult the
> [Log4j 1 to Log4j 2 migration guide](https://logging.apache.org/log4j/2.x/migrate-from-log4j1.html), and specifically the section on eliminating reliance on the bridge.','MEDIUM','2026-04-10T18:31:18Z','2026-10-26T15:30:05.719203570Z','["https://nvd.nist.gov/vuln/detail/CVE-2026-34479","https://github.com/apache/logging-log4j2/pull/4078","https://github.com/apache/logging-log4j2","https://lists.apache.org/thread/gd0hp6mj17rn3kj279vgy4p7kd4zz5on","https://logging.apache.org/cyclonedx/vdr.xml","https://logging.apache.org/log4j/2.x/migrate-from-log4j1.html","https://logging.apache.org/security.html#CVE-2026-34479","http://www.openwall.com/lists/oss-security/2026/04/10/8"]','{}','2026-11-02T09:44:58Z',0,'',0.00535,-1.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-jfh8-c2jp-5v3q','["CVE-2021-44228"]','Remote code injection in Log4j','# Summary

Log4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the ldap JNDI parser.
As per [Apache''s Log4j security guide](https://logging.apache.org/log4j/2.x/security.html): Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.16.0, this behavior has been disabled by default.

Log4j version 2.15.0 contained an earlier fix for the vulnerability, but that patch did not disable attacker-controlled JNDI lookups in all situations. For more information, see the `Updated advice for version 2.16.0` section of this advisory.

# Impact

Logging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input. 

# Affected versions

Any Log4J version prior to v2.15.0 is affected to this specific issue.

The v1 branch of Log4J which is considered End Of Life (EOL) is vulnerable to other RCE vectors so the recommendation is to still update to 2.16.0 where possible.

## Security releases
Additional backports of this fix have been made available in versions 2.3.1, 2.12.2, and 2.12.3

## Affected packages
Only the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.

# Remediation Advice

## Updated advice for version 2.16.0

The Apache Logging Services team provided updated mitigation advice upon the release of version 2.16.0, which [disables JNDI by default and completely removes support for message lookups](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0).
Even in version 2.15.0, lookups used in layouts to provide specific pieces of context information will still recursively resolve, possibly triggering JNDI lookups. This problem is being tracked as [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046). More information is available on the [GitHub Security Advisory for CVE-2021-45046](https://github.com/advisories/GHSA-7rjr-3q55-vv33).

Users who want to avoid attacker-controlled JNDI lookups but cannot upgrade to 2.16.0 must [ensure that no such lookups resolve to attacker-provided data and ensure that the the JndiLookup class is not loaded](https://issues.apache.org/jira/browse/LOG4J2-3221).

Please note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue. Log4J v1 is also vulnerable to other RCE vectors and we recommend you migrate to Log4J 2.16.0 where possible.','CRITICAL','2021-12-10T00:40:56Z','2025-10-22T19:37:02.616807Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-44228","https://github.com/apache/logging-log4j2/pull/608","https://github.com/github/advisory-database/pull/5501","https://cert-portal.siemens.com/productcert/pdf/ssa-397453.pdf","https://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html","https://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html","https://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html","https://packetstormsecurity.com/files/171626/AD-Manager-Plus-7122-Remote-Code-Execution.html","https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032","https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://seclists.org/fulldisclosure/2022/Dec/2","https://seclists.org/fulldisclosure/2022/Jul/11","https://seclists.org/fulldisclosure/2022/Mar/23","https://security.netapp.com/advisory/ntap-20211210-0007","https://support.apple.com/kb/HT213189","https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://twitter.com/kurtseifried/status/1469345530182455296","https://www.bentley.com/en/common-vulnerability-exposure/be-2022-0001","https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228","https://www.debian.org/security/2021/dsa-5020","https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00646.html","https://www.kb.cert.org/vuls/id/930724","https://www.nu11secur1ty.com/2021/12/cve-2021-44228.html","https://www.oracle.com/security-alerts/alert-cve-2021-44228.html","https://www.oracle.com/security-alerts/cpuapr2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-661247.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-714170.pdf","https://github.com/advisories/GHSA-7rjr-3q55-vv33","https://github.com/apache/logging-log4j2","https://github.com/cisagov/log4j-affected-db","https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md","https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-44228","https://github.com/tangxiaofeng7/apache-log4j-poc","https://issues.apache.org/jira/browse/LOG4J2-3198","https://issues.apache.org/jira/browse/LOG4J2-3201","https://issues.apache.org/jira/browse/LOG4J2-3214","https://issues.apache.org/jira/browse/LOG4J2-3221","https://lists.debian.org/debian-lts-announce/2021/12/msg00007.html","https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB","https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/M5CSVUNV4HWZZXGOKNSK6L7RPM7BOKIB","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VU57UJDCFIASIO35GC55JMKSRXJMCDFM","https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0","https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup","https://logging.apache.org/log4j/2.x/manual/migration.html","https://logging.apache.org/log4j/2.x/security.html","https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2","http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html","http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html","http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html","http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html","http://packetstormsecurity.com/files/165281/Log4j2-Log4Shell-Regexes.html","http://packetstormsecurity.com/files/165282/Log4j-Payload-Generator.html","http://packetstormsecurity.com/files/165306/L4sh-Log4j-Remote-Code-Execution.html","http://packetstormsecurity.com/files/165307/Log4j-Remote-Code-Execution-Word-Bypassing.html","http://packetstormsecurity.com/files/165311/log4j-scan-Extensive-Scanner.html","http://packetstormsecurity.com/files/165371/VMware-Security-Advisory-2021-0028.4.html","http://packetstormsecurity.com/files/165532/Log4Shell-HTTP-Header-Injection.html","http://packetstormsecurity.com/files/165642/VMware-vCenter-Server-Unauthenticated-Log4Shell-JNDI-Injection-Remote-Code-Execution.html","http://packetstormsecurity.com/files/165673/UniFi-Network-Application-Unauthenticated-Log4Shell-Remote-Code-Execution.html","http://packetstormsecurity.com/files/167794/Open-Xchange-App-Suite-7.10.x-Cross-Site-Scripting-Command-Injection.html","http://packetstormsecurity.com/files/167917/MobileIron-Log4Shell-Remote-Command-Execution.html","http://packetstormsecurity.com/files/171626/AD-Manager-Plus-7122-Remote-Code-Execution.html","http://seclists.org/fulldisclosure/2022/Dec/2","http://seclists.org/fulldisclosure/2022/Jul/11","http://seclists.org/fulldisclosure/2022/Mar/23","http://www.openwall.com/lists/oss-security/2021/12/10/1","http://www.openwall.com/lists/oss-security/2021/12/10/2","http://www.openwall.com/lists/oss-security/2021/12/10/3","http://www.openwall.com/lists/oss-security/2021/12/13/1","http://www.openwall.com/lists/oss-security/2021/12/13/2","http://www.openwall.com/lists/oss-security/2021/12/14/4","http://www.openwall.com/lists/oss-security/2021/12/15/3"]','{"affected":[{"package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven","purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]}],"versions":["2.13.0","2.13.1","2.13.2","2.13.3","2.14.0","2.14.1"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven","purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.3.1"}]}],"versions":["2.0","2.0-beta9","2.0-rc1","2.0-rc2","2.0.1","2.0.2","2.1","2.2","2.3"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven","purl":"pkg:maven/org.apache.logging.log4j/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4"},{"fixed":"2.12.2"}]}],"versions":["2.10.0","2.11.0","2.11.1","2.11.2","2.12.0","2.12.1","2.4","2.4.1","2.5","2.6","2.6.1","2.6.2","2.7","2.8","2.8.1","2.8.2","2.9.0","2.9.1"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"com.guicedee.services:log4j-core","ecosystem":"Maven","purl":"pkg:maven/com.guicedee.services/log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.2.1.2-jre17"}]}],"versions":["1.0.10.0","1.0.10.0-jre13","1.0.10.0-jre14","1.0.10.1","1.0.10.1-jre14","1.0.10.3","1.0.10.3-jre14","1.0.10.4","1.0.10.4-jre12","1.0.10.4-jre13","1.0.10.4-jre14","1.0.11.0-jre14","1.0.11.2-jre14","1.0.11.5","1.0.11.5-jre12","1.0.11.5-jre14","1.0.11.6-jre14","1.0.11.7","1.0.11.7-jre12","1.0.11.7-jre14","1.0.12.0","1.0.12.0-jre12","1.0.12.0-jre13","1.0.12.0-jre14","1.0.12.0-jre8","1.0.12.1","1.0.12.1-jre12","1.0.12.1-jre14","1.0.12.2","1.0.12.2-jre12","1.0.12.2-jre14","1.0.12.3","1.0.12.3-jre12","1.0.12.3-jre13","1.0.12.3-jre14","1.0.12.4","1.0.12.4-jre12","1.0.12.4-jre13","1.0.12.4-jre14","1.0.12.4-jre8","1.0.12.5","1.0.12.5-jre14","1.0.13.0","1.0.13.0-jre12","1.0.13.0-jre13","1.0.13.0-jre14","1.0.13.0-jre8","1.0.13.1","1.0.13.1-jre13","1.0.13.1-jre14","1.0.13.1-jre8","1.0.13.2","1.0.13.2-jre12","1.0.13.2-jre13","1.0.13.2-jre14","1.0.13.2-jre8","1.0.13.3","1.0.13.3-jre14","1.0.13.4","1.0.13.4-jre12","1.0.13.4-jre13","1.0.13.4-jre14","1.0.13.5","1.0.13.5-jre12","1.0.13.5-jre14","1.0.13.5-jre8","1.0.14.0-RC1-jre14","1.0.14.0-RC1-jre8","1.0.14.1","1.0.14.1-jre12","1.0.14.1-jre13","1.0.14.1-jre14","1.0.14.1-jre8","1.0.14.3-jre8","1.0.14.4-jre14","1.0.14.4-jre8","1.0.15.1","1.0.15.1-jre12","1.0.15.1-jre13","1.0.15.1-jre14","1.0.15.1-jre8","1.0.15.2","1.0.15.2-jre12","1.0.15.2-jre14","1.0.15.2-jre8","1.0.15.3-jre14","1.0.15.3-jre8","1.0.15.4","1.0.15.4-jre14","1.0.15.4-jre8","1.0.15.5","1.0.15.5-jre14","1.0.15.5-jre8","1.0.16.0","1.0.16.0-jre14","1.0.16.0-jre8","1.0.17.0","1.0.17.0-jre14","1.0.17.1","1.0.17.1-jre14","1.0.17.1-jre8","1.0.18.0","1.0.18.0-jre14","1.0.18.0-jre15","1.0.18.0-jre8","1.0.18.1","1.0.18.1-jre14","1.0.18.1-jre15","1.0.18.1-jre8","1.0.19.0","1.0.19.0-jre14","1.0.19.0-jre15","1.0.19.1","1.0.19.1-jre12","1.0.19.1-jre13","1.0.19.1-jre14","1.0.19.1-jre15","1.0.19.1-jre8","1.0.19.10","1.0.19.10-jre12","1.0.19.10-jre14","1.0.19.10-jre15","1.0.19.10-jre8","1.0.19.11","1.0.19.11-jre14","1.0.19.11-jre8","1.0.19.12-jre14","1.0.19.12-jre8","1.0.19.13","1.0.19.13-jre14","1.0.19.13-jre15","1.0.19.13-jre8","1.0.19.2","1.0.19.2-jre13","1.0.19.2-jre14","1.0.19.2-jre15","1.0.19.2-jre8","1.0.19.3","1.0.19.3-jre13","1.0.19.3-jre14","1.0.19.3-jre15","1.0.19.3-jre8","1.0.19.4","1.0.19.4-jre14","1.0.19.4-jre15","1.0.19.4-jre8","1.0.19.5","1.0.19.5-jre14","1.0.19.5-jre15","1.0.19.5-jre8","1.0.19.6","1.0.19.6-jre14","1.0.19.6-jre8","1.0.19.7-jre14","1.0.19.7-jre8","1.0.19.8-jre8","1.0.19.9","1.0.19.9-jre13","1.0.19.9-jre14","1.0.19.9-jre15","1.0.19.9-jre8","1.0.2.15","1.0.2.15-jre13","1.0.2.16-jre13","1.0.2.17-jre13","1.0.2.18","1.0.2.18-jre12","1.0.2.18-jre13","1.0.20.0","1.0.20.0-jre14","1.0.20.0-jre15","1.0.20.0-jre8","1.0.20.1","1.0.20.1-jre14","1.0.20.1-jre15","1.0.20.1-jre8","1.0.20.2","1.0.20.2-jre14","1.0.20.2-jre15","1.0.20.2-jre8","1.0.3.1-jre13","1.0.3.2","1.0.3.2-jre13","1.0.3.3","1.0.3.3-jre12","1.0.3.3-jre13","1.0.4.1-jre13","1.0.4.2","1.0.4.2-jre13","1.0.4.3-jre13","1.0.4.4","1.0.4.4-jre13","1.0.5.0","1.0.5.0-jre13","1.0.5.1","1.0.5.1-jre12","1.0.5.1-jre13","1.0.5.2","1.0.5.2-jre12","1.0.5.2-jre13","1.0.5.3","1.0.5.3-jre12","1.0.5.3-jre13","1.0.5.4-jre13","1.0.5.4-jre14","1.0.5.5","1.0.5.5-jre12","1.0.5.5-jre13","1.0.5.5-jre14","1.0.6.1","1.0.6.1-jre12","1.0.6.1-jre13","1.0.6.1-jre14","1.0.6.2","1.0.6.2-jre12","1.0.6.2-jre13","1.0.6.2-jre14","1.0.6.3","1.0.6.3-jre12","1.0.6.3-jre13","1.0.6.3-jre14","1.0.6.4-jre14","1.0.6.5","1.0.6.5-jre12","1.0.6.5-jre13","1.0.6.5-jre14","1.0.6.7","1.0.6.7-jre14","1.0.7.0","1.0.7.0-jre12","1.0.7.0-jre13","1.0.7.0-jre14","1.0.7.1","1.0.7.1-jre13","1.0.7.1-jre14","1.0.7.10","1.0.7.10-jre13","1.0.7.10-jre14","1.0.7.11","1.0.7.11-jre14","1.0.7.12","1.0.7.12-jre12","1.0.7.12-jre13","1.0.7.12-jre14","1.0.7.2-jre14","1.0.7.3","1.0.7.3-jre13","1.0.7.3-jre14","1.0.7.4","1.0.7.4-jre14","1.0.7.5","1.0.7.5-jre14","1.0.7.6","1.0.7.6-jre14","1.0.7.9","1.0.7.9-jre14","1.0.8.1","1.0.8.1-jre14","1.0.8.12","1.0.8.12-jre12","1.0.8.12-jre14","1.0.8.16","1.0.8.16-jre14","1.0.8.18","1.0.8.18-jre14","1.0.8.2","1.0.8.2-jre13","1.0.8.2-jre14","1.0.8.3","1.0.8.3-jre13","1.0.8.3-jre14","1.0.8.4","1.0.8.4-jre12","1.0.8.4-jre13","1.0.8.4-jre14","1.0.8.5","1.0.8.5-jre12","1.0.8.5-jre13","1.0.8.5-jre14","1.0.8.6-jre14","1.0.9.0","1.0.9.0-jre14","1.0.9.1","1.0.9.1-jre14","1.0.9.10","1.0.9.10-jre14","1.0.9.11","1.0.9.11-jre14","1.0.9.13","1.0.9.13-jre14","1.0.9.14","1.0.9.14-jre14","1.0.9.2","1.0.9.2-jre14","1.0.9.3-jre14","1.0.9.4-jre14","1.0.9.5-jre14","1.0.9.7-jre14","1.1.0.0-jre15","1.1.0.1","1.1.0.1-jre14","1.1.0.1-jre15","1.1.0.2","1.1.0.2-jre14","1.1.0.2-jre15","1.1.0.3","1.1.0.3-jre14","1.1.0.3-jre15","1.1.0.3-jre8","1.1.0.4-jre14","1.1.0.4-jre15","1.1.0.4-jre8","1.1.0.5-jre14","1.1.0.5-jre15","1.1.0.6","1.1.0.6-jre14","1.1.0.6-jre15","1.1.0.7","1.1.0.7-jre14","1.1.0.7-jre15","1.1.0.7-jre8","1.1.0.8-SNAPSHOT-jre14","1.1.1.0","1.1.1.0-SNAPSHOT-jre14","1.1.1.0-SNAPSHOT-jre15","1.1.1.0-SNAPSHOT-jre8","1.1.1.0-jre14","1.1.1.0-jre15","1.1.1.0-jre8","1.1.1.1-SP1","1.1.1.1-jre14-SP1","1.1.1.1-jre15-SP1","1.1.1.2","1.1.1.2-jre14","1.1.1.2-jre15","1.1.1.3","1.1.1.3-jre14","1.1.1.3-jre15","1.1.1.3-jre16","1.1.1.3-jre8","1.1.1.4","1.1.1.4-jre14","1.1.1.4-jre15","1.1.1.4-jre16","1.1.1.4-jre8","1.1.1.5-jre15","1.1.1.7","1.1.1.7-jre15","1.1.1.7-jre16","1.1.1.7-jre8","1.1.1.8-jre15","1.1.1.8-jre16","1.1.1.9-jre15","1.1.1.9-jre16","1.2.0.0-jre16","1.2.0.1-jre11","1.2.0.1-jre15","1.2.0.1-jre16","1.2.0.2-jre16","1.2.0.3-jre17-rc1","1.2.1.1-jre17","1.2.1.2-jre17"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.xbib.elasticsearch:log4j","ecosystem":"Maven","purl":"pkg:maven/org.xbib.elasticsearch/log4j"},"versions":["6.3.2.1"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"uk.co.nichesolutions.logging.log4j:log4j-core","ecosystem":"Maven","purl":"pkg:maven/uk.co.nichesolutions.logging.log4j/log4j-core"},"versions":["2.6.3-CUSTOM"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.ops4j.pax.logging:pax-logging-log4j2","ecosystem":"Maven","purl":"pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.8.0"},{"fixed":"1.9.2"}]}],"versions":["1.8.0","1.8.1","1.8.2","1.8.3","1.8.4","1.8.5","1.8.6","1.8.7","1.9.0","1.9.1"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.ops4j.pax.logging:pax-logging-log4j2","ecosystem":"Maven","purl":"pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.10.0"},{"fixed":"1.10.8"}]}],"versions":["1.10.0","1.10.1","1.10.2","1.10.3","1.10.4","1.10.5","1.10.6","1.10.7"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.ops4j.pax.logging:pax-logging-log4j2","ecosystem":"Maven","purl":"pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.11.0"},{"fixed":"1.11.10"}]}],"versions":["1.11.0","1.11.1","1.11.2","1.11.3","1.11.4","1.11.5","1.11.6","1.11.7","1.11.8","1.11.9"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}},{"package":{"name":"org.ops4j.pax.logging:pax-logging-log4j2","ecosystem":"Maven","purl":"pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.0.11"}]}],"versions":["2.0.0","2.0.1","2.0.10","2.0.2","2.0.3","2.0.4","2.0.5","2.0.6","2.0.7","2.0.8","2.0.9"],"database_specific":{"source":"https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json"}}]}','2026-11-02T09:44:58Z',1,'2021-12-24',0.99999,10.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-p6xc-xr62-6r2g','["CVE-2021-45105"]','Apache Log4j2 vulnerable to Improper Input Validation and Uncontrolled Recursion','Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0 and 2.12.3.


# Affected packages
Only the `org.apache.logging.log4j:log4j-core` package is directly affected by this vulnerability. The `org.apache.logging.log4j:log4j-api` should be kept at the same version as the `org.apache.logging.log4j:log4j-core` package to ensure compatability if in use.','HIGH','2021-12-18T18:00:07Z','2026-06-09T10:30:14.432177927Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-45105","https://www.zerodayinitiative.com/advisories/ZDI-21-1541","https://www.oracle.com/security-alerts/cpujul2022.html","https://www.oracle.com/security-alerts/cpujan2022.html","https://www.oracle.com/security-alerts/cpuapr2022.html","https://www.kb.cert.org/vuls/id/930724","https://www.debian.org/security/2021/dsa-5024","https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://security.netapp.com/advisory/ntap-20211218-0001","https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd","https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032","https://logging.apache.org/log4j/2.x/security.html","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SIG7FZULMNK2XF6FZRU4VWYDQXNMUGAJ","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/EOKPQGV24RRBBI4TBZUDQMM4MEH7MXCY","https://lists.debian.org/debian-lts-announce/2021/12/msg00017.html","https://cert-portal.siemens.com/productcert/pdf/ssa-501673.pdf","https://cert-portal.siemens.com/productcert/pdf/ssa-479842.pdf","http://www.openwall.com/lists/oss-security/2021/12/19/1"]','{}','2026-11-02T09:44:58Z',0,'',0.99999,8.6);
INSERT INTO "vulnerabilities" VALUES('GHSA-vc5p-v9hr-52mj','["CVE-2025-68161"]','Apache Log4j does not verify the TLS hostname in its Socket Appender','The Socket Appender in Apache Log4j Core versions 2.0-beta9 through 2.25.2 does not perform TLS hostname verification of the peer certificate, even when the  [verifyHostName](https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName)  configuration attribute or the  [log4j2.sslVerifyHostName](https://logging.apache.org/log4j/2.x/manual/systemproperties.html#log4j2.sslVerifyHostName) system property is set to true.

This issue may allow a man-in-the-middle attacker to intercept or redirect log traffic under the following conditions:

  *  The attacker is able to intercept or redirect network traffic between the client and the log receiver.
  *  The attacker can present a server certificate issued by a certification authority trusted by the Socket Appender’s configured trust store (or by the default Java trust store if no custom trust store is configured).


Users are advised to upgrade to Apache Log4j Core version 2.25.3, which addresses this issue.

As an alternative mitigation, the Socket Appender may be configured to use a private or restricted trust root to limit the set of trusted certificates.','MEDIUM','2025-12-18T21:31:44Z','2026-09-10T03:50:32.126499218Z','["https://nvd.nist.gov/vuln/detail/CVE-2025-68161","https://github.com/apache/logging-log4j2/pull/4002","https://github.com/apache/logging-log4j2/commit/3b93748497e1adbbd027fda8a5e7268ec5d0d578","https://github.com/apache/logging-log4j2","https://lists.apache.org/thread/xr33kyxq3sl67lwb61ggvm1fzc8k7dvx","https://logging.apache.org/cyclonedx/vdr.xml","https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName","https://logging.apache.org/log4j/2.x/manual/systemproperties.html#log4j2.sslVerifyHostName","https://logging.apache.org/security.html#CVE-2025-68161","http://www.openwall.com/lists/oss-security/2025/12/18/1"]','{}','2026-11-02T09:44:58Z',0,'',0.00767,-1.0);
INSERT INTO "vulnerabilities" VALUES('GHSA-xvch-5gv4-984h','["CVE-2021-44906"]','Prototype Pollution in minimist','Minimist prior to 1.2.6 and 0.2.4 is vulnerable to Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95).','CRITICAL','2022-03-18T00:01:09Z','2026-03-13T22:11:59.523514Z','["https://nvd.nist.gov/vuln/detail/CVE-2021-44906","https://github.com/minimistjs/minimist/issues/11","https://github.com/substack/minimist/issues/164","https://github.com/minimistjs/minimist/pull/24","https://github.com/minimistjs/minimist/commit/34e20b8461118608703d6485326abbb8e35e1703","https://github.com/minimistjs/minimist/commit/bc8ecee43875261f4f17eb20b1243d3ed15e70eb","https://github.com/minimistjs/minimist/commit/c2b981977fa834b223b408cfb860f933c9811e4d","https://github.com/minimistjs/minimist/commit/ef9153fc52b6cea0744b2239921c5dcae4697f11","https://github.com/Marynk/JavaScript-vulnerability-detection/blob/main/minimist%20PoC.zip","https://github.com/minimistjs/minimist/commits/v0.2.4","https://github.com/substack/minimist","https://github.com/substack/minimist/blob/master/index.js#L69","https://security.netapp.com/advisory/ntap-20240621-0006","https://snyk.io/vuln/SNYK-JS-MINIMIST-559764","https://stackoverflow.com/questions/8588563/adding-custom-properties-to-a-function/20278068#20278068"]','{}','2026-11-02T09:44:59Z',0,'',0.04581,9.8);
INSERT INTO "vulnerabilities" VALUES('GHSA-9hjg-9r4m-mvj7','["CVE-2024-47081","PYSEC-2026-1872"]','Requests vulnerable to .netrc credentials leak via malicious URLs','### Impact

Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs.

### Workarounds
For older versions of Requests, use of the .netrc file can be disabled with `trust_env=False` on your Requests Session ([docs](https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env)).

### References
https://github.com/psf/requests/pull/6965
https://seclists.org/fulldisclosure/2025/Jun/2','MEDIUM','2025-06-09T19:06:08Z','2026-10-19T20:00:04.716114530Z','["https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7","https://nvd.nist.gov/vuln/detail/CVE-2024-47081","https://github.com/psf/requests/pull/6965","https://github.com/psf/requests/commit/96ba401c1296ab1dda74a2365ef36d88f7d144ef","https://github.com/advisories/GHSA-9hjg-9r4m-mvj7","https://github.com/psf/requests","https://github.com/psf/requests/releases/tag/v2.32.4","https://github.com/pypa/advisory-database/tree/main/vulns/requests/PYSEC-2026-1872.yaml","https://pypi.org/project/requests","https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env","https://seclists.org/fulldisclosure/2025/Jun/2","http://www.openwall.com/lists/oss-security/2025/06/03/11","http://www.openwall.com/lists/oss-security/2025/06/03/9","http://www.openwall.com/lists/oss-security/2025/06/04/1","http://www.openwall.com/lists/oss-security/2025/06/04/6"]','{}','2026-11-02T09:44:59Z',0,'',0.0098,5.3);
INSERT INTO "vulnerabilities" VALUES('GHSA-9wx4-h78v-vm56','["CVE-2024-35195","PYSEC-2026-1873"]','Requests `Session` object does not verify requests after making first request with verify=False','When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate verification may remain disabled for all subsequent requests to that origin, even if `verify=True` is explicitly specified later.

This occurs because the underlying connection is reused from the session''s connection pool, causing the initial TLS verification setting to persist for the lifetime of the pooled connection. As a result, applications may unintentionally send requests without certificate verification, leading to potential man-in-the-middle attacks and compromised confidentiality or integrity.

This behavior affects versions of `requests` prior to 2.32.0.','MEDIUM','2024-05-20T20:15:00Z','2026-09-10T03:50:13.740879755Z','["https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56","https://nvd.nist.gov/vuln/detail/CVE-2024-35195","https://github.com/psf/requests/pull/6655","https://github.com/psf/requests/commit/a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac","https://github.com/psf/requests","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYLSNK5TL46Q6XPRVMHVWS63MVJQOK4Q","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N7WP6EYDSUOCOJYHDK5NX43PYZ4SNHGZ"]','{}','2026-11-02T09:44:59Z',0,'',0.0034,5.6);
INSERT INTO "vulnerabilities" VALUES('GHSA-gc5v-m9x4-r6x2','["CVE-2026-25645","PYSEC-2026-2275"]','Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function','### Impact
The `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting files from zip archives into the system temporary directory. If the target file already exists, it is reused without validation. A local attacker with write access to the temp directory could pre-create a malicious file that would be loaded in place of the legitimate one.

### Affected usages
**Standard usage of the Requests library is not affected by this vulnerability.** Only applications that call `extract_zipped_paths()` directly are impacted.

### Remediation
Upgrade to at least Requests 2.33.0, where the library now extracts files to a non-deterministic location.

If developers are unable to upgrade, they can set `TMPDIR` in their environment to a directory with restricted write access.','MEDIUM','2026-03-25T16:56:28Z','2026-09-10T03:50:39.207922076Z','["https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2","https://nvd.nist.gov/vuln/detail/CVE-2026-25645","https://github.com/psf/requests/commit/66d21cb07bd6255b1280291c4fafb71803cdb3b7","https://github.com/psf/requests","https://github.com/psf/requests/releases/tag/v2.33.0"]','{}','2026-11-02T09:44:59Z',0,'',0.00189,4.4);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1872','["CVE-2024-47081","GHSA-9hjg-9r4m-mvj7"]','Requests vulnerable to .netrc credentials leak via malicious URLs','### Impact

Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs.

### Workarounds
For older versions of Requests, use of the .netrc file can be disabled with `trust_env=False` on your Requests Session ([docs](https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env)).

### References
https://github.com/psf/requests/pull/6965
https://seclists.org/fulldisclosure/2025/Jun/2','MEDIUM','2026-07-07T16:02:54.151964Z','2026-07-07T17:47:00.332079836Z','["https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7","https://nvd.nist.gov/vuln/detail/CVE-2024-47081","https://github.com/psf/requests/pull/6965","https://github.com/psf/requests/commit/96ba401c1296ab1dda74a2365ef36d88f7d144ef","https://github.com/psf/requests","https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env","https://seclists.org/fulldisclosure/2025/Jun/2","http://seclists.org/fulldisclosure/2025/Jun/2","http://www.openwall.com/lists/oss-security/2025/06/03/11","http://www.openwall.com/lists/oss-security/2025/06/03/9","http://www.openwall.com/lists/oss-security/2025/06/04/1","http://www.openwall.com/lists/oss-security/2025/06/04/6","https://pypi.org/project/requests","https://github.com/advisories/GHSA-9hjg-9r4m-mvj7"]','{}','2026-11-02T09:44:59Z',0,'',0.0098,5.3);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-1873','["CVE-2024-35195","GHSA-9wx4-h78v-vm56"]','Requests `Session` object does not verify requests after making first request with verify=False','When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate verification may remain disabled for all subsequent requests to that origin, even if `verify=True` is explicitly specified later.

This occurs because the underlying connection is reused from the session''s connection pool, causing the initial TLS verification setting to persist for the lifetime of the pooled connection. As a result, applications may unintentionally send requests without certificate verification, leading to potential man-in-the-middle attacks and compromised confidentiality or integrity.

This behavior affects versions of `requests` prior to 2.32.0.','MEDIUM','2026-07-07T11:45:42.890131Z','2026-07-07T17:46:36.762141019Z','["https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56","https://nvd.nist.gov/vuln/detail/CVE-2024-35195","https://github.com/psf/requests/pull/6655","https://github.com/psf/requests/commit/a58d7f2ffb4d00b46dca2d70a3932a0b37e22fac","https://github.com/psf/requests","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IYLSNK5TL46Q6XPRVMHVWS63MVJQOK4Q","https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/N7WP6EYDSUOCOJYHDK5NX43PYZ4SNHGZ","https://pypi.org/project/requests","https://github.com/advisories/GHSA-9wx4-h78v-vm56"]','{}','2026-11-02T09:45:00Z',0,'',0.0034,5.6);
INSERT INTO "vulnerabilities" VALUES('PYSEC-2026-2275','["CVE-2026-25645","GHSA-gc5v-m9x4-r6x2"]','','Requests is a HTTP library. Prior to version 2.33.0, the `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting files from zip archives into the system temporary directory. If the target file already exists, it is reused without validation. A local attacker with write access to the temp directory could pre-create a malicious file that would be loaded in place of the legitimate one. Standard usage of the Requests library is not affected by this vulnerability. Only applications that call `extract_zipped_paths()` directly are impacted. Starting in version 2.33.0, the library extracts files to a non-deterministic location. If developers are unable to upgrade, they can set `TMPDIR` in their environment to a directory with restricted write access.','MEDIUM','2026-03-25T17:16:52.970Z','2026-07-13T07:15:43.964902190Z','["https://github.com/psf/requests/releases/tag/v2.33.0","https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2","https://github.com/psf/requests/commit/66d21cb07bd6255b1280291c4fafb71803cdb3b7"]','{}','2026-11-02T09:45:00Z',0,'',0.00189,5.5);
CREATE TABLE "webhooks" (
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
INSERT INTO "webhooks" VALUES(1,'Équipe sécu','slack','https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX',1,'réponse HTTP 404','2026-11-02T09:44:54Z',1,'priority');
CREATE INDEX findings_status ON findings (status);
CREATE INDEX findings_first_seen ON findings (first_seen);
CREATE INDEX assets_project ON assets (project);
CREATE INDEX cti_items_published ON cti_items (published);
CREATE INDEX vulnerabilities_cvss ON vulnerabilities (cvss);
CREATE INDEX cti_mentions_cve ON cti_mentions (cve);
COMMIT;
