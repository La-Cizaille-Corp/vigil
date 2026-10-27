# Architecture

Un binaire Go unique, sans CGO, embarquant les migrations SQL, les templates et la feuille de style.

```
cmd/vigil              CLI : serve, sync, digest, import-sbom, user add
internal/store         SQLite (modernc.org/sqlite), migrations, toutes les requêtes SQL
internal/inventory     Validation et normalisation des actifs
internal/sbom          Lecture CycloneDX / SPDX (JSON) → actifs
internal/sources/osv   Client de l'API OSV.dev
internal/sources/kev   Catalogue CISA Known Exploited Vulnerabilities
internal/sources/epss  Scores FIRST EPSS
internal/tracking      Synchronisation inventaire ↔ sources, enrichissement, statuts VEX
internal/cti           Flux RSS/Atom, étiquetage pays / secteur, filtres de veille
internal/digest        Génération du digest (Markdown + HTML)
internal/notify        Envoi des digests aux webhooks
internal/netsafe       Client HTTP anti-SSRF pour les URL fournies par les utilisateurs
internal/auth          argon2id, jetons, limitation des tentatives, rôles
internal/web           Handlers HTTP, middleware de sécurité, templates
```

## Flux de synchronisation

1. `tracking.Syncer` liste les actifs interrogeables (purl ou écosystème + version).
2. Une requête `querybatch` OSV renvoie les identifiants de vulnérabilités par actif.
3. Chaque avis inconnu ou modifié est téléchargé et stocké (`vulnerabilities`).
4. `findings` : création si nouveau, réouverture si résolu automatiquement puis signalé à nouveau,
   résolution automatique si la source ne le signale plus (ex. version mise à jour).
5. Enrichissement : les CVE des avis stockés sont croisées avec CISA KEV et EPSS. Une panne de
   ces sources est journalisée sans faire échouer la synchronisation.
6. `cti.Collector` récupère les flux actifs ; chaque item reçoit les pays / secteurs de sa
   source, complétés par mots-clés. Les items de plus de 180 jours sont purgés.

## Digest

Couvre la période depuis le digest précédent (7 jours pour le premier) : nouvelles
vulnérabilités, vulnérabilités ouvertes, synthèse par statut et actualités CTI correspondant aux
filtres de veille. Tri : exploitée (KEV), puis EPSS ≥ 10 %, puis sévérité, puis EPSS.

## Choix

- **SQLite + SQL écrit à la main** : lisible, auditable, sans ORM.
- **Rendu serveur sans JavaScript** : surface d'attaque minimale, CSP `default-src 'none'`.
- **Statuts CycloneDX/VEX** : interopérabilité avec les SBOM.
- **Clé purl pour les SBOM** : seule identification fiable pour la correspondance avec OSV ; les
  composants sans purl sont comptés et ignorés.
- **Étiquetage CTI par source puis mots-clés** : simple et prévisible ; un NLP optionnel pourra
  venir plus tard sans être requis.
- **Peu de dépendances** : `modernc.org/sqlite`, `golang.org/x/crypto`, `golang.org/x/term`.
