# Architecture

Un binaire Go unique, sans CGO, embarquant les migrations SQL, les templates et la feuille de style.

```
cmd/vigil            CLI : serve, sync, digest, user add
internal/store       SQLite (modernc.org/sqlite), migrations, toutes les requêtes SQL
internal/inventory   Validation et normalisation des actifs
internal/sources/osv Client de l'API OSV.dev
internal/tracking    Synchronisation inventaire ↔ sources, statuts VEX
internal/digest      Génération du digest (Markdown + HTML)
internal/auth        argon2id, jetons, limitation des tentatives, rôles
internal/web         Handlers HTTP, middleware de sécurité, templates
```

## Flux de synchronisation

1. `tracking.Syncer` liste les actifs interrogeables (purl ou écosystème + version).
2. Une requête `querybatch` OSV renvoie les identifiants de vulnérabilités par actif.
3. Chaque avis inconnu ou modifié est téléchargé et stocké (`vulnerabilities`).
4. `findings` : création si nouveau, réouverture si résolu automatiquement puis signalé à nouveau,
   résolution automatique si la source ne le signale plus (ex. version mise à jour).
5. Chaque changement de statut est historisé dans `finding_events`.

## Choix

- **SQLite + SQL écrit à la main** : lisible, auditable, sans ORM.
- **Rendu serveur sans JavaScript** : surface d'attaque minimale, CSP `default-src 'none'`.
- **Statuts CycloneDX/VEX** : interopérabilité avec l'import SBOM prévu.
- **Peu de dépendances** : `modernc.org/sqlite`, `golang.org/x/crypto`, `golang.org/x/term`.
