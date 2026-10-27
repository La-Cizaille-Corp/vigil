# Dépendances

Vigil privilégie la bibliothèque standard de Go (`net/http`, `html/template`, `database/sql`,
`log/slog`, `embed`, `crypto/*`). Chaque dépendance directe est justifiée ci-dessous ; toute
nouvelle dépendance doit l'être aussi.

| Module | Usage | Pourquoi pas la bibliothèque standard |
|---|---|---|
| `modernc.org/sqlite` | Base SQLite | Pilote en Go pur : binaire statique sans CGO, compilation croisée simple. Les autres pilotes (`mattn/go-sqlite3`) exigent CGO. |
| `golang.org/x/crypto` | Hachage argon2id des mots de passe | argon2 n'est pas dans la bibliothèque standard ; module maintenu par l'équipe Go. |
| `golang.org/x/term` | Saisie du mot de passe sans écho (`vigil user add`) | Pas d'équivalent portable dans la bibliothèque standard. |

Les dépendances indirectes viennent toutes de `modernc.org/sqlite` (runtime C traduit en Go).

Implémentés sans dépendance, volontairement :
- **TOTP** (RFC 6238) : une trentaine de lignes, testées avec les vecteurs de la RFC ;
- **parsing CycloneDX / SPDX / VEX et RSS / Atom** : `encoding/json` et `encoding/xml` suffisent
  pour le sous-ensemble utilisé ;
- **clients OSV, NVD, KEV, EPSS** : simples appels HTTP JSON.

Chaque dépendance n'est importée que par **un seul fichier** (`internal/store/store.go`,
`internal/auth/auth.go`, `cmd/vigil/main.go`) : la remplacer ne touche pas au reste du code.

## Évaluation des risques

| Dépendance | Risque | Raison |
|---|---|---|
| `golang.org/x/crypto`, `golang.org/x/term` | Faible | Maintenues et revues par l'équipe Go, très utilisées. |
| `modernc.org/sqlite` (+ `libc`, `mathutil`, `memory`…) | **À surveiller** | Essentiellement un seul mainteneur ; code C transpilé, volumineux et non relisible à la main ; plus gros volume de code tiers du binaire. |
| Indirectes (`go-humanize`, `uuid`, `isatty`, `bigfft`…) | Faible | Petites, stables, n'arrivent que par `modernc.org/sqlite`. |

## Plan B pour SQLite

Si `modernc.org/sqlite` devenait non maintenu ou compromis :

1. **`github.com/ncruces/go-sqlite3`** (préféré) : SQLite officiel compilé en WebAssembly et exécuté
   en Go pur ; garde le binaire statique et la compilation croisée.
2. **`github.com/mattn/go-sqlite3`** : le plus répandu, mais exige CGO (compilation croisée et
   image distroless plus complexes).

Le changement tient dans `internal/store/store.go` (import et nom du pilote dans `sql.Open`, syntaxe
des `_pragma` dans le DSN). Le SQL est du SQLite standard. Les tests de `internal/store`
(`contract_test.go` notamment) fixent le comportement attendu et servent de filet de sécurité ;
les bases existantes restent lisibles (même format de fichier SQLite).

## Défenses de la chaîne d'approvisionnement

| Menace | Défense |
|---|---|
| Version republiée avec un autre contenu | `go.sum` + base de checksums publique de Go ; `go mod verify` en CI. |
| Mise à jour silencieuse | Impossible avec Go (sélection de version minimale) : seule une modification de `go.mod` change une version. |
| Version malveillante publiée puis proposée | Dependabot attend 7 jours (30 pour une version majeure) avant de la proposer ; revue de la PR. |
| Dépendance qui gagne un accès nouveau (réseau, fichiers, exécution) | Job `capabilities` (capslock) : échoue si un paquet obtient une capacité absente de la branche cible. |
| Vulnérabilité connue | govulncheck (bloquant, ne signale que le code réellement appelé), revue des dépendances, alertes Dependabot. |
| Action GitHub ou image compromise | Actions épinglées par SHA de commit, images de base par digest. |

## En cas de compromission annoncée d'une dépendance

1. Identifier les versions touchées et vérifier `go.mod` / `go.sum` ; consulter le SBOM des releases
   pour savoir lesquelles l'embarquent.
2. Revenir à une version saine (ou appliquer le plan B), publier une release corrective et
   l'annoncer (avis de sécurité GitHub, voir SECURITY.md).
3. Si une release compromise a été publiée : la marquer comme telle, indiquer les actions côté
   utilisateurs (mise à jour, rotation des jetons d'API et des URL de webhooks, vérification du
   journal d'audit).

Contrôles : `govulncheck` en CI, `go.sum` vérifié (`go mod verify`) en CI et avant chaque release.
