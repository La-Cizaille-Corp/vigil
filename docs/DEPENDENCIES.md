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

Contrôles : `govulncheck` en CI, `go.sum` vérifié (`go mod verify`) avant chaque release.
