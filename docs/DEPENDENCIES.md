# Dépendances

Vigil privilégie la bibliothèque standard de Go (`net/http`, `html/template`, `database/sql`,
`log/slog`, `embed`, `crypto/*`). Chaque dépendance directe est justifiée ci-dessous ; toute
nouvelle dépendance doit l'être aussi.

| Module | Usage | Pourquoi pas la bibliothèque standard |
|---|---|---|
| `modernc.org/sqlite` | Base SQLite | Pilote en Go pur : binaire statique sans CGO, compilation croisée simple. Les autres pilotes (`mattn/go-sqlite3`) exigent CGO. |
| `golang.org/x/crypto` | Hachage argon2id des mots de passe | argon2 n'est pas dans la bibliothèque standard ; module maintenu par l'équipe Go. |
| `golang.org/x/term` | Saisie du mot de passe sans écho (`vigil user add`) | Pas d'équivalent portable dans la bibliothèque standard. |

Les dépendances indirectes viennent de `modernc.org/sqlite` (runtime C traduit en Go), sauf
`golang.org/x/sys`, que `x/crypto` et `x/term` requièrent aussi.

**Alerte connue de govulncheck : GO-2026-5932** (`golang.org/x/crypto/openpgp`, paquet non
maintenu). Elle est signalée au niveau du module seulement : Vigil n'importe de `x/crypto` que
`argon2` (et `blake2b`, qu'il emploie), et `openpgp` n'est pas lié au binaire (`go list -deps ./...`).
govulncheck sort donc sans erreur. Pas d'action : la prochaine version étiquetée de `x/crypto`,
proposée par Dependabot, fera disparaître l'alerte (revue de la 0.5.0, C7).

Implémentés sans dépendance, volontairement :
- **TOTP** (RFC 6238) : une trentaine de lignes, testées avec les vecteurs de la RFC ;
- **parsing CycloneDX / SPDX / VEX et RSS / Atom** : `encoding/json` et `encoding/xml` suffisent
  pour le sous-ensemble utilisé ;
- **clients OSV, NVD, KEV, EPSS** : simples appels HTTP JSON.

Chaque dépendance n'est importée que par **un seul fichier** (`internal/store/store.go`,
`internal/auth/auth.go`, `cmd/vigil/main.go`) : la remplacer ne touche pas au reste du code.

## Données tierces embarquées

Une donnée embarquée n'est pas un module Go : ni `go.sum` ni govulncheck ne la suivent. Sa
provenance est donc consignée ici, avec de quoi la vérifier.

**Mots de passe les plus courants** (`internal/auth/common-passwords.txt`, registre A77) : les
mots de passe refusés à l'installation, sur « Mon compte » et par `vigil user`.

| | |
|---|---|
| Source | [SecLists](https://github.com/danielmiessler/SecLists), commit `feeac159932a4bf1d0155e8c3a7412e9d1cec3fc`, fichier `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt` (empreinte git `e5e73232c8f4f53edfe9c0fd699f415da8a336e3`) |
| Extraction | dans l'ordre du fichier, du plus courant au moins courant, les 3 000 premiers de 12 caractères ou plus (`auth.MinPasswordLength`), passés en minuscules et dédoublonnés ; sur le million de lignes, 46 296 font 12 caractères ou plus |
| Fichier embarqué | 3 000 lignes, ASCII, 41,7 Ko ; SHA-256 `eb76ae50d86aeddabb99f6b5d7f9a0613d354d1824804e394744b32d7bd6a8e6` |
| Licence | MIT, « Copyright (c) 2018 Daniel Miessler » : texte complet dans `internal/auth/SECLISTS-LICENSE.txt`, joint à la racine de chaque archive de release (`.goreleaser.yaml`) et dans l'image Docker (`/usr/share/doc/vigil/`, avec la licence de Vigil) |
| Contrôle | `TestCommonPasswordsList` : 3 000 entrées distinctes, en minuscules, aucune de moins de 12 caractères, aucune de la forme d'un mot de passe provisoire |

Les mots de passe les plus courants changent peu : la liste se met à jour à la main, rarement, en
refaisant l'extraction depuis un commit de SecLists et en reportant ici le commit et les empreintes.

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
