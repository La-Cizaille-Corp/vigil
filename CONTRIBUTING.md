# Contribuer

## Flux de travail

- Une branche par changement, fusionnée dans `main` par pull request une fois la CI verte.
- Messages de commit en français, au présent, décrivant le pourquoi.
- Toute nouvelle dépendance est justifiée dans [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).
- Les points sensibles du code portent un commentaire `// SECURITY:` ; une exception à un outil
  d'analyse (`#nosec`) est toujours accompagnée de sa justification.
- Toute évolution de la surface d'attaque met à jour [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Tout choix structurant est consigné dans le registre des arbitrages de
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (décision, options écartées, conséquences).
- Une PR Dependabot n'est pas fusionnée « parce que la CI est verte » : lire le changelog et le
  diff de la dépendance, surtout pour `modernc.org/*`.

## Réutiliser avant d'écrire

Le code dérive quand chaque changement ajoute sa propre variante de ce qui existe déjà : l'audit de
la 0.4.2 a compté neuf façons de raccourcir un texte, dont trois coupaient un caractère, et
environ 25 copies de la même boucle de lecture SQL. Avant d'écrire une fonction, chaque changement
répond à ces questions, et sa PR dit ce qui a été réutilisé, étendu ou remplacé :

1. **Une fonction fait-elle déjà cela, ou presque ?** Chercher par ce qu'elle fait (les verbes, les
   types manipulés), pas seulement par son nom, d'abord dans les paquets communs (`clip`,
   `netsafe`, `chattext`, `store`, `tracking`, `auth`).
2. **Une fonction existante peut-elle évoluer** pour couvrir le nouveau cas (un paramètre, un type
   plus général) sans devenir un fourre-tout ? Alors on l'étend et on met à jour ses appelants,
   plutôt que d'écrire une voisine.
3. **Le changement crée-t-il une deuxième façon de faire** la même chose (valider une URL, mesurer
   un texte, journaliser une action, lire une requête) ? On n'en garde qu'une : la nouvelle
   remplace l'ancienne partout, ou elle n'est pas ajoutée.
4. **Un motif revient-il pour la troisième fois ?** Il devient une fonction commune, avec ses
   tests, dans le même changement.

## Contrôles

| Contrôle | Où | Bloquant |
|---|---|---|
| Tests (`-race` sous Linux) sur Linux, Windows, macOS | `ci.yml` | oui |
| `gofmt`, `go mod tidy`, `go mod verify`, `go vet` | `ci.yml` | oui |
| staticcheck, gosec, govulncheck (versions épinglées) | `ci.yml` | oui |
| Secrets dans tout l'historique (gitleaks, règle dédiée aux jetons `vgl_`) | `ci.yml` | oui |
| Revue des dépendances ajoutées (vulnérabilités, licences) | `ci.yml`, PR | oui |
| Nouvelles capacités d'un paquet (réseau, fichiers, exécution…) par rapport à la branche cible (capslock) | `ci.yml`, PR | oui ; une capacité légitime s'accepte en revue |
| Config GoReleaser, build Docker, Compose valide, scan de l'image (Trivy HIGH/CRITICAL corrigeables) | `ci.yml` | oui |
| SBOM CycloneDX du code source (artefact `sbom`) | `ci.yml` | — |
| CodeQL (Go et workflows GitHub Actions) | `codeql.yml` | alertes dans *Security* |
| OpenSSF Scorecard | `scorecard.yml` | alertes dans *Security* |
| Mises à jour des dépendances, actions et images | `dependabot.yml` | PR hebdomadaires, après 7 jours d'attente |
| Revue d'optimisation et de sécurité de tout le code ([ci-dessous](#revue-des-versions-xy0)) | avant chaque tag `vX.Y.0` | oui |

Les actions GitHub sont épinglées par SHA de commit, les images de base par digest et GoReleaser
par version exacte : une étiquette compromise ne peut pas changer ce qui construit une release.
L'image est compilée en croisé, sans émulateur QEMU. Dependabot propose les mises à jour, sauf pour
GoReleaser (`version:` dans `ci.yml` et `release.yml`), des images Trivy et gitleaks (`ci.yml`) et de
BuildKit (`release.yml`), épinglés par version ou digest et à monter à la main après 7 jours :
`crane digest image:tag` donne le digest.

En local :

```bash
gofmt -l .
go vet ./...
go test ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -quiet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

## Release

Pousser un tag `vX.Y.Z` sur `main` déclenche `release.yml` : binaires (GoReleaser), SBOM par
archive, checksums, attestations de provenance, image multi-architecture sur ghcr.io. La release
est créée en brouillon et publiée à la main après relecture.

### Revue des versions X.Y.0

La CI ne voit ni la duplication ni les défauts de conception. Avant de taguer une version mineure
ou majeure (`vX.Y.0`), tout le code de `main` est donc relu sur deux axes :

- **Optimisation et rationalisation** : fonctions en double ou presque, variantes d'une même
  opération, code mort, requêtes répétées ou sans index, tests redondants. Chaque constat propose
  la forme commune et liste les endroits où elle s'applique, selon la règle « Réutiliser avant
  d'écrire ».
- **Sécurité** : authentification, rôle et jeton CSRF de chaque route ; entrées et sorties
  (OWASP ASVS et Top 10) ; secrets dans les journaux, les erreurs et les URL ; limites de taille
  et de débit ; SSRF ; dépendances. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) est mis à jour.

Chaque constat est corrigé avant le tag, ou consigné : décision dans le registre de
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), ou lot prévu pour une version suivante. Aucune
version X.Y.0 ne sort avec un constat de sécurité non tranché. La PR de documentation de la version
résume la revue : nombre de constats, corrigés, reportés et pourquoi.

Une version corrective (`vX.Y.Z`, Z > 0) n'y est pas soumise : elle ne corrige que ce qui doit
l'être, et la règle « Réutiliser avant d'écrire » s'applique à ses changements.

## Schéma de la base

Les données des utilisateurs doivent survivre à chaque mise à jour (registre A36 de
[ARCHITECTURE.md](docs/ARCHITECTURE.md)) :

- toute évolution passe par une **nouvelle** migration `internal/store/migrations/NNN_description.sql` ;
  une migration publiée ne se modifie jamais (`TestMigrationsFrozen`) ;
- une migration ne supprime pas de donnée utilisateur ; une transformation voulue se déclare dans
  la liste `transformed` de `internal/store/upgrade_test.go` ;
- une transformation impossible en SQL s'écrit en Go dans `afterMigration` (`store.go`), dans la
  même transaction.

À chaque release, après publication :

1. ajouter les empreintes des nouvelles migrations à `releasedMigrations` (`upgrade_test.go`) ;
2. produire avec le binaire publié une base de démonstration (comptes, import SBOM, synchronisation,
   triage, flux, canal de notification, digest), la réduire, et l'ajouter en
   `internal/store/testdata/upgrade/vX.Y.Z.sql` (`sqlite3 base.db .dump`) : `TestUpgradeFromReleases`
   vérifiera ensuite que chaque version future la reprend sans perte. Jusqu'à la migration suivante,
   cette base est seulement rouverte (aucune copie de mise à niveau n'est attendue).

Sous Windows, n'envoyez pas les formulaires du scénario avec `curl` en ligne de commande : il
convertit les arguments dans la page de codes du système et les textes accentués arrivent en
Latin-1 dans la base. Un petit script Python (`urllib`, UTF-8) convient.
