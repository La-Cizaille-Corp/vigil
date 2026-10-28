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

Les actions GitHub sont épinglées par SHA de commit et les images de base par digest :
une étiquette compromise ne peut pas changer ce qui s'exécute. Dependabot propose les mises à jour.

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
   vérifiera ensuite que chaque version future la reprend sans perte.
