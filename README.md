# Vigil

Outil open source de **veille de sécurité** léger : un seul binaire, aucune infrastructure.

- **Inventaire** des actifs suivis (dépendances, technologies, produits, OS) : saisie manuelle
  ou **import de SBOM** CycloneDX / SPDX (JSON), regroupés par projet.
- **Vulnérabilités** détectées via [OSV.dev](https://osv.dev), enrichies par
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploitation avérée) et
  [FIRST EPSS](https://www.first.org/epss/) (probabilité d'exploitation), puis priorisées :
  KEV > EPSS élevé > sévérité.
- **Suivi** du traitement avec les statuts CycloneDX / VEX et un historique ; résolution et
  réouverture automatiques quand une version change.
- **Veille CTI** : flux RSS/Atom (CERT-FR, CISA, presse spécialisée… modifiables), étiquetés par
  **pays** et **secteur** (liste NIS2), avec filtres enregistrés.
- **Digest** périodique (vulnérabilités + menaces filtrées) consultable dans l'interface,
  exportable en Markdown et envoyé aux **webhooks** Slack, Mattermost, Teams ou JSON générique.
- Fonctionne **en local** (par défaut sur `127.0.0.1`) ou **en mode client / serveur** (TLS, rôles).

## Installation

**Binaires** : téléchargez l'archive de votre système (Linux, macOS, Windows ; amd64 ou arm64)
depuis les [releases](https://github.com/La-Cizaille-Corp/vigil/releases), puis vérifiez-la :

```bash
sha256sum --ignore-missing -c checksums.txt
gh attestation verify vigil_*_linux_amd64.tar.gz --repo La-Cizaille-Corp/vigil
```

Chaque archive est accompagnée de son SBOM CycloneDX et d'une attestation de provenance signée.

**Depuis les sources** (Go, version indiquée dans `go.mod`) :

```bash
go build -o vigil ./cmd/vigil
```

**Docker** (image distroless, utilisateur non privilégié, données dans `/data`) :

```bash
docker run -d --name vigil -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil
docker exec -it vigil vigil user add -username admin -role admin
```

Dans un conteneur, les requêtes ne viennent pas de `127.0.0.1` : le premier administrateur se
crée donc avec `docker exec` plutôt que par la page de configuration. L'image écoute en
`-behind-proxy` : exposez-la derrière un reverse proxy HTTPS (ou seulement sur `127.0.0.1`).

## Démarrage

```bash
./vigil serve
```

Ouvrez <http://127.0.0.1:8080> : au premier lancement, la page de configuration crée le compte
administrateur (uniquement depuis la machine locale). La synchronisation (vulnérabilités + CTI)
tourne au démarrage puis toutes les 6 heures.

| Commande | Rôle |
|---|---|
| `vigil serve` | Interface web, synchronisation (`-sync-interval 6h`) et digest automatiques (`-digest-interval 24h`) |
| `vigil sync` | Synchronisation ponctuelle : OSV, KEV, EPSS, flux CTI |
| `vigil digest` | Génère un digest, l'affiche en Markdown et l'envoie aux webhooks (`-no-webhooks` pour ne pas l'envoyer) |
| `vigil import-sbom -project app sbom.json` | Importe ou met à jour les composants d'un projet |
| `vigil user add -username bob -role analyst` | Crée un compte (mot de passe lu sans écho) |

La base SQLite est stockée dans le dossier de configuration de l'utilisateur ; `-db` ou la
variable `VIGIL_DB` permettent de la déplacer.

### Intégration continue

Générez un SBOM dans votre pipeline (par exemple avec `syft` ou `cdxgen`), puis :

```bash
vigil import-sbom -project mon-app sbom.cdx.json
```

Si Vigil tourne en mode serveur, le pipeline peut pousser le SBOM par l'API. Un administrateur crée
un jeton dans **Paramètres → Jetons d'API** ; chaque jeton n'autorise qu'un seul projet.

```bash
curl -fsS -X PUT -H "Authorization: Bearer $VIGIL_TOKEN" \
  --data-binary @sbom.cdx.json https://vigil.example.org/api/v1/projects/mon-app/sbom
```

La réponse JSON résume l'import et une synchronisation est lancée automatiquement.

Un nouvel import du même projet ajoute les nouveaux composants, retire les composants disparus et
conserve l'historique de suivi des composants inchangés.

### Mode serveur

```bash
vigil serve -addr 0.0.0.0:8443 -tls-cert cert.pem -tls-key key.pem -base-url https://vigil.example.org
# ou derrière un reverse proxy qui termine TLS :
vigil serve -addr 0.0.0.0:8080 -behind-proxy -base-url https://vigil.example.org
```

Vigil refuse d'écouter sur une interface non locale sans TLS. Les flux et webhooks ne peuvent
pas viser d'adresses privées ou locales, sauf avec `-allow-private-urls`.

Rôles : `viewer` (lecture), `analyst` (inventaire, triage, synchronisation, digests, filtres de
veille), `admin` (flux CTI et webhooks en plus).

## Développement

```bash
go test ./...
go vet ./...
```

Pour publier une version, poussez un tag `vX.Y.Z` : le workflow `release` construit les binaires
avec [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) et l'image Docker, puis prépare
une release en brouillon à relire avant publication. Test local : `goreleaser release --snapshot --clean`.

La CI exécute aussi `gofmt`, `staticcheck`, `govulncheck` et `gosec`.
Voir [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) et [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0
