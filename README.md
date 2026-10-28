# Vigil

Outil open source de **veille de sécurité** léger : un seul binaire, aucune infrastructure.

- **Inventaire** des actifs suivis (dépendances, technologies, produits, OS) : saisie manuelle
  avec **recherche de CPE** dans le dictionnaire de la NVD (un produit, ou **tous les produits d'un
  éditeur**), **étiquettes libres** (équipe, environnement, site…), **import de SBOM** CycloneDX / SPDX
  (JSON) regroupés par projet, ou **import et export CSV** (tableur, Excel en français compris).
- **Vulnérabilités** détectées via [OSV.dev](https://osv.dev) pour les paquets (purl) et la
  [NVD](https://nvd.nist.gov) pour les produits identifiés par un CPE, enrichies par
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploitation avérée) et
  [FIRST EPSS](https://www.first.org/epss/) (probabilité d'exploitation), puis priorisées :
  KEV > EPSS élevé > sévérité.
- **Suivi** du traitement avec les statuts CycloneDX / VEX et un historique, triage par lot ;
  **délais de traitement** par sévérité avec indicateur « hors délai » ; résolution et réouverture
  automatiques quand une version change ; **export et import VEX** CycloneDX, export CSV.
- **Veille CTI** : flux RSS/Atom (CERT-FR, CISA, presse spécialisée… modifiables), étiquetés par
  **pays** et **secteur** (liste NIS2), avec filtres enregistrés ; **veille réglementaire** (NIS2,
  CRA, DORA, RGPD, AI Act, ISO 27001, SecNumCloud…) alimentée par des sources officielles (Commission
  européenne, CNIL, EDPB, EBA) et par la détection des réglementations citées dans tous les flux.
  Les actualités qui citent une vulnérabilité ouverte de l'inventaire sont signalées (« Vous concerne »).
- **Digest** périodique (vulnérabilités regroupées par éditeur et comptées par sévérité, retards,
  menaces filtrées) consultable dans l'interface,
  exportable en Markdown, et **alertes immédiates** dès qu'une vulnérabilité devient urgente
  (exploitée, probable, critique), par **e-mail** ou **webhook** Slack, Mattermost, Teams ou JSON.
- Fonctionne **en local** (par défaut sur `127.0.0.1`) ou **en mode client / serveur** (TLS, rôles,
  journal d'audit). Les **mises à jour conservent les données** : copie automatique de la base avant
  toute évolution de schéma.

Comparaison avec OpenCVE, Dependency-Track, DefectDojo, Vulnerability-Lookup et Taranis AI :
[docs/BENCHMARK.md](docs/BENCHMARK.md).

## Installation

Guide pas à pas par système (Windows, macOS, Linux, Docker), avec la partie réseau (reverse proxy,
pare-feu, proxy d'entreprise, flux sortants, e-mail) : **[docs/INSTALL.md](docs/INSTALL.md)**.

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

**Service systemd ou Docker Compose (avec HTTPS automatique par Caddy)** : fichiers prêts dans
[deploy/](deploy/), procédure dans [docs/OPERATIONS.md](docs/OPERATIONS.md).

**Docker** (image distroless, utilisateur non privilégié, données dans `/data`) :

```bash
docker run -d --name vigil -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil:0.3
docker exec -it vigil vigil user add -username admin -role admin
```

Dans un conteneur, et plus généralement derrière un reverse proxy (`-behind-proxy`), la page de
configuration est désactivée : le premier administrateur se crée en ligne de commande
(`vigil user add -username admin -role admin`, ici via `docker exec`). L'image écoute en
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

### Mettre à jour

Les données vivent hors du binaire (fichier SQLite, ou volume `/data` du conteneur) : remplacer le
binaire ou changer le tag de l'image les conserve. Au premier démarrage d'une nouvelle version,
Vigil écrit une copie de la base (`vigil.db.schema-N.<date>.bak`) avant de faire évoluer son schéma,
et refuse d'ouvrir une base créée par une version plus récente. Chaque version est testée sur de
vraies bases produites par les versions précédentes. Procédure par système :
[docs/INSTALL.md](docs/INSTALL.md#7-mettre-à-jour-en-conservant-les-données).

### Notifications

Dans **Paramètres → Canaux de notification**, chaque canal (webhook ou e-mail) reçoit les digests,
les alertes immédiates, ou les deux. L'e-mail demande un serveur SMTP :
`vigil serve -smtp-addr smtp.example.org:587 -smtp-from vigil@example.org -smtp-username …`, mot de
passe dans `VIGIL_SMTP_PASSWORD`. Les délais de traitement se règlent dans la même page.

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
veille), `admin` (flux CTI, webhooks et jetons d'API en plus). Chaque utilisateur peut activer la
**double authentification TOTP** dans « Mon compte » (recommandé en mode serveur) ; en cas de
téléphone perdu : `vigil user reset-totp -username NOM`.

### Paquets et produits : purl ou CPE

- Un **purl** (`pkg:npm/lodash@4.17.21`) est interrogé dans OSV : correspondance de version précise.
  Les SBOM en fournissent un par composant.
- Pour suivre **tous les produits d'un éditeur**, recherchez l'éditeur seul (« fortinet ») puis
  « Suivre tous les produits », ou saisissez `cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*`. Pour un grand
  éditeur (Microsoft, Google…), cela représente des milliers de vulnérabilités par an.
- La recherche signale les **anciens noms d'éditeur** (« ancien nom » : plus aucune version ajoutée
  depuis des années, comme `elasticsearch:elasticsearch` devenu `elastic:elasticsearch`) : préférez
  le nom actuel, proposé en premier, sans quoi aucune vulnérabilité récente ne remonte.
- Un **CPE** (`cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*`, à trouver avec « Trouver son CPE »
  dans l'inventaire) est interrogé dans la NVD quand l'actif n'a pas de purl.
  Le champ **Versions suivies dans la NVD** de l'actif choisit les versions concernées :
  - *version de l'actif* (défaut) : CVE affectant la version du CPE ou du champ Version ; un CPE
    sans version (`*`) suit toutes les versions ;
  - *toutes les versions du produit* ;
  - *à partir de la version X* : CVE affectant les versions ≥ X.
- **Période de suivi** : un nouvel actif (ajout manuel ou SBOM) remonte les vulnérabilités publiées
  dans les 120 jours précédant son ajout, puis toutes les nouvelles. Les plus anciennes ne sont
  signalées que si elles sont activement exploitées (CISA KEV). Videz la date de début de l'actif
  pour suivre tout l'historique.
- L'ajout ou la modification d'un actif lance aussitôt son analyse ; « Analyser cet actif » la
  relance, « Synchroniser l'inventaire » relance tout. L'état de la dernière synchronisation est
  affiché à côté.
- Un actif qui a un purl est interrogé dans OSV uniquement : son CPE est alors ignoré, il n'y a donc
  pas de doublon. Évitez en revanche de déclarer le même produit en deux actifs (un purl, un CPE).
- Sans clé, la NVD limite à 5 requêtes par 30 secondes : une clé gratuite
  (variable `VIGIL_NVD_API_KEY`) accélère la synchronisation des gros inventaires.

## Développement

```bash
go test ./...
go vet ./...
```

Pour publier une version, poussez un tag `vX.Y.Z` : le workflow `release` construit les binaires
avec [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) et l'image Docker, puis prépare
une release en brouillon à relire avant publication. Test local : `goreleaser release --snapshot --clean`.

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les contrôles exécutés en CI et en local.
Voir [docs/INSTALL.md](docs/INSTALL.md) (installation par système, réseau),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (architecture et arbitrages),
[docs/BENCHMARK.md](docs/BENCHMARK.md) (comparatif),
[docs/OPERATIONS.md](docs/OPERATIONS.md) (sauvegarde, restauration, mise à jour),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)
et [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0
