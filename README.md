# Vigil

Outil open source de **veille de sécurité** léger : un seul binaire, aucune infrastructure.

- **Inventaire** des actifs suivis (dépendances, technologies, produits, OS) : saisie manuelle
  avec **recherche de CPE** dans le dictionnaire de la NVD (un produit, ou **tous les produits d'un
  éditeur**), **étiquettes libres** (équipe, environnement, site…), **import de SBOM** CycloneDX / SPDX
  (JSON) regroupés par projet, ou **import et export CSV** (tableur, Excel en français compris).
- **Vulnérabilités** détectées via [OSV.dev](https://osv.dev) pour les paquets (purl) et la
  [NVD](https://nvd.nist.gov) pour les produits identifiés par un CPE, ou à défaut par leur nom ;
  version **`latest`** pour un actif toujours à jour (seules les failles sans correctif sont
  signalées). Elles sont enrichies par
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploitation avérée) et
  [FIRST EPSS](https://www.first.org/epss/) (probabilité d'exploitation), puis classées en quatre
  niveaux : Urgentes, À planifier, À surveiller, Écartées. La liste s'ouvre sur ce qui reste à traiter, et
  les tableaux se trient par colonne.
- **Suivi** du traitement avec les statuts CycloneDX / VEX et un historique, triage par lot ;
  **règles pour écarter** ce qui ne concerne pas un actif (`wifi:` sur un serveur sans Wi-Fi) ;
  **délais de traitement** par sévérité avec indicateur « hors délai » ; résolution et réouverture
  automatiques quand une version change ; **version corrigée** indiquée sur chaque vulnérabilité, en
  colonne des tableaux comme dans l'export CSV ;
  **export et import VEX** CycloneDX, export CSV. Un composant absent d'un nouveau SBOM est retiré
  sans perdre son historique.
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
docker run -d --name vigil -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil:0.4
docker exec -it vigil vigil user add -username admin -role admin
```

Gardez `-v vigil-data:/data` : c'est ce volume nommé qui conserve la base d'une version à l'autre.

Dans un conteneur, et plus généralement derrière un reverse proxy (`-behind-proxy`), la page de
configuration est désactivée : le premier administrateur se crée en ligne de commande
(`vigil user add -username admin -role admin`, ici via `docker exec`). L'image écoute en
`-behind-proxy` : exposez-la derrière un reverse proxy HTTPS (ou seulement sur `127.0.0.1`).

## Démarrage

```bash
./vigil serve
```

Ouvrez <http://127.0.0.1:8080> : au premier lancement, la page de configuration crée le compte
administrateur (uniquement depuis la machine locale). La synchronisation des vulnérabilités tourne
au démarrage puis toutes les 6 heures ; les flux de veille sont collectés au démarrage puis 4 fois par
jour, fréquence réglable dans **Paramètres → Flux de veille**.

| Commande | Rôle |
|---|---|
| `vigil serve` | Interface web, synchronisation des vulnérabilités (`-sync-interval 6h`), collecte des flux (fréquence dans Paramètres, 4 fois par jour par défaut) et digest automatiques (`-digest-interval 24h`) |
| `vigil sync` | Synchronisation ponctuelle : OSV, KEV, EPSS, flux CTI |
| `vigil digest` | Génère un digest, l'affiche en Markdown et l'envoie aux webhooks (`-no-webhooks` pour ne pas l'envoyer) |
| `vigil import-sbom -project app sbom.json` | Importe ou met à jour les composants d'un projet |
| `vigil user add -username bob -role analyst` | Crée un compte (mot de passe lu sans écho) |
| `vigil user list` / `disable` / `enable` / `set-role` / `reset-password` | Gère les comptes en ligne de commande (aussi dans Paramètres → Utilisateurs) |

La base SQLite est stockée dans le dossier de configuration de l'utilisateur ; `-db` ou la
variable `VIGIL_DB` permettent de la déplacer.

### Mettre à jour

Les données vivent hors du binaire (fichier SQLite, ou volume `/data` du conteneur) : remplacer le
binaire ou changer le tag de l'image les conserve. Au premier démarrage d'une nouvelle version,
Vigil écrit une copie de la base (`vigil.db.schema-N.<date>.bak`) avant de faire évoluer son schéma,
et refuse d'ouvrir une base créée par une version plus récente. Chaque version est testée sur de
vraies bases produites par les versions précédentes. Procédure pas à pas, poste local et
serveur, et ce qui change de la 0.3 à la 0.4 : [docs/MISE_A_JOUR.md](docs/MISE_A_JOUR.md).

### Notifications

Dans **Paramètres → Canaux de notification**, chaque canal (webhook ou e-mail) reçoit les digests,
les alertes immédiates, ou les deux. L'e-mail demande un serveur SMTP :
`vigil serve -smtp-addr smtp.example.org:587 -smtp-from vigil@example.org -smtp-username …`, mot de
passe dans `VIGIL_SMTP_PASSWORD`. Les délais de traitement se règlent dans la même page.
« Envoyer un test » vérifie un canal sans attendre une alerte, et son état indique la raison d'un refus.

Teams : créez un workflow « Publier dans un canal lors de la réception d'une requête webhook » dont
le déclencheur accepte **« Tout le monde »**. Un workflow réservé aux utilisateurs du tenant répond 401,
car un webhook n'a pas de jeton Microsoft. Si votre organisation l'impose, le canal e-mail peut viser
l'adresse e-mail du canal Teams.

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
veille), `admin` (flux CTI, webhooks, jetons d'API et comptes en plus). Les administrateurs gèrent
les comptes dans **Paramètres → Utilisateurs** : création avec mot de passe provisoire, rôle,
désactivation d'un départ (sessions fermées aussitôt, historique conservé). Chaque utilisateur
peut activer la **double authentification TOTP** dans « Mon compte » (recommandé en mode serveur) ;
en cas de téléphone perdu, un administrateur la retire dans Paramètres → Utilisateurs ou avec
`vigil user reset-totp -username NOM` (`-all` pour tous les comptes, après une fuite de la base).

### Paquets et produits : purl, CPE ou nom

- Un **purl** (`pkg:npm/lodash@4.17.21`) est interrogé dans OSV : correspondance de version précise.
  Les SBOM en fournissent un par composant. Pour mettre à jour un actif, changez le champ **Version** :
  s'il diffère de la version écrite dans le purl, c'est lui qui est vérifié. Si vous ne changez que la
  version du purl, le champ Version la reprend.
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
  signalées que si elles sont activement exploitées (CISA KEV) ; leur nombre est affiché sur l'actif,
  avec un bouton « Suivre tout l'historique ».
- L'ajout ou la modification d'un actif lance aussitôt son analyse ; « Analyser cet actif » la
  relance, « Synchroniser l'inventaire » relance tout. L'avancement (actifs vérifiés, barre) et le
  résultat de la dernière synchronisation sont affichés à côté, avec les actifs qui n'ont pas pu être
  vérifiés : ils gardent leurs vulnérabilités jusqu'à la prochaine.
- **Classement des vulnérabilités**, le même pour tous les produits : **Urgentes** (exploitées d'après
  CISA KEV, ou probables d'après EPSS ≥ 10 %), **À planifier** (sévérité critique ou haute), **À surveiller**
  (le reste, y compris sans score) et **Écartées** (non affecté ou faux positif). Les corrigées sortent du
  classement. Ce sont les mêmes seuils que les alertes.
- **Écarter ce qui ne vous concerne pas** : sur la page d'un actif, cherchez un texte (`wifi:` sur un
  serveur sans Wi-Fi), vérifiez la liste, puis « Écarter tout ce qui correspond sur cet actif ». Elles passent
  en « Non affecté », les prochaines aussi. Les vulnérabilités exploitées ou probables restent visibles, et
  y reviennent si elles le deviennent ; une décision prise par quelqu'un n'est jamais changée. Supprimer
  la règle remet ses vulnérabilités à analyser.
- Les tableaux de l'inventaire et des vulnérabilités se **trient en cliquant sur le titre d'une
  colonne**, qui inverse l'ordre au second clic ; l'export CSV des vulnérabilités suit le même ordre.
- **Sans purl ni CPE**, Vigil cherche le **nom de l'actif** dans les descriptions des CVE de la NVD
  (« Ivanti Connect Secure », « FortiOS » : le nom employé par l'éditeur dans ses avis). Une CVE déjà
  analysée par la NVD n'est gardée que si ses produits correspondent au nom, à la version de l'actif
  (une CVE qui cite seulement le nom, comme Shellshock pour Apache HTTP Server, est écartée) ; une
  CVE en attente d'analyse est gardée. Moins précise qu'un CPE, cette détection donne des résultats
  à vérifier ; elle ne s'applique pas aux composants de SBOM sans purl. Le nom est envoyé à la NVD :
  n'y mettez pas d'information interne.
- **Version `latest`** : l'actif est tenu à jour sur la dernière version publiée (mises à jour
  automatiques, service en ligne). Seules les vulnérabilités **sans version corrigée connue** sont
  signalées : plage OSV encore ouverte ou affectée « jusqu'à » une version sans correctif ; dans la
  NVD, produit affecté sans borne haute (« jusqu'à 7.2.13 » y vaut correction dans la suivante, comme
  dans les bulletins des éditeurs). Dès que la source indique un correctif, la vulnérabilité est
  marquée corrigée. Valable avec un purl, un écosystème, un CPE ou le nom.
- **Paquets de distribution** : précisez la version de la distribution (écosystème `Debian:12`,
  `Ubuntu:24.04:LTS`, `Alpine:v3.22`, `AlmaLinux:9`… ou `?distro=debian-12` dans le purl) et nommez le
  paquet source (`openssl`, pas `libssl3`). Sans version de distribution, la version de l'actif est
  comparée aux avis de toutes les autres : pour le noyau Debian, le résultat ne bouge plus quand on
  applique les correctifs. Alpine ne répond même rien sans elle. Les SBOM de Syft et de Trivy donnent
  le paquet source ; Vigil le lit.
- **Noyau Linux** : c'est un paquet comme un autre. `linux` dans `Debian:12` ou `Ubuntu:24.04:LTS`,
  `kernel` dans `AlmaLinux:9` ou `Rocky Linux:9`, avec la version du paquet : c'est la voie exacte, qui
  tient compte des correctifs reportés par la distribution. Pour le noyau officiel, choisissez
  l'écosystème `Linux` et sa version : les versions touchées viennent de kernel.org. Chaque
  synchronisation relit alors tous ses avis (environ 150 Mo, 3 minutes), une seule fois quel que soit
  le nombre d'actifs. Un CPE `linux_kernel` ne voit que les CVE déjà analysées par la NVD, une petite
  partie d'entre elles ; un actif seulement nommé « Linux Kernel » remonte des milliers de résultats
  à vérifier.
- Un actif qui a un purl est interrogé dans OSV uniquement : son CPE est alors ignoré, il n'y a donc
  pas de doublon. Évitez en revanche de déclarer le même produit en deux actifs (un purl, un CPE).
- Sans clé, la NVD limite à 5 requêtes par 30 secondes : une clé gratuite
  (variable `VIGIL_NVD_API_KEY`) accélère la synchronisation des gros inventaires, surtout avec
  beaucoup d'actifs suivis par CPE ou par leur nom.

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
