# Vigil

Outil open source de **veille de sécurité** léger : un seul binaire, aucune infrastructure.

- Inventaire des actifs suivis (dépendances, technologies, produits, OS) avec version, purl, CPE.
- Détection des vulnérabilités via [OSV.dev](https://osv.dev) et suivi de leur traitement
  (statuts alignés sur CycloneDX / VEX, historique).
- Digest périodique consultable dans l'interface et exportable en Markdown.
- Fonctionne en local (par défaut sur `127.0.0.1`) ou en mode client / serveur (TLS, rôles).

> Statut : MVP. Feuille de route : NVD/CPE, CISA KEV, EPSS, veille CTI (RSS, filtres secteur/pays),
> webhooks Slack/Teams/Mattermost, import SBOM CycloneDX/SPDX.

## Démarrage

Prérequis pour compiler : Go (version indiquée dans `go.mod`).

```bash
go build -o vigil ./cmd/vigil
./vigil serve
```

Ouvrez <http://127.0.0.1:8080> : au premier lancement, la page de configuration crée le compte
administrateur (uniquement depuis la machine locale).

| Commande | Rôle |
|---|---|
| `vigil serve` | Interface web + synchronisation automatique (`-sync-interval 6h`) |
| `vigil sync` | Synchronisation ponctuelle avec OSV |
| `vigil digest` | Génère un digest et l'affiche en Markdown |
| `vigil user add -username bob -role analyst` | Crée un compte (mot de passe lu sans écho) |

La base SQLite est stockée dans le dossier de configuration de l'utilisateur ; `-db` ou la
variable `VIGIL_DB` permettent de la déplacer.

### Mode serveur

```bash
vigil serve -addr 0.0.0.0:8443 -tls-cert cert.pem -tls-key key.pem
# ou derrière un reverse proxy qui termine TLS :
vigil serve -addr 0.0.0.0:8080 -behind-proxy
```

Vigil refuse d'écouter sur une interface non locale sans TLS.

Rôles : `viewer` (lecture), `analyst` (inventaire, triage, synchro, digests), `admin`.

## Développement

```bash
go test ./...
go vet ./...
```

Voir [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) et [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0
