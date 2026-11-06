# Mettre à jour Vigil

Vos données (inventaire, triage, comptes, réglages) sont dans la base, à part du programme : une
mise à jour remplace le programme et garde la base. Au premier démarrage de la nouvelle version,
Vigil copie la base à côté d'elle avant de la faire évoluer. Comptez une dizaine de minutes.

## En bref

1. **Lire les notes de version** de la version à installer.
2. **Télécharger et vérifier** la nouvelle version, sans l'installer encore.
3. **Arrêter Vigil**, tous ses processus, y compris ce qui le relance tout seul.
4. **Sauvegarder** la base.
5. **Remplacer** le programme (ou l'image Docker), puis **relancer**.
6. **Vérifier** que tout fonctionne. Sinon : [revenir en arrière](#revenir-en-arrière).

Les commandes de chaque cas sont plus bas :

| Vous utilisez Vigil… | Section |
|---|---|
| sur votre poste, sous Windows, macOS ou Linux | [Poste local](#poste-local) |
| sur votre poste, dans Docker | [Poste local : Docker](#docker-docker-run) |
| sur un serveur Linux (service systemd) | [Serveur Linux](#serveur-linux-systemd) |
| sur un serveur Windows (tâche planifiée) | [Serveur Windows](#serveur-windows-tâche-planifiée) |
| sur un serveur avec Docker Compose | [Serveur Docker Compose](#serveur-docker-compose) |

## De la 0.3 à la 0.4

La procédure est la même, et **la base est conservée** : inventaire, triage et historique, comptes,
canaux, jetons et réglages. Au premier démarrage, elle passe du schéma 12 au schéma 14 : une table et
une colonne pour les règles d'écart, un index et un flux de veille. Rien n'est supprimé.

- **Fichiers de déploiement** : rien à reprendre. L'unité systemd, le `Caddyfile`, le
  `docker-compose.yml` et votre `.env` restent valables. Sous Compose, changez seulement le tag de
  l'image (`0.3` → `0.4`).
- **Proxy d'entreprise** : autorisez `thehackernews.com`, nouveau flux par défaut.
- **Place** : gardez libre au moins deux fois la taille de la base ([détail](OPERATIONS.md#place-à-prévoir)).

Après la mise à jour :

1. **Précisez la version de vos distributions.** Passez vos actifs de `Debian` à `Debian:12`, de
   `Ubuntu` à `Ubuntu:22.04:LTS`, d'`Alpine` à `Alpine:v3.20`… Sans cela, la version est comparée aux
   avis de toutes les versions de la distribution : beaucoup de faux positifs, et rien pour Alpine.
   La page de l'actif le signale. Le triage déjà fait sur ces actifs est conservé.
2. **Attendez-vous à du volume.** Un noyau n'était pas détecté correctement en 0.3 : il peut remonter
   des milliers de vulnérabilités à la première synchronisation, qui peut prendre une vingtaine de
   minutes avec un noyau Ubuntu. Commencez par le niveau « Urgentes », et écartez ce que vous n'utilisez pas
   (page de l'actif). Les alertes restent groupées : un message par canal et par niveau.
3. **Actifs sans identifiant** : un actif sans purl, sans CPE ni écosystème est désormais cherché par
   son nom dans la NVD. Ce nom sort donc de chez vous : retirez-en toute information interne avant de
   mettre à jour.
4. **Fréquence des actualités** : elle se règle désormais dans Paramètres (4 fois par jour par défaut).
   `-sync-interval` ne concerne plus que les vulnérabilités, mais `0` coupe toujours les deux.

## 1. Avant de commencer

- Lisez les [notes de version](https://github.com/La-Cizaille-Corp/vigil/releases) : elles
  signalent ce qui change pour vous (par exemple : se reconnecter, fichier de déploiement à
  reprendre).
- En mode serveur, prévenez les utilisateurs : l'interface est indisponible une ou deux minutes.
- Gardez libre au moins deux fois la taille de la base : sauvegarde, puis copie automatique. Si la
  place manque, Vigil s'arrête sans rien modifier.
- Mettez en pause ce qui lance `vigil` de lui-même en dehors du service : tâche cron ou planifiée
  (`vigil sync`, `vigil digest`), pipeline qui envoie des SBOM. Pendant la mise à jour, aucun autre
  processus `vigil` ne doit utiliser la base.

## 2. Télécharger et vérifier la nouvelle version

Remplacez `0.4.0` par la version à installer. Le programme est extrait dans un dossier à part : il
ne remplace encore rien.

**Windows** (PowerShell) :

```powershell
$v = "0.4.0"; $arch = "amd64"   # arm64 sur processeur ARM
$zip = "vigil_${v}_windows_$arch.zip"
$base = "https://github.com/La-Cizaille-Corp/vigil/releases/download/v$v"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest "$base/$zip" -OutFile $zip
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt
$line = Select-String -Path checksums.txt -Pattern ("\s" + [regex]::Escape($zip) + "$")
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne ($line.Line -split "\s+")[0]) { throw "Empreinte invalide : n'utilisez pas ce fichier." }
Unblock-File $zip
Expand-Archive $zip -DestinationPath ".\vigil-$v" -Force
```

**macOS** :

```bash
VERSION=0.4.0; ARCH=arm64   # amd64 sur Mac Intel
BASE=https://github.com/La-Cizaille-Corp/vigil/releases/download/v$VERSION
curl -fsSLO $BASE/vigil_${VERSION}_darwin_$ARCH.tar.gz
curl -fsSLO $BASE/checksums.txt
grep " vigil_${VERSION}_darwin_$ARCH.tar.gz$" checksums.txt | shasum -a 256 -c
mkdir -p vigil-$VERSION && tar -xzf vigil_${VERSION}_darwin_$ARCH.tar.gz -C vigil-$VERSION vigil
xattr -d com.apple.quarantine vigil-$VERSION/vigil 2>/dev/null || true
```

**Linux** :

```bash
VERSION=0.4.0; ARCH=amd64   # arm64 sur ARM
BASE=https://github.com/La-Cizaille-Corp/vigil/releases/download/v$VERSION
curl -fsSLO $BASE/vigil_${VERSION}_linux_$ARCH.tar.gz
curl -fsSLO $BASE/checksums.txt
sha256sum --ignore-missing -c checksums.txt
mkdir -p vigil-$VERSION && tar -xzf vigil_${VERSION}_linux_$ARCH.tar.gz -C vigil-$VERSION vigil
```

Avec Docker, rien à télécharger : l'image est récupérée à l'étape de remplacement.

## Poste local

### Windows

1. **Arrêter** : `Ctrl+C` dans la fenêtre où Vigil tourne. Puis vérifiez qu'il ne reste aucun
   processus (sinon, la deuxième ligne l'arrête) :

   ```powershell
   Get-Process vigil -ErrorAction SilentlyContinue
   Stop-Process -Name vigil -ErrorAction SilentlyContinue
   ```

2. **Sauvegarder** :

   ```powershell
   & "C:\Program Files\Vigil\vigil.exe" backup -o "$HOME\vigil-avant-maj-$(Get-Date -Format yyyyMMdd-HHmm).db"
   ```

3. **Remplacer** (PowerShell **administrateur**, dans le dossier du téléchargement) :

   ```powershell
   Copy-Item ".\vigil-$v\*" "C:\Program Files\Vigil" -Recurse -Force
   ```

4. **Relancer** : `& "C:\Program Files\Vigil\vigil.exe" serve`, puis [vérifier](#vérifier).

### macOS

1. **Arrêter** :
   - lancé dans un terminal : `Ctrl+C` ;
   - lancé au démarrage de la session (LaunchAgent) : `launchctl bootout gui/$(id -u)/org.lacizaille.vigil`
     (un simple arrêt ne suffit pas : launchd le relancerait).

   `pgrep -lx vigil` ne doit plus rien afficher ; sinon `pkill -x vigil` l'arrête proprement.

2. **Sauvegarder** :

   ```bash
   vigil backup -o ~/vigil-avant-maj-$(date +%Y%m%d-%H%M).db
   ```

3. **Remplacer** :

   ```bash
   sudo install -m 0755 vigil-$VERSION/vigil /usr/local/bin/vigil
   ```

4. **Relancer** : `vigil serve` dans un terminal, ou pour le LaunchAgent :
   `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.lacizaille.vigil.plist`.
   Puis [vérifier](#vérifier).

### Linux

1. **Arrêter** : `Ctrl+C` dans le terminal de Vigil. `pgrep -lx vigil` ne doit plus rien
   afficher ; sinon `pkill -x vigil` l'arrête proprement.
2. **Sauvegarder** :

   ```bash
   vigil backup -o ~/vigil-avant-maj-$(date +%Y%m%d-%H%M).db
   ```

3. **Remplacer** le programme que vous lancez d'habitude (ici, celui trouvé dans le `PATH`) :

   ```bash
   sudo install -m 0755 vigil-$VERSION/vigil "$(command -v vigil)"
   ```

4. **Relancer** : `vigil serve`, puis [vérifier](#vérifier).

### Docker (`docker run`)

Vérifiez d'abord que la base est dans un volume nommé. Cette commande doit afficher `vigil-data` :

```bash
docker inspect vigil --format '{{range .Mounts}}{{.Name}} -> {{.Destination}}{{end}}'
```

Si elle affiche une longue suite de chiffres et de lettres, le conteneur a été créé sans `-v` :
remplacez `vigil-data` par ce nom dans la commande `docker run` ci-dessous, sinon le nouveau conteneur
repartirait d'une base vide.

```bash
docker exec vigil vigil backup -o /data/backups/avant-maj-$(date +%Y%m%d-%H%M).db   # sauvegarder (Vigil tourne encore)
docker stop vigil && docker rm vigil       # arrêter ; le volume vigil-data, qui contient la base, reste
docker pull ghcr.io/la-cizaille-corp/vigil:0.4   # changez 0.4 pour passer à une nouvelle version mineure
docker run -d --name vigil --restart unless-stopped -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil:0.4
docker logs --tail 20 vigil
```

Puis [vérifier](#vérifier).

## Serveur

### Serveur Linux (systemd)

```bash
sudo systemctl stop vigil                     # arrêter
sudo -u vigil VIGIL_DB=/var/lib/vigil/vigil.db vigil backup -o /var/lib/vigil/backups/avant-maj-$(date +%Y%m%d-%H%M).db
sudo install -m 0755 vigil-$VERSION/vigil /usr/local/bin/vigil   # remplacer
sudo systemctl start vigil                    # relancer
journalctl -u vigil -n 30 --no-pager
```

Lancez les commandes `vigil` en tant que `vigil` (`sudo -u vigil`), jamais en root : le service ne
pourrait plus ouvrir les fichiers créés. Si les notes de version signalent un changement de l'unité
`deploy/vigil.service`, reprenez-la avant de relancer :

```bash
curl -fsSL https://raw.githubusercontent.com/La-Cizaille-Corp/vigil/v$VERSION/deploy/vigil.service | sudo tee /etc/systemd/system/vigil.service > /dev/null
sudo systemctl daemon-reload
```

Puis [vérifier](#vérifier).

### Serveur Windows (tâche planifiée)

PowerShell **administrateur**, dans le dossier du téléchargement :

```powershell
Disable-ScheduledTask -TaskName Vigil | Out-Null   # sinon la tâche relance Vigil toutes les 5 minutes
Stop-ScheduledTask -TaskName Vigil
Stop-Process -Name vigil -ErrorAction SilentlyContinue   # le programme peut survivre à l'arrêt de la tâche
& "C:\Program Files\Vigil\vigil.exe" backup -db C:\ProgramData\Vigil\vigil.db -o "C:\ProgramData\Vigil\backups\avant-maj-$(Get-Date -Format yyyyMMdd-HHmm).db"
Copy-Item ".\vigil-$v\*" "C:\Program Files\Vigil" -Recurse -Force   # remplacer
Enable-ScheduledTask -TaskName Vigil | Out-Null
Start-ScheduledTask -TaskName Vigil                # relancer
Get-Content C:\ProgramData\Vigil\vigil.log -Tail 20
```

Avec WinSW ou NSSM, remplacez les trois premières lignes par `Stop-Service vigil` et les deux
lignes de relance par `Start-Service vigil` (nom du service tel que vous l'avez créé).

Puis [vérifier](#vérifier).

### Serveur Docker Compose

Dans le dossier du `docker-compose.yml` :

```bash
docker compose exec vigil vigil backup -o /data/backups/avant-maj-$(date +%Y%m%d-%H%M).db   # sauvegarder (Vigil tourne encore)
# Nouvelle version mineure (0.4 → 0.5) : changez le tag de l'image dans docker-compose.yml.
docker compose pull
docker compose up -d             # arrête proprement l'ancien conteneur et démarre le nouveau
docker compose logs --tail 20 vigil
```

N'utilisez jamais `docker compose down -v` : `-v` supprime le volume, donc la base. Si les notes de
version signalent un changement de `docker-compose.yml` ou du `Caddyfile`, reprenez-les au tag de
la nouvelle version (vos réglages restent dans `.env`). Gardez la ligne `name: vigil` du fichier : elle
fixe le nom du volume (`vigil_vigil-data`), et le conteneur repartirait sinon d'un volume vide.

Puis [vérifier](#vérifier).

## Vérifier

1. **Version** : `vigil version` affiche la nouvelle version et son schéma de base
   (`docker compose exec vigil vigil version` sous Docker).
2. **Journal** : si le schéma de la base a changé, il indique « base mise à jour vers le schéma N ;
   copie de l'ancienne base : … ». Notez le nom de cette copie `.bak` : elle sert au retour arrière.
3. **Intégrité** : `vigil check`, avec la même base que le service, doit répondre
   « intègre, schéma N (à jour) ». Selon le cas :
   - poste local : `vigil check` ;
   - serveur Linux : `sudo -u vigil VIGIL_DB=/var/lib/vigil/vigil.db vigil check` ;
   - serveur Windows : `& "C:\Program Files\Vigil\vigil.exe" check -db C:\ProgramData\Vigil\vigil.db` ;
   - Docker : `docker compose exec vigil vigil check` (ou `docker exec vigil vigil check`).
4. **Interface** : connectez-vous avec votre compte habituel, et vérifiez que l'inventaire et le
   triage sont là. Lancez « Synchroniser l'inventaire » et suivez-la jusqu'au bout.
5. **Remettez en route** ce que vous aviez mis en pause (tâches, pipelines).

Page de première configuration ou inventaire vide : **rien n'est perdu**, Vigil a ouvert une autre
base. Arrêtez-le sans rien saisir. Le journal de démarrage indique le fichier ouvert (`db=…`) : relancez
avec le bon compte, le bon `-db` ou `VIGIL_DB`, ou le bon volume Docker.

Gardez la sauvegarde `avant-maj` quelques jours, puis supprimez-la : elle contient les mêmes secrets
que la base. Vigil ne garde de lui-même que les trois dernières copies `.bak`.

## Revenir en arrière

Si la nouvelle version ne démarre pas ou se comporte mal :

1. **Arrêtez Vigil** comme à l'étape d'arrêt de votre cas.
2. **Remettez la base d'avant** : la copie `vigil.db.schema-N.<date>.bak` posée à côté de la base,
   ou votre sauvegarde `avant-maj`. Renommez la base actuelle (`vigil.db` → `vigil.db.incident`),
   supprimez `vigil.db-wal` et `vigil.db-shm` s'ils existent, puis copiez la sauvegarde sous le nom
   `vigil.db`. Sur un serveur Linux, rendez-la au service :
   `sudo chown vigil:vigil /var/lib/vigil/vigil.db && sudo chmod 600 /var/lib/vigil/vigil.db`.
3. **Réinstallez l'ancienne version** : étape 2 avec l'ancien numéro de version, puis remplacement ;
   sous Docker, remettez l'ancien tag d'image.
4. **Relancez**.

Sous Docker, la base est dans le volume ; un conteneur auxiliaire la restaure (sous Compose, le
volume s'appelle `vigil_vigil-data` : `docker volume ls` le confirme ; avec `docker run`, `vigil-data`) :

```bash
docker compose stop vigil
docker run --rm -v vigil_vigil-data:/data alpine:3.20 sh -c 'cp /data/backups/avant-maj-AAAAMMJJ-HHMM.db /data/vigil.db && rm -f /data/vigil.db-wal /data/vigil.db-shm && chown 65532:65532 /data/vigil.db && chmod 600 /data/vigil.db'
```

Le travail fait entre la mise à jour et le retour arrière (triage, réglages) est perdu ; les
vulnérabilités se recalculent à la synchronisation suivante. Une version ancienne refuse d'ouvrir
une base déjà mise à jour : c'est voulu, et c'est pourquoi il faut remettre la base d'avant.

## Ce que Vigil garantit

- Une copie de la base est écrite **avant** toute évolution de schéma ; si elle échoue (disque
  plein, droits), rien n'est modifié.
- Chaque évolution s'applique dans une transaction : une coupure en cours de route laisse la base
  intacte.
- Chaque version est testée sur de vraies bases produites par les versions précédentes.

Le détail est dans [OPERATIONS.md](OPERATIONS.md#mettre-à-jour).
