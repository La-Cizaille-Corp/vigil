# Installation

Vigil est un binaire unique, sans dépendance : ni base de données à installer, ni runtime. Les
données tiennent dans un fichier SQLite, **hors du binaire** : remplacer le binaire (ou l'image
Docker) conserve tout (voir [Mettre à jour](#7-mettre-à-jour-en-conservant-les-données)).

Exploitation courante (sauvegarde, restauration, supervision) : [OPERATIONS.md](OPERATIONS.md).

## 1. Choisir un mode

| Usage | Mode | Écoute | Base de données |
|---|---|---|---|
| Poste d'analyste | binaire lancé à la main ou à l'ouverture de session | `127.0.0.1:8080` | dossier de l'utilisateur |
| Serveur d'équipe Linux | service systemd + reverse proxy HTTPS | `127.0.0.1:8080`, proxy sur 443 | `/var/lib/vigil/vigil.db` |
| Serveur d'équipe Windows | tâche planifiée (ou WinSW) + TLS natif ou IIS | `0.0.0.0:8443` ou `127.0.0.1:8080` | `C:\ProgramData\Vigil\vigil.db` |
| Conteneurs (toutes plateformes) | Docker Compose + Caddy | conteneur `8080`, Caddy sur 443 | volume `vigil-data` (`/data`) |

Emplacement par défaut de la base quand `-db` / `VIGIL_DB` n'est pas donné :

| Système | Fichier |
|---|---|
| Windows | `%AppData%\vigil\vigil.db` |
| macOS | `~/Library/Application Support/vigil/vigil.db` |
| Linux | `$XDG_CONFIG_HOME/vigil/vigil.db`, soit `~/.config/vigil/vigil.db` |

Les fichiers `vigil.db-wal` et `vigil.db-shm` à côté font partie de la base : ne les supprimez pas
pendant que Vigil tourne.

Toute option de `vigil serve` se règle aussi par variable d'environnement : `VIGIL_` + nom de
l'option en majuscules, tirets remplacés par `_` (`-backup-dir` → `VIGIL_BACKUP_DIR`). La ligne de
commande l'emporte.

## 2. Windows (10, 11, Server 2016 et suivants)

### Télécharger et vérifier

```powershell
$v = "0.3.0"; $arch = "amd64"   # arm64 sur processeur ARM
$base = "https://github.com/La-Cizaille-Corp/vigil/releases/download/v$v"
$zip = "vigil_${v}_windows_$arch.zip"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"   # accélère Invoke-WebRequest sous PowerShell 5.1
Invoke-WebRequest "$base/$zip" -OutFile $zip
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt
$line = Select-String -Path checksums.txt -Pattern ("\s" + [regex]::Escape($zip) + "$")
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne ($line.Line -split "\s+")[0]) { throw "Empreinte invalide : n'utilisez pas ce fichier." }
```

Facultatif, avec [GitHub CLI](https://cli.github.com) : `gh attestation verify $zip --repo La-Cizaille-Corp/vigil`
prouve que l'archive a été construite par le workflow de release du dépôt.

Le binaire n'est pas signé par Authenticode : SmartScreen peut afficher « Windows a protégé votre
ordinateur ». Une fois l'empreinte vérifiée, retirez la marque « téléchargé depuis Internet »
puis installez (PowerShell **administrateur**) :

```powershell
Unblock-File $zip
Expand-Archive $zip -DestinationPath "C:\Program Files\Vigil" -Force
& "C:\Program Files\Vigil\vigil.exe" version
```

### Poste local

```powershell
& "C:\Program Files\Vigil\vigil.exe" serve
```

Ouvrez <http://127.0.0.1:8080> : la page de première configuration crée le compte administrateur.
La base va dans `%AppData%\vigil\vigil.db`. `Ctrl+C` arrête Vigil proprement. Rien à ouvrir dans le
pare-feu : Vigil n'écoute que sur la boucle locale.

### Serveur : démarrage automatique

Vigil n'est pas un service Windows natif. Deux options :

- **Planificateur de tâches** (intégré, ci-dessous) : démarrage au boot, relance toutes les
  5 minutes si le processus s'est arrêté ;
- **[WinSW](https://github.com/winsw/winsw)** ou **[NSSM](https://nssm.cc)** : enveloppent
  `vigil.exe` dans un vrai service (relance immédiate, rotation des journaux, variables
  d'environnement dans un fichier de configuration dont vous restreignez l'accès).

Préparer le dossier de données, accessible seulement au compte de service (`SERVICE LOCAL`), à
`SYSTEM` et aux administrateurs. Les SID rendent la commande indépendante de la langue de Windows.
Sous Windows, ce sont ces droits NTFS qui protègent la base (secrets TOTP, URL de webhooks) :

```powershell
New-Item -ItemType Directory -Force "C:\ProgramData\Vigil\backups" | Out-Null
icacls "C:\ProgramData\Vigil" /inheritance:r /grant:r "*S-1-5-19:(OI)(CI)M" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

Créer la tâche. `cmd /c` sert uniquement à écrire le journal (stderr) dans un fichier :

```powershell
$cmd = '/c ""C:\Program Files\Vigil\vigil.exe" serve -addr 127.0.0.1:8080 -db C:\ProgramData\Vigil\vigil.db -backup-dir C:\ProgramData\Vigil\backups 2>> C:\ProgramData\Vigil\vigil.log"'
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmd
$trigger = New-ScheduledTaskTrigger -AtStartup
# Toutes les 5 minutes, relance Vigil s'il ne tourne plus (une seule instance à la fois).
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-19" -LogonType ServiceAccount   # SERVICE LOCAL
Register-ScheduledTask -TaskName "Vigil" -Action $action -Trigger $trigger -Settings $settings -Principal $principal
Start-ScheduledTask -TaskName "Vigil"
Get-Content C:\ProgramData\Vigil\vigil.log -Tail 20 -Wait
```

`-ExecutionTimeLimit ([TimeSpan]::Zero)` est indispensable : par défaut Windows arrête une tâche
au bout de 72 heures. Le premier administrateur se crée depuis le serveur lui-même, soit par la
page de configuration (<http://127.0.0.1:8080>), soit en ligne de commande :

```powershell
& "C:\Program Files\Vigil\vigil.exe" user add -db C:\ProgramData\Vigil\vigil.db -username admin -role admin
```

Variables secrètes (`VIGIL_NVD_API_KEY`, `VIGIL_SMTP_PASSWORD`) : le planificateur n'a pas de
variables par tâche. Sur un serveur dédié, définissez-les au niveau machine (lisibles par les
utilisateurs locaux, prises en compte au prochain redémarrage) ; sinon préférez WinSW.

```powershell
[Environment]::SetEnvironmentVariable("VIGIL_NVD_API_KEY", "votre-clé", "Machine")
```

### Serveur : exposer sur le réseau

Soit Vigil termine TLS lui-même (certificat et clé **PEM** ; un `.pfx` se convertit avec
`openssl pkcs12`) : remplacez dans la tâche `-addr 127.0.0.1:8080` par
`-addr 0.0.0.0:8443 -tls-cert C:\ProgramData\Vigil\tls\cert.pem -tls-key C:\ProgramData\Vigil\tls\key.pem -base-url https://vigil.example.org:8443`.
Soit IIS (URL Rewrite + ARR) sert de reverse proxy, voir [§ 6](#reverse-proxy).

Ouvrir le port au réseau local seulement :

```powershell
New-NetFirewallRule -DisplayName "Vigil (HTTPS)" -Direction Inbound -Protocol TCP -LocalPort 8443 -RemoteAddress LocalSubnet -Profile Domain,Private -Action Allow
```

## 3. macOS (Intel et Apple Silicon)

```bash
VERSION=0.3.0; ARCH=arm64   # amd64 sur Mac Intel
BASE=https://github.com/La-Cizaille-Corp/vigil/releases/download/v$VERSION
curl -fsSLO $BASE/vigil_${VERSION}_darwin_$ARCH.tar.gz
curl -fsSLO $BASE/checksums.txt
grep " vigil_${VERSION}_darwin_$ARCH.tar.gz$" checksums.txt | shasum -a 256 -c
tar -xzf vigil_${VERSION}_darwin_$ARCH.tar.gz vigil
xattr -d com.apple.quarantine vigil 2>/dev/null || true   # archive téléchargée par un navigateur
sudo mkdir -p /usr/local/bin && sudo install -m 0755 vigil /usr/local/bin/vigil
vigil serve
```

Le binaire n'est pas notarié : sans retrait de l'attribut de quarantaine, Gatekeeper refuse de le
lancer (« développeur non identifié »). La base va dans
`~/Library/Application Support/vigil/vigil.db`.

**Démarrage à l'ouverture de session** (LaunchAgent, relance automatique) : le fichier
[deploy/launchd/org.lacizaille.vigil.plist](../deploy/launchd/org.lacizaille.vigil.plist) fixe
la base, les sauvegardes et le journal. launchd ne développe pas `~` : `sed` y place votre dossier.

```bash
mkdir -p ~/Library/LaunchAgents
curl -fsSL https://raw.githubusercontent.com/La-Cizaille-Corp/vigil/v$VERSION/deploy/launchd/org.lacizaille.vigil.plist \
  | sed "s|/Users/UTILISATEUR|$HOME|g" > ~/Library/LaunchAgents/org.lacizaille.vigil.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.lacizaille.vigil.plist
tail -f ~/Library/Logs/vigil.log
```

Redémarrer : `launchctl kickstart -k gui/$(id -u)/org.lacizaille.vigil` ; arrêter et désactiver :
`launchctl bootout gui/$(id -u)/org.lacizaille.vigil`. Pour un Mac serveur sans session ouverte,
placez le fichier dans `/Library/LaunchDaemons/` avec une clé `UserName` (compte dédié).

En écoute locale, le pare-feu applicatif de macOS ne demande rien. En mode serveur, autorisez le
binaire (il n'est pas signé, macOS peut sinon bloquer les connexions entrantes) :

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/vigil
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/vigil
```

## 4. Linux

```bash
VERSION=0.3.0; ARCH=amd64   # arm64 sur ARM
BASE=https://github.com/La-Cizaille-Corp/vigil/releases/download/v$VERSION
curl -fsSLO $BASE/vigil_${VERSION}_linux_$ARCH.tar.gz
curl -fsSLO $BASE/checksums.txt
sha256sum --ignore-missing -c checksums.txt
tar -xzf vigil_${VERSION}_linux_$ARCH.tar.gz vigil
```

**Poste local** : `./vigil serve`, base dans `~/.config/vigil/vigil.db`.

**Serveur (systemd)** : l'unité [deploy/vigil.service](../deploy/vigil.service) fait tourner Vigil
sous un compte système, avec un durcissement systemd (système de fichiers en lecture seule sauf
`/var/lib/vigil`, aucune capacité, appels système filtrés). Les fichiers de `deploy/` sont dans
l'archive ; les commandes ci-dessous les prennent aussi bien dans le dépôt, au tag de la version
installée.

```bash
RAW=https://raw.githubusercontent.com/La-Cizaille-Corp/vigil/v$VERSION/deploy
sudo useradd --system --home /var/lib/vigil --shell /usr/sbin/nologin vigil
sudo install -m 0755 vigil /usr/local/bin/vigil
sudo install -d -m 0750 -g vigil /etc/vigil
curl -fsSLO $RAW/.env.example
sudo install -m 0640 -g vigil .env.example /etc/vigil/vigil.env   # puis éditez-le
curl -fsSL $RAW/vigil.service | sudo tee /etc/systemd/system/vigil.service > /dev/null
sudo systemctl daemon-reload && sudo systemctl enable --now vigil
sudo -u vigil VIGIL_DB=/var/lib/vigil/vigil.db vigil user add -username admin -role admin
journalctl -u vigil -f
```

Lancez toujours les commandes `vigil` sur la base du service **en tant que `vigil`** (`sudo -u
vigil`) : lancées en root, elles peuvent créer des fichiers que le service ne pourra plus ouvrir.

L'unité écoute sur `127.0.0.1:8080` en `-behind-proxy` : placez nginx ou Caddy devant
([§ 6](#reverse-proxy)). Pour que Vigil termine TLS lui-même, `sudo systemctl edit vigil` :

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/vigil serve -addr 0.0.0.0:8443 -tls-cert /etc/vigil/tls/cert.pem -tls-key /etc/vigil/tls/key.pem
```

Le service n'a aucune capacité : il ne peut pas écouter sous le port 1024 (d'où 8443). Clé
privée lisible par le groupe `vigil` (`chmod 0640`, `chgrp vigil`).

Pare-feu, en n'ouvrant le port qu'au réseau interne (443 pour un reverse proxy, 8443 sinon) :

```bash
sudo ufw allow from 192.168.10.0/24 to any port 443 proto tcp
```

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.10.0/24" port port="443" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Binaire statique sans bibliothèque externe : aucune règle SELinux ou AppArmor particulière.

## 5. Docker et Docker Compose

Image distroless (sans shell), utilisateur non privilégié, données dans le volume `/data`.
Fonctionne de la même façon sous Docker Desktop (Windows, macOS). Les tags suivent les versions
(`0.3.0`, `0.3`) : fixez-en toujours un.

**Poste local** :

```bash
docker run -d --name vigil --restart unless-stopped -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil:0.3
docker exec -it vigil vigil user add -username admin -role admin
```

Gardez `127.0.0.1:` devant le port : l'image écoute en clair derrière un proxy attendu, et
`-p 8080:8080` exposerait l'interface au réseau sans TLS.

**Serveur avec HTTPS automatique** ([docker-compose.yml](../deploy/docker-compose.yml) + Caddy) :

```bash
mkdir vigil && cd vigil
RAW=https://raw.githubusercontent.com/La-Cizaille-Corp/vigil/v0.3.0/deploy
curl -fsSLO $RAW/docker-compose.yml
curl -fsSLO $RAW/Caddyfile
curl -fsSL -o .env $RAW/.env.example   # renseignez VIGIL_DOMAIN ; vérifiez le tag d'image du compose
docker compose up -d
docker compose exec vigil vigil user add -username admin -role admin
```

Caddy obtient le certificat Let's Encrypt de `VIGIL_DOMAIN`, ce qui suppose les ports 80 et 443
joignables depuis Internet. Pour un serveur purement interne, remplacez dans le `Caddyfile` par
`tls /certs/cert.pem /certs/key.pem` (certificat de l'entreprise, monté en lecture seule dans le
conteneur `caddy`) ou
`tls internal` (autorité de Caddy, à installer sur les postes).

**Les données vivent dans le volume nommé `vigil-data`**, pas dans le conteneur : `docker compose
down`, `pull`, `up` les conservent. **`docker compose down -v` supprime le volume, donc la base.**
Sous Docker Desktop, le volume est dans la machine virtuelle de Docker, invisible dans
l'Explorateur ou le Finder ; pour copier une sauvegarde sur l'hôte :

```bash
docker compose exec vigil vigil backup -o /data/backups/manuelle.db
docker compose cp vigil:/data/backups/manuelle.db .
```

## 6. Réseau

### Écoute

- Par défaut `127.0.0.1:8080` : seule la machine locale accède à l'interface.
- Vigil **refuse d'écouter en clair sur une interface non locale** : il faut `-tls-cert` et
  `-tls-key`, ou `-behind-proxy` quand un reverse proxy termine TLS.
- `-base-url https://vigil.example.org` : adresse publique utilisée dans les liens des
  notifications (webhooks, e-mails).
- Derrière un reverse proxy, la page de première configuration est désactivée : créez
  l'administrateur avec `vigil user add`.

### Reverse proxy

| Proxy | Fichier | Remarques |
|---|---|---|
| Caddy | [deploy/Caddyfile](../deploy/Caddyfile) | Certificat automatique, transmet `Host` par défaut |
| nginx | [deploy/nginx.conf](../deploy/nginx.conf) | `client_max_body_size 22m` pour les imports SBOM et VEX (21 Mio maximum) |
| IIS (Windows) | URL Rewrite + Application Request Routing | Règle de réécriture vers `http://127.0.0.1:8080` ; la limite d'envoi par défaut d'IIS (30 Mo) suffit |

Le proxy **doit transmettre l'en-tête `Host` d'origine** : Vigil compare l'en-tête `Origin` des
formulaires à `Host` et répond « Origine refusée » sinon. Sous IIS :

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" set config -section:system.webServer/proxy /enabled:"True" /preserveHostHeader:"True" /commit:apphost
```

Vigil coupe toute réponse après 120 s ; réglez le délai de lecture du proxy un peu au-dessus.

### Flux sortants

Vigil n'a besoin d'aucun flux entrant depuis Internet, seulement que les utilisateurs atteignent
l'interface. Toutes les requêtes sortantes sont en HTTPS (TCP 443), sauf l'e-mail.

| Destination | Usage | Nécessaire |
|---|---|---|
| `api.osv.dev` | Vulnérabilités des paquets (purl) | Oui, si l'inventaire a des purl |
| `services.nvd.nist.gov` | CVE des produits (CPE) et recherche de CPE | Oui, si l'inventaire a des CPE |
| `www.cisa.gov` | Catalogue KEV (exploitation avérée) et flux d'avis CISA | Recommandé |
| `api.first.org` | Scores EPSS | Recommandé |
| `www.cert.ssi.gouv.fr` | Flux CERT-FR (alertes, avis, menaces) | Flux par défaut |
| `www.bleepingcomputer.com`, `feeds.feedburner.com` | Presse spécialisée | Flux par défaut |
| `digital-strategy.ec.europa.eu`, `www.cnil.fr`, `www.edpb.europa.eu`, `www.eba.europa.eu` | Veille réglementaire | Flux par défaut |
| Flux ajoutés, webhooks (Slack, Teams, Mattermost…) | Selon votre configuration | Selon usage |
| Serveur SMTP, TCP 587 (STARTTLS) ou 465 (TLS) | Notifications par e-mail | Si le canal e-mail est utilisé |

Les flux peuvent rediriger vers un autre hôte (HTTPS uniquement). Sans accès Internet, Vigil
reste utilisable pour l'inventaire et le triage, mais ne synchronise plus rien.

### Proxy d'entreprise

À partir de la 0.3, Vigil passe par le proxy défini dans `HTTPS_PROXY` (et `NO_PROXY` pour les
exceptions) pour **toutes** ses requêtes sortantes, y compris les flux CTI et webhooks saisis par
les utilisateurs. Pour ces derniers, la protection anti-SSRF résout elle-même le nom de
destination et refuse les adresses privées avant de confier la requête au proxy (le proxy, lui,
peut avoir une adresse privée). Vigil demande au proxy le nom de destination, pas son adresse : les
listes d'autorisation par domaine du proxy s'appliquent. Configurez aussi le proxy pour interdire
les destinations internes. Seuls les proxys HTTP sans authentification ou en authentification Basic
(`http://utilisateur:motdepasse@proxy:3128`) sont pris en charge ; pour NTLM ou Kerberos, passez
par un relais local ([Px](https://github.com/genotrance/px), cntlm).

Go **n'utilise pas** les réglages proxy de Windows (Internet Explorer, WinHTTP, PAC) : seules les
variables d'environnement comptent.

| Système | Où définir `HTTPS_PROXY` / `NO_PROXY` |
|---|---|
| Windows | Session : `$env:HTTPS_PROXY = "http://proxy.example.org:3128"` ; service : `[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://proxy.example.org:3128", "Machine")` puis redémarrage, ou fichier WinSW |
| macOS | Session : `export HTTPS_PROXY=…` ; LaunchAgent : `EnvironmentVariables` du `.plist` |
| Linux | `/etc/vigil/vigil.env` (une ligne `HTTPS_PROXY=…`), puis `systemctl restart vigil` |
| Docker Compose | Fichier `.env` (transmis au conteneur par `env_file`) |

Un webhook interne (Mattermost sur le réseau local) demande `-allow-private-urls` et, en général,
son hôte dans `NO_PROXY`.

### Proxy qui inspecte TLS

Le proxy présente ses propres certificats : Vigil doit faire confiance à l'autorité de
l'entreprise.

- Windows, macOS : Vigil utilise le magasin de certificats du système ; une autorité déployée par
  GPO ou MDM est reconnue sans réglage.
- Linux : ajoutez l'autorité au magasin du système (`update-ca-certificates` ou
  `update-ca-trust`), ou pointez `SSL_CERT_FILE` / `SSL_CERT_DIR` vers elle.
- Docker : montez le certificat dans le dossier lu par défaut, sans retirer les autorités
  publiques : `- ./ca-entreprise.pem:/etc/ssl/certs/ca-entreprise.pem:ro` dans `volumes`.

### E-mail

| Option | Variable | Rôle |
|---|---|---|
| `-smtp-addr hote:port` | `VIGIL_SMTP_ADDR` | Serveur d'envoi, par exemple `smtp.example.org:587` |
| `-smtp-tls starttls\|tls\|none` | `VIGIL_SMTP_TLS` | `starttls` (587, par défaut : Vigil refuse d'envoyer si le serveur ne propose pas STARTTLS), `tls` (465) ; `none` pour un relais interne sans chiffrement, sans identifiant (Vigil n'envoie un mot de passe en clair qu'à la machine locale) |
| `-smtp-username` | `VIGIL_SMTP_USERNAME` | Compte d'envoi |
| `-smtp-password` | `VIGIL_SMTP_PASSWORD` | Préférez la variable : un argument de commande est plus exposé |
| `-smtp-from` | `VIGIL_SMTP_FROM` | Expéditeur, par exemple `vigil@example.org` |

Les destinataires se règlent dans **Paramètres → Canaux de notification**, type « E-mail » (plusieurs
adresses séparées par des virgules). Chaque canal choisit s'il reçoit les digests, les alertes
immédiates, ou les deux. L'e-mail ne passe pas par `HTTPS_PROXY` : le pare-feu doit autoriser la
connexion directe au serveur SMTP.

## 7. Mettre à jour en conservant les données

La base est un fichier (ou un volume) séparé du binaire : remplacer le binaire ou changer le tag
de l'image conserve inventaire, triage, historique, comptes et réglages.

À partir de la 0.3, au démarrage, Vigil :

- écrit une copie cohérente de la base **avant** d'appliquer des migrations de schéma, à côté
  d'elle : `vigil.db.schema-<N>.<horodatage UTC>.bak` (N = version de schéma avant mise à jour) ;
- **refuse de démarrer** sur une base créée par une version plus récente que lui : le message
  indique de mettre Vigil à jour ou de restaurer la copie prise avant la mise à jour.

Faites tout de même une sauvegarde explicite avant, et un contrôle après.

| Système | Mise à jour |
|---|---|
| Windows (poste) | `Ctrl+C`, `vigil.exe backup -o C:\Users\…\vigil-avant-maj.db`, remplacer `vigil.exe` (même dossier), relancer |
| Windows (tâche) | `Stop-ScheduledTask Vigil` ; `vigil.exe backup -db C:\ProgramData\Vigil\vigil.db -o C:\ProgramData\Vigil\backups\avant-maj.db` ; extraire la nouvelle archive dans `C:\Program Files\Vigil` ; `Start-ScheduledTask Vigil` |
| macOS | `vigil backup -o ~/vigil-avant-maj.db` ; `sudo install -m 0755 vigil /usr/local/bin/vigil` ; `launchctl kickstart -k gui/$(id -u)/org.lacizaille.vigil` |
| Linux (systemd) | `sudo -u vigil VIGIL_DB=/var/lib/vigil/vigil.db vigil backup -o /var/lib/vigil/backups/avant-maj.db` ; `sudo install -m 0755 vigil /usr/local/bin/vigil` ; `sudo systemctl restart vigil` |
| Docker Compose | `docker compose exec vigil vigil backup -o /data/backups/avant-maj.db` ; changer le tag d'image dans `docker-compose.yml` ; `docker compose pull && docker compose up -d` (jamais `down -v`) |

Sous Windows, `vigil.exe` est verrouillé tant qu'il tourne : arrêtez-le avant de le remplacer.
Après le redémarrage, vérifiez le journal (« base mise à jour vers le schéma N ; copie de
l'ancienne base : … ») et lancez `vigil check` (avec le même `-db`), qui contrôle l'intégrité de la
base et indique sa version de schéma. `vigil backup` copie la base telle quelle, sans la mettre à
jour, même lancé avec le nouveau binaire. Pour revenir en arrière : arrêtez Vigil, restaurez la copie
`.bak` (ou votre sauvegarde) comme décrit dans [OPERATIONS.md](OPERATIONS.md#restaurer), puis
relancez l'ancienne version.

## 8. Dépannage

| Symptôme | Cause et solution |
|---|---|
| `écoute sur 127.0.0.1:8080 (port déjà utilisé ?)` | Une autre instance tourne, ou un autre logiciel occupe le port. Windows : `Get-NetTCPConnection -LocalPort 8080 -State Listen \| ForEach-Object { Get-Process -Id $_.OwningProcess }` ; Linux et macOS : `sudo lsof -iTCP:8080 -sTCP:LISTEN`. Arrêtez l'ancienne instance ou changez de port (`-addr 127.0.0.1:8081`). |
| `écoute sur une interface non locale : fournissez -tls-cert/-tls-key ou -behind-proxy` | Vigil refuse le HTTP en clair sur le réseau : voir [§ 6](#écoute). |
| La page de première configuration redirige vers la connexion | Mode `-behind-proxy` (Docker, systemd) ou accès depuis une autre machine : `vigil user add -username admin -role admin` sur le serveur. |
| « Origine refusée » à l'envoi d'un formulaire | Le reverse proxy ne transmet pas l'en-tête `Host` d'origine (voir [§ 6](#reverse-proxy)). |
| Synchronisation NVD très lente | Sans clé, la NVD limite à 5 requêtes par 30 s. Clé gratuite : <https://nvd.nist.gov/developers/request-an-api-key>, dans `VIGIL_NVD_API_KEY`. |
| `proxyconnect tcp`, délais dépassés vers les sources | Proxy absent ou mal renseigné : `HTTPS_PROXY`, et autorisation des destinations du [tableau des flux](#flux-sortants). |
| `x509: certificate signed by unknown authority` | Proxy qui inspecte TLS : voir [§ 6](#proxy-qui-inspecte-tls). |
| `adresse de destination interdite (réseau privé ou local)` | Flux ou webhook sur le réseau interne : `-allow-private-urls` (et `NO_PROXY` pour cet hôte). |
| En HTTP local, la connexion revient sans cesse à la page de connexion (Safari) | En mode `-behind-proxy` (image Docker), le cookie de session est réservé à HTTPS ; Chrome, Edge et Firefox l'acceptent sur la machine locale, pas tous les navigateurs. Ouvrez <http://localhost:8080>, ou passez par le reverse proxy HTTPS. |
| Code de double authentification toujours refusé | Horloge du serveur ou du téléphone décalée de plus de 30 s environ. Windows : `w32tm /resync` ; Linux : `timedatectl` (NTP actif). |
| Vigil refuse de démarrer : base créée par une version plus récente | Binaire plus ancien que la base : installez la version la plus récente, ou restaurez la copie `.bak` prise avant la mise à jour. |
