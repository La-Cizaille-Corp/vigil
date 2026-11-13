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

## De la 0.4 à la 0.5

La procédure est la même, et **la base est conservée** : inventaire, triage et historique, comptes,
canaux, jetons et réglages. Au premier démarrage, elle passe du schéma 15 au schéma 21 : six
migrations, qui n'ajoutent que des index, des tables et des colonnes. Rien n'est supprimé. Une copie
`.bak` est écrite avant, comme pour toute évolution du schéma ; sur une base de 180 Mo (deux noyaux
suivis), copie et migrations prennent environ une seconde. La 0.4 refuse ensuite cette base : pour y
revenir, remettez la base d'avant ([revenir en arrière](#revenir-en-arrière)).

**Avant la mise à jour**

- **Tag de l'image** : sous Docker, passez de `0.4` à `0.5` (`docker run` ou `docker-compose.yml`).
  L'unité systemd, le `Caddyfile` et votre `.env` restent valables.
- **Expéditeur des e-mails** : un `-smtp-from` (ou `VIGIL_SMTP_FROM`) entre guillemets, avec une
  adresse IP entre crochets, une espace ou un second `@` empêche désormais Vigil de démarrer.
  Vérifiez-le. Un canal dont un destinataire a une telle adresse échoue à l'envoi, avec la raison
  sur le canal : corrigez l'adresse.
- **Options des commandes** : `vigil user …`, `vigil backup`, `vigil import-sbom` et `vigil digest`
  ne lisent plus leurs options propres dans l'environnement (`VIGIL_ALL`, `VIGIL_ROLE`,
  `VIGIL_GROUPS`, `VIGIL_USERNAME`, `VIGIL_O`, `VIGIL_PROJECT`, `VIGIL_NO_WEBHOOKS`) : passez-les en
  options. Les options communes (`VIGIL_DB`…) et celles de `vigil serve` ne changent pas.
- **TLS** : `-tls-cert` sans `-tls-key`, ou l'inverse, est refusé au démarrage au lieu de servir en
  HTTP.
- **Réseau** : les sources (OSV, NVD, KEV, EPSS) passent par le même contrôle d'adresse que les flux
  et les webhooks. Si votre DNS les résout vers une adresse privée (miroir, proxy transparent), elles
  sont refusées sauf avec `-allow-private-urls`.
- **Scripts** : un appel scripté à `/setup` doit envoyer aussi `confirm`, le mot de passe une seconde
  fois.
- **Journaux** : les messages du journal du service passent en anglais (détail ci-dessous), et le
  détail des nouvelles entrées du journal d'audit s'écrit en paires `clé=valeur`
  (`id=12 status=resolved`, `source=cli` pour la ligne de commande). Les anciennes entrées gardent
  leur texte. Adaptez un filtre ou un SIEM qui lisait l'ancien texte.

<details>
<summary>Messages du journal du service qui changent</summary>

| Avant | Après |
|---|---|
| `synchronisation automatique`, `asset sync failed` | `sync failed` (avec `asset=0` pour tout l'inventaire) |
| `collecte automatique des flux` | `scheduled cti collection failed` |
| `sauvegarde automatique` | `scheduled backup failed` |
| `sauvegarde` | `backup done` |
| `digest automatique` | `scheduled digest failed` |
| `vigil démarré` | `vigil started` |
| `arrêt du serveur` | `server shutdown failed` |
| `e-mails envoyés sans chiffrement à un serveur distant…` | `e-mail sent unencrypted to a remote server…` |
| `flux CTI en erreur` | `cti feed failed` |
| `notification en erreur`, clé `canal` | `notification failed`, clé `channel` |
| `alertes immédiates` | `immediate alerts failed` |
| `enrichissement KEV/EPSS` | `kev/epss enrichment failed` |
| `actif non vérifié` | `asset not checked` |
| `catalogue KEV` | `kev catalog failed` |
| `export CSV` | `csv export failed` |
| `recherche CPE` | `cpe search failed` |

</details>

**À la première synchronisation**

1. **Lecture complète** : elle lit encore les gros paquets en entier, près d'une heure pour un noyau
   Ubuntu. Les suivantes ne lisent que ce qui a changé : moins d'une minute et 600 Ko au lieu de
   4,5 Go. Ubuntu régénère les avis de son noyau à chaque publication d'un de ses noyaux : comptez
   encore une lecture complète environ une synchronisation sur sept, et au moins une par semaine.
2. **Une ligne par CVE** : les avis groupés (USN, DSA) et les seconds avis d'une même CVE sont
   repliés sur la ligne de la CVE, dont la page les montre. Aucune alerte ne repart et aucune ligne
   ne paraît nouvelle. La détection d'une ligne gardée peut reculer à celle de l'autre avis : son
   échéance avance d'autant et peut passer « hors délai ».
3. **Alertes à attendre, une fois** :
   - les vulnérabilités déjà marquées « Exploitable – à traiter » partent en alerte urgente ;
   - sur un noyau Ubuntu, la sévérité d'un avis sans score vient désormais de la priorité d'Ubuntu :
     une centaine de lignes deviennent hautes ou critiques, et chaque canal abonné aux alertes « À
     planifier » reçoit un message groupé ;
   - les CVE plus anciennes que la période de suivi mais probablement exploitées (EPSS ≥ 10 %)
     entrent dans la période, en alerte urgente : 13 lignes sur la base de test, dont deux CVE TCP de
     2004 et 2008 que Debian dit toujours affecter le noyau.
4. **Délai moyen de traitement** : il ne compte plus l'arriéré trouvé à la première analyse d'un
   actif. La valeur affichée change, en général à la baisse.

**Ce qui change à l'usage**

- **Niveaux** : « Urgentes » remplace « À traiter en priorité » et la case « Prioritaire » des
  filtres ; les liens `?priority=1` des alertes déjà reçues ouvrent le niveau Urgentes. Chaque ligne
  commence par son niveau et sa raison. Une vulnérabilité exploitée, ou marquée Exploitable, passe
  devant une critique qui ne l'est pas ; une vulnérabilité notée par son seul score se range à sa
  bande. Les réglages d'alerte des canaux s'appellent « Urgentes seulement » et « Urgentes et À
  planifier » : rien à refaire.
- **Listes** : pages de 100 lignes, retour à la liste et « Suivante » depuis une vulnérabilité,
  filtres par actif (`/findings?asset=…`) et par groupe. Une décision peut viser toute la liste
  filtrée : elle ne change pas ce que quelqu'un a déjà décidé et demande confirmation au-delà de 50
  vulnérabilités. Export et import VEX sont au-dessus du tableau.
- **Page d'un actif** : un résumé par niveau et ses dix vulnérabilités les plus urgentes ; la liste
  complète s'ouvre depuis ses compteurs. Un favori vers `/assets/{id}?page=N` n'ouvre plus que la
  première page. « Écarter le bruit » y est toujours visible pour les analystes, et « Suivre tout
  l'historique » demande confirmation.
- **Inventaire** : colonnes Urgentes et Ouvertes, et une recherche.
- **Ajouter des actifs** : quatre entrées, un formulaire en trois groupes, des refus qui disent quoi
  écrire, une erreur par ligne pour un CSV. Un purl doit nommer un paquet, et un CPE doit avoir ses
  13 champs : un actif déjà en base qui ne le respecte pas est à corriger à sa prochaine
  modification. La première configuration demande de confirmer le mot de passe.
- **Digest** : les urgentes d'abord, les nombres par niveau, des listes bornées à 50 lignes ; plus de
  résumés ni de synthèse par statut, et la colonne « Exploitées (KEV) » du tableau par éditeur
  devient « Urgentes ». Un outil qui lirait son Markdown est à revoir. « Digest envoyé » ne s'affiche
  que si un canal l'a reçu ; dans Teams, un digest long garde son lien vers le digest complet.
- **Veille** : le nombre d'actualités de chaque vue, « Qui concernent mon inventaire » en premier,
  des pages de 100 groupées par jour, jusqu'aux 500 plus récentes. Les flux RSS 1.0 sont lus ; d'un
  flux de plus de 2 000 entrées, seules les 2 000 premières le sont.
- **Paramètres** : des sous-pages (Notifications, Délais, Filtres de veille, Flux, Utilisateurs,
  Groupes, Jetons d'API, Journal d'audit). Les favoris vers `/settings#canaux` ou `#jetons` mènent à
  la première. Un formulaire refusé garde ce qui a été saisi.
- **Groupes d'actifs** (nouveau) : Paramètres → Groupes, définis par des étiquettes et des projets.
  Un compte peut être limité à des groupes (`vigil user add -groups`, `vigil user set-access`), et
  un canal ne recevoir que les alertes et le digest d'un groupe. Les comptes existants gardent
  l'accès à tout, et `vigil user add` sans `-groups` aussi ; créer un compte dans l'interface demande
  de choisir son accès. Les filtres de veille sont réservés aux comptes qui voient tout.
- **Comptes** :
  - « Fermer mes autres sessions » dans Mon compte ;
  - un nom qui ne diffère d'un compte existant que par la casse est refusé ;
  - un mot de passe parmi les 3 000 plus courants est refusé quand on le choisit, pas à la
    connexion ;
  - un mot de passe de plus de 1 024 octets n'est plus accepté : un compte qui en aurait un
    reçoit un nouveau mot de passe par `vigil user reset-password` ;
  - **un jeton d'API créé par un compte désactivé est suspendu** jusqu'à sa réactivation :
    désactiver un administrateur coupe les CI qui utilisent ses jetons.
- **Nombres** : CVSS et EPSS s'écrivent avec une virgule (9,8 ; 12,3 %), à l'écran, dans le digest
  et les alertes. Les exports CSV ajoutent une apostrophe devant ce qui pourrait commencer une
  formule après un saut de ligne ou une virgule ; un export réimporté redonne les mêmes valeurs.
- **Imports** : un CSV est importé en entier ou pas du tout. Un fichier trop gros reçoit « Envoi trop
  volumineux » avec la borne, au lieu de « Jeton CSRF invalide. ». Un SBOM ou un VEX de plus de
  2 millions de valeurs JSON est refusé ; deux imports simultanés se suivent.
- **Sources** : une réponse illisible de la NVD, un catalogue KEV vide ou une réponse d'EPSS sans
  liste laissent l'actif « non vérifié » au lieu de faire passer des vulnérabilités pour corrigées.
  KEV et EPSS sont redemandés après une panne passagère, et une coupure pendant la lecture d'OSV ne
  fait plus perdre l'actif. Les messages d'erreur des sources changent (`HTTP 503` au lieu de
  `status 503`, `réponse illisible`).
- **Ligne de commande** : `-nvd-api-key` pour `serve`, `sync` et `digest` (la variable
  `VIGIL_NVD_API_KEY` reste conseillée) ; `vigil digest -base-url` ajoute le lien du digest à ses
  messages ; `vigil digest` produit aussi les digests des groupes qui ont un canal.
- **Performances** : listes, alertes et tableau de bord 4 à 15 fois plus rapides sur une grosse base.
  La base grossit d'environ 1,4 Mo par noyau Ubuntu suivi.
- **Sauvegardes** : les copies `.bak` sont triées par la date de leur nom, et une copie renommée à
  la main n'est plus effacée. Une base dans un dossier dont le nom contient « # » ou « % » est
  sauvegardée correctement : avant, la copie était vide, ou la sauvegarde échouait.
- **Téléphone** : une vulnérabilité en carte compacte, tous les tableaux en cartes, « Trier par » au
  lieu des titres de colonnes.
- **Image Docker** : elle contient les licences (`/usr/share/doc/vigil/`), et `vigil version` y
  affiche `0.5.0` au lieu de `v0.5.0`.

## De la 0.4.2 à la 0.4.3

Version corrective : la procédure est la même, la base reste au schéma 15 et rien n'est à reprendre
dans les fichiers de déploiement. Comme pour la 0.4.2, **Vigil n'écrit pas de copie `.bak`**, et la
0.4.2 rouvre la même base si vous revenez en arrière. Sous Docker, l'image `0.4` passe d'elle-même à
la 0.4.3. En venant de la 0.4.1, lisez aussi la section suivante.

- **Go 1.27.4** : le programme et l'image Docker sont recompilés avec cette version, qui corrige une
  faille du serveur web de Go (GO-2026-6859).
- **Clé NVD refusée** : la NVD répond alors par une erreur 404, que Vigil lisait comme « aucune
  vulnérabilité ». Chaque synchronisation passait donc à « Corrigé » les vulnérabilités des actifs
  suivis par la NVD. Ces actifs restent désormais « non vérifiés », avec la raison donnée par la
  NVD (`HTTP 404 (Invalid apiKey.)`) : corrigez alors `VIGIL_NVD_API_KEY`, ou retirez-la. Les
  vulnérabilités fermées à tort se rouvrent, avec leur historique, à la première synchronisation où
  la NVD répond normalement.
- **Liens d'actualité** : un lien qui contient un saut de ligne ou des identifiants
  (`https://site@autre-site/`) n'est plus enregistré, et le digest neutralise ceux déjà en base. Un
  flux ne peut plus glisser une mention comme `@channel` dans une messagerie par ce biais.
- **Interface** : les listes ne débordent plus de l'écran, sur ordinateur comme sur téléphone ; les
  boutons rouges du thème sombre et les bordures des champs sont plus contrastés. Le panneau
  « Traiter la sélection… » passe sous la liste et reste au bas de l'écran pendant le défilement.
  Un lien « Aller au contenu » apparaît au premier appui sur Tab.

## De la 0.4.1 à la 0.4.2

Version corrective : la procédure est la même, la base reste au schéma 15 et rien n'est à reprendre
dans les fichiers de déploiement. Sans évolution de schéma, **Vigil n'écrit pas de copie `.bak`** :
votre sauvegarde est la seule copie d'avant la mise à jour. Pour revenir à la 0.4.1, remettez son
programme : elle ouvre la même base. Sous Docker, l'image `0.4` passe d'elle-même à la 0.4.2.

- **Clé d'accès dans l'URL d'un flux** : une erreur de collecte la montrait en clair dans
  Paramètres, à tous les rôles, et l'écrivait dans le journal du service. Après la mise à jour,
  lancez « Collecter les flux » (page Veille) : l'erreur de chaque flux actif est remplacée. Un flux
  désactivé garde la sienne jusqu'à sa prochaine collecte. Si un flux à clé a échoué auparavant,
  changez sa clé : elle peut figurer dans vos anciens journaux.
- **Liste des vulnérabilités** : elle s'ouvre sur les vulnérabilités à traiter (onglet
  « Ouvertes »). Les corrigées ont leur onglet, « Toutes » réunit tout, et un filtre de statut montre
  toujours ce qu'il demande. Les cartes du tableau de bord ouvrent désormais la bonne liste.

## De la 0.4.0 à la 0.4.1

La procédure est la même, et **la base est conservée**. Au premier démarrage, elle passe du schéma 14
au schéma 15 : une colonne pour la version qui corrige chaque vulnérabilité. Rien n'est supprimé. La 0.4.0
refuse ensuite cette base : pour y revenir, remettez la base d'avant ([revenir en arrière](#revenir-en-arrière)).

- **Fichiers de déploiement** : rien à reprendre. Sous Docker, l'image `0.4` passe d'elle-même à la
  0.4.1 : suivez la procédure de votre cas sans changer le tag.
- **Colonne « Corrigée en »** : les tableaux de vulnérabilités et l'export CSV indiquent la version qui
  corrige chacune pour l'actif. Elle se remplit à la première synchronisation ; les vulnérabilités déjà
  corrigées avant la mise à jour restent vides.
- **Page d'un actif** : ses détails viennent avant ses vulnérabilités, et le formulaire de modification
  est replié juste en dessous.
- **Le champ Version fait foi.** Si le purl d'un actif porte une autre version que ce champ, c'est
  désormais le champ qui est vérifié. Dès la première synchronisation, ces actifs peuvent changer de
  résultat : des vulnérabilités passent à « Corrigé », d'autres apparaissent. Un SBOM qui sépare
  l'époque de la version (Version `1:3.0.7-24.el9`, purl `@3.0.7-24.el9?epoch=1`) est concerné.

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

Remplacez `0.5.0` par la version à installer. Le programme est extrait dans un dossier à part : il
ne remplace encore rien.

**Windows** (PowerShell) :

```powershell
$v = "0.5.0"; $arch = "amd64"   # arm64 sur processeur ARM
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
VERSION=0.5.0; ARCH=arm64   # amd64 sur Mac Intel
BASE=https://github.com/La-Cizaille-Corp/vigil/releases/download/v$VERSION
curl -fsSLO $BASE/vigil_${VERSION}_darwin_$ARCH.tar.gz
curl -fsSLO $BASE/checksums.txt
grep " vigil_${VERSION}_darwin_$ARCH.tar.gz$" checksums.txt | shasum -a 256 -c
mkdir -p vigil-$VERSION && tar -xzf vigil_${VERSION}_darwin_$ARCH.tar.gz -C vigil-$VERSION vigil
xattr -d com.apple.quarantine vigil-$VERSION/vigil 2>/dev/null || true
```

**Linux** :

```bash
VERSION=0.5.0; ARCH=amd64   # arm64 sur ARM
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
     (un simple arrêt ne suffit pas : launchd le relancerait). `Boot-out failed: 3: No such process`
     signifie qu'aucun LaunchAgent n'est chargé : rien à arrêter de ce côté.

   `pgrep -lx vigil` ne doit plus rien afficher ; sinon `pkill -x vigil` l'arrête proprement.

2. **Sauvegarder**, dans le dossier du téléchargement. La nouvelle version copie la base telle quelle,
   sans la mettre à jour, et fonctionne où que soit installée l'ancienne :

   ```bash
   vigil-$VERSION/vigil backup -o ~/vigil-avant-maj-$(date +%Y%m%d-%H%M).db
   ```

3. **Remplacer** :

   ```bash
   sudo mkdir -p /usr/local/bin
   sudo install -m 0755 vigil-$VERSION/vigil /usr/local/bin/vigil
   ```

   Si vous lanciez Vigil depuis un autre dossier, l'ancien programme ne sert plus : lancez celui-ci.

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
docker pull ghcr.io/la-cizaille-corp/vigil:0.5   # changez 0.5 pour passer à une nouvelle version mineure
docker run -d --name vigil --restart unless-stopped -p 127.0.0.1:8080:8080 -v vigil-data:/data ghcr.io/la-cizaille-corp/vigil:0.5
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
# Nouvelle version mineure (0.5 → 0.6) : changez le tag de l'image dans docker-compose.yml.
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
