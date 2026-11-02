# Exploitation

## Déployer

Installation pas à pas par système, réseau compris : [INSTALL.md](INSTALL.md).

| Mode | Quand | Fichiers |
|---|---|---|
| Binaire seul | Poste d'analyste, usage local (`127.0.0.1`) | `vigil serve` |
| Service systemd | Serveur Linux sans conteneurs | [deploy/vigil.service](../deploy/vigil.service) + reverse proxy TLS |
| Docker Compose | Exploitation par conteneurs | [deploy/docker-compose.yml](../deploy/docker-compose.yml), `Caddyfile`, `.env.example` |

Toutes les options de `vigil serve` se règlent aussi par variables d'environnement
(`-backup-keep` → `VIGIL_BACKUP_KEEP`) ; la ligne de commande l'emporte. Derrière un reverse proxy,
la page de configuration web est désactivée : le premier administrateur se crée avec
`vigil user add -username admin -role admin`.

## Sauvegarder

La base SQLite est en mode WAL : les dernières transactions vivent dans `vigil.db-wal`.
**Ne copiez jamais `vigil.db` avec `cp`, rsync ou un outil de sauvegarde de fichiers pendant que
Vigil tourne** : la copie peut être incohérente. Utilisez l'une de ces méthodes, toutes sûres
pendant les écritures :

1. **Sauvegardes automatiques** (recommandé) : `vigil serve -backup-dir /chemin -backup-interval 24h
   -backup-keep 14`. Une copie est faite au démarrage puis à chaque intervalle, vérifiée par
   `integrity_check`, et les plus anciennes sont supprimées. Le Compose et l'unité systemd les
   activent par défaut.
2. **Ponctuelle** : `vigil backup -o /chemin/vigil-avant-maj.db` (par exemple avant une mise à jour).
3. **Continue** (perte maximale de quelques secondes) : [Litestream](https://litestream.io)
   réplique la base vers S3, Azure Blob, SFTP… en lisant le WAL, sans arrêter Vigil. Outil externe,
   à installer à côté (`litestream replicate /var/lib/vigil/vigil.db s3://bucket/vigil`).

**Une sauvegarde sur le même disque ne protège pas d'une perte du disque** : exportez
`backups/` hors de la machine.

Une sauvegarde contient tout ce que contient la base : l'inventaire et ses vulnérabilités, mais
aussi des secrets que Vigil utilise en clair (secrets de double authentification, URL des webhooks,
URL des flux qui portent une clé). Vigil ne les chiffre pas lui-même, pour n'avoir aucune clé à
gérer (registre A50). Protégez donc la base et ses copies dans leur ensemble :

- chiffrez le disque du serveur (BitLocker, LUKS, FileVault) ;
- copiez les sauvegardes hors de la machine avec un outil qui les chiffre :
  [restic](https://restic.net), [borg](https://www.borgbackup.org) ou `rclone crypt`. Leur clé
  est gérée par cet outil et se garde ailleurs que sur le serveur ;
- si une copie fuit malgré tout, suivez [Fuite de la base ou d'une sauvegarde](#fuite-de-la-base-ou-dune-sauvegarde).

## Restaurer

```bash
vigil check -db /chemin/vigil-20261027-020000.db   # vérifier la sauvegarde
systemctl stop vigil                               # ou : docker compose stop vigil
mv /var/lib/vigil/vigil.db /var/lib/vigil/vigil.db.incident
rm -f /var/lib/vigil/vigil.db-wal /var/lib/vigil/vigil.db-shm
cp /chemin/vigil-20261027-020000.db /var/lib/vigil/vigil.db
chown vigil:vigil /var/lib/vigil/vigil.db && chmod 600 /var/lib/vigil/vigil.db
systemctl start vigil
```

Une sauvegarde plus ancienne que le binaire est mise à niveau automatiquement au démarrage
(migrations, précédées d'une copie `.bak`). Une sauvegarde plus récente que le binaire est refusée
au démarrage : restaurez avec une version au moins aussi récente. `vigil check -db fichier` indique
la version de schéma d'une sauvegarde avant de la restaurer. Les vulnérabilités se recalculent à la
synchronisation suivante ; seul le travail de triage postérieur à la sauvegarde est perdu.

Testez une restauration de temps en temps : une sauvegarde jamais restaurée n'est pas une sauvegarde.

## Mettre à jour

Les données ne sont jamais dans le binaire ni dans l'image : fichier SQLite (`-db`, `VIGIL_DB`) ou
volume `/data`. Procédure par système : [INSTALL.md](INSTALL.md#7-mettre-à-jour-en-conservant-les-données).

1. `vigil backup -o …` (copie la base telle quelle, sans la mettre à jour, quel que soit le binaire) ;
2. vérifier la release (checksums, `gh attestation verify`, voir le README) ;
3. remplacer le binaire ou changer le tag de l'image, redémarrer ;
4. lire le journal : « base mise à jour vers le schéma N ; copie de l'ancienne base : … », puis
   `vigil check`.

Garanties (registre A36 de [ARCHITECTURE.md](ARCHITECTURE.md)) :

- avant toute évolution de schéma d'une base existante, Vigil écrit à côté d'elle une copie
  cohérente `vigil.db.schema-N.<date UTC>.bak` ; si elle échoue (disque plein, droits), rien n'est
  modifié et Vigil s'arrête avec l'erreur ;
- chaque migration s'applique dans une transaction : une coupure en cours de route laisse la base
  dans l'état précédent ;
- une migration publiée n'est jamais modifiée, et aucune ne supprime de donnée utilisateur sans
  le signaler dans les notes de version ;
- une base écrite par une version plus récente est refusée (retour arrière d'un binaire sans
  restaurer la base) : restaurez la copie `.bak` ou réinstallez la version récente ;
- les tests ouvrent de vraies bases produites par chaque version publiée et vérifient que chaque
  valeur est conservée.

Seules les trois copies `.bak` les plus récentes sont gardées (chacune contient tous les secrets
de la base) ; effacez-les une fois la nouvelle version validée.

## Surveiller

- Le journal (stderr, ou `journalctl -u vigil`) trace synchronisations, sauvegardes, webhooks en échec.
- `vigil check` vérifie l'intégrité de la base (utilisé comme healthcheck Docker).
- La page Paramètres affiche la dernière erreur de chaque flux CTI et de chaque canal de
  notification (webhook ou e-mail) ; le journal trace aussi les alertes en échec.
- Paramètres → Journal d'audit (administrateurs) : connexions, comptes, inventaire, triage par lot,
  réglages. Chaque entrée est aussi écrite dans le journal du service (`msg=audit`) : envoyé à un
  serveur de journaux (journald distant, syslog, SIEM), il garde une trace hors de la base, que
  l'altération ou la perte de la base n'efface pas.

## Gérer les comptes

- **Double authentification obligatoire** : Paramètres → Utilisateurs → « Double authentification »,
  pour les administrateurs ou pour tous. Un compte concerné qui ne l'a pas encore configurée
  n'accède plus qu'à « Mon compte ».
- **Durée du journal d'audit** : sans limite par défaut ; `-audit-retention-days 365` (ou
  `VIGIL_AUDIT_RETENTION_DAYS`) purge les entrées plus anciennes, chaque heure.
- **Arrivée** : Paramètres → Utilisateurs → « Ajouter un utilisateur ». Un mot de passe provisoire
  s'affiche une fois ; transmettez-le par un canal sûr, l'utilisateur le change dans « Mon compte ».
- **Départ ou compte compromis** : « Désactiver… ». La connexion est refusée et les sessions sont
  fermées aussitôt ; le nom reste dans l'historique de triage et le journal d'audit. Révoquez aussi
  les jetons d'API que la personne utilisait.
- **Mot de passe oublié, téléphone perdu** : « Nouveau mot de passe… » ou « Retirer la double
  authentification… ».
- **Plus aucun administrateur ne peut se connecter** : sur le serveur, `vigil user list`, puis
  `vigil user reset-password -username NOM` ou `vigil user set-role -username NOM -role admin`.
- Un administrateur ne peut ni se désactiver ni changer son propre rôle, et le dernier
  administrateur actif ne peut pas être désactivé ni rétrogradé.

## Fuite de la base ou d'une sauvegarde

Une copie de `vigil.db`, d'une sauvegarde ou d'une copie `.bak` est sortie de vos mains.

**Ce qui est exposé**

- L'inventaire et ses vulnérabilités : la liste de vos points faibles. Rien à révoquer, mais
  considérez-la comme connue et traitez en priorité les vulnérabilités exploitées.
- Des secrets utilisables tels quels : secrets de double authentification, URL des webhooks,
  URL des flux qui portent une clé d'accès.

**Ce qui ne l'est pas** : les mots de passe (empreintes argon2id), les jetons de session et
les jetons d'API (empreintes SHA-256) ne se retrouvent pas à partir de la base.

**Que faire, dans l'ordre**

1. **Double authentification** : `vigil user reset-totp -all` la retire de tous les comptes et
   ferme leurs sessions. Chacun la reconfigure dans « Mon compte » ; si elle est obligatoire
   (Paramètres → Utilisateurs), Vigil l'y conduit à la connexion.
2. **Canaux de notification** : chez le fournisseur, supprimez chaque webhook et créez-en un
   nouveau (Slack : application → *Incoming Webhooks* ; Mattermost : Intégrations → Webhooks
   entrants ; Teams : workflow ou connecteur du canal), puis dans Paramètres supprimez le canal et
   recréez-le avec la nouvelle URL. L'ancienne URL ne permet plus d'écrire dans le canal.
3. **Flux à clé** : faites changer la clé chez le fournisseur, puis supprimez et ajoutez à nouveau
   le flux.
4. **Mots de passe** : ils résistent, mais un mot de passe faible finit par céder à une attaque
   hors ligne sur son empreinte. Faites-les changer, administrateurs d'abord (« Nouveau mot de
   passe… » ou `vigil user reset-password`).
5. **Origine** : cherchez par où la copie est sortie (emplacement des sauvegardes, droits,
   journaux d'accès) avant de reprendre les copies hors machine.
