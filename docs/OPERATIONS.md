# Exploitation

## Déployer

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

Les sauvegardes contiennent les mêmes secrets que la base (secrets TOTP, empreintes de mots de
passe, URL de webhooks) : elles sont créées en `0600` ; stockez-les chiffrées.
**Une sauvegarde sur le même disque ne protège pas d'une perte du disque** : exportez
`backups/` hors de la machine (sauvegarde du serveur, rclone, Litestream…).

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
(migrations). L'inverse (sauvegarde plus récente que le binaire) n'est pas pris en charge :
restaurez avec une version au moins aussi récente. Les vulnérabilités se recalculent à la
synchronisation suivante ; seul le travail de triage postérieur à la sauvegarde est perdu.

Testez une restauration de temps en temps : une sauvegarde jamais restaurée n'est pas une sauvegarde.

## Mettre à jour

1. `vigil backup -o …` ;
2. vérifier la release (checksums, `gh attestation verify`, voir le README) ;
3. remplacer le binaire ou changer le tag de l'image, redémarrer. Les migrations s'appliquent seules
   et ne suppriment jamais de données utilisateur sans le signaler dans les notes de version.

## Surveiller

- Le journal (stderr, ou `journalctl -u vigil`) trace synchronisations, sauvegardes, webhooks en échec.
- `vigil check` vérifie l'intégrité de la base (utilisé comme healthcheck Docker).
- La page Paramètres affiche la dernière erreur de chaque flux CTI et de chaque webhook.
