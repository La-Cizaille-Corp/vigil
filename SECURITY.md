# Politique de sécurité

## Signaler une vulnérabilité

Merci de ne pas ouvrir d'issue publique. Utilisez le signalement privé de GitHub
(onglet *Security* → *Report a vulnerability*) du dépôt.

## Mesures en place

| Risque (OWASP) | Mesure |
|---|---|
| Injection SQL | Requêtes exclusivement paramétrées (`internal/store`) |
| XSS | Rendu `html/template` (échappement contextuel), CSP stricte sans script |
| CSRF | Jeton synchroniseur par session, cookies `SameSite=Strict`, contrôle `Origin` / `Sec-Fetch-Site` |
| Authentification | argon2id (m=64 Mio, t=3, p=2), 12 caractères minimum, limitation des échecs par IP, temps de réponse constant |
| Sessions | Jeton aléatoire 256 bits, seul son SHA-256 est stocké, `HttpOnly`, `Secure` en HTTPS, expiration 12 h |
| Contrôle d'accès | Rôle vérifié côté serveur sur chaque route |
| Exposition | Écoute locale par défaut ; refus d'une interface publique sans TLS ; premier compte créable uniquement en local |
| Données | Base SQLite créée en `0600` ; erreurs détaillées uniquement dans les journaux ; journal d'audit |
| Réseau sortant | HTTPS vers OSV uniquement, délais d'expiration, réponses bornées en taille |

Les passages sensibles du code sont marqués `// SECURITY:`.
