# Politique de sécurité

## Signaler une vulnérabilité

Merci de ne pas ouvrir d'issue publique. Utilisez le signalement privé de GitHub
(onglet *Security* → *Report a vulnerability*) du dépôt.

## Mesures en place

| Risque (OWASP) | Mesure |
|---|---|
| Injection SQL | Requêtes exclusivement paramétrées (`internal/store`) |
| XSS | Rendu `html/template` (échappement contextuel), CSP stricte sans script ; le texte des flux CTI est réduit à du texte brut et seuls les liens http(s) sont conservés |
| CSRF | Jeton synchroniseur par session, cookies `SameSite=Strict`, contrôle `Origin` / `Sec-Fetch-Site` |
| Authentification | argon2id (m=64 Mio, t=3, p=2), 12 caractères minimum, limitation des échecs par IP, temps de réponse constant |
| Sessions | Jeton aléatoire 256 bits, seul son SHA-256 est stocké, `HttpOnly`, `Secure` en HTTPS, expiration 12 h |
| Contrôle d'accès | Rôle vérifié côté serveur sur chaque route |
| SSRF | Flux CTI et webhooks : https uniquement, sans identifiants dans l'URL ; adresses privées, locales et link-local refusées au moment de la connexion (après résolution DNS), y compris après redirection |
| XXE / documents malveillants | `encoding/xml` ne résout pas les entités externes ; tailles bornées (flux 8 Mo, SBOM 20 Mo, 50 000 composants) |
| Secrets | URL de webhook jamais réaffichée, masquée dans le journal d'audit et retirée des messages d'erreur |
| Exposition | Écoute locale par défaut ; refus d'une interface publique sans TLS ; premier compte créable uniquement en local |
| Données | Base SQLite créée en `0600` ; erreurs détaillées uniquement dans les journaux ; journal d'audit |
| Dépendances | Trois dépendances directes ; toolchain Go épinglée ; `govulncheck` et `gosec` en CI |

Les passages sensibles du code sont marqués `// SECURITY:`. Les exceptions `gosec` sont
annotées `#nosec` avec leur justification.
