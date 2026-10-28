# Modèle de menace

Modèle volontairement court, à relire à chaque évolution notable. Les mesures citées sont
repérables dans le code par le commentaire `SECURITY:`.

## Ce que l'on protège

- **L'inventaire et les vulnérabilités** : ils révèlent la surface d'attaque de l'organisation
  (versions vulnérables non corrigées). C'est la donnée la plus sensible.
- **Les secrets** : mots de passe (hachés), sessions, jetons d'API, secrets TOTP, URL de webhooks.
- **L'intégrité du suivi** : statuts, justifications VEX, journal d'audit.

## Modes et frontières de confiance

| Mode | Exposition | Hypothèse |
|---|---|---|
| Local (défaut) | `127.0.0.1` uniquement | La machine et son utilisateur sont de confiance. |
| Serveur | Réseau, TLS natif ou reverse proxy | Les utilisateurs sont authentifiés mais pas tous administrateurs ; le réseau est hostile. |

Données entrantes **non fiables** : formulaires, fichiers SBOM et VEX, flux RSS/Atom, réponses des
API externes (OSV, NVD, KEV, EPSS), requêtes de l'API CI.

## Menaces et mesures

| Menace | Mesures |
|---|---|
| Vol ou devinette de mot de passe | argon2id, 12 caractères minimum, limitation des échecs par IP (mémoire bornée), temps constant si l'utilisateur n'existe pas, TOTP optionnel avec anti-rejeu atomique. |
| Vol de session | Jeton aléatoire 256 bits stocké haché, cookie `HttpOnly`, `SameSite=Strict`, `Secure` en HTTPS, expiration 12 h. Désactiver le TOTP exige un code (essais limités par utilisateur) ; activer ou désactiver le TOTP ferme les autres sessions. |
| CSRF | Jeton synchroniseur sur toute requête modifiante, vérification `Origin` / `Sec-Fetch-Site`, `SameSite=Strict`. |
| XSS | `html/template` (échappement contextuel), CSP stricte sans script, pas de HTML venant des sources. |
| Injection SQL | Requêtes exclusivement paramétrées. |
| Élévation de privilèges | Rôle vérifié côté serveur sur chaque route ; jeton d'API limité à un projet. |
| Prise de contrôle à l'installation | Le premier administrateur ne peut être créé que depuis la machine locale ; derrière un reverse proxy (`-behind-proxy`), la page de configuration est désactivée et l'administrateur se crée en ligne de commande. |
| SSRF via flux ou webhooks | Client dédié : HTTPS uniquement, IP privées, locales et réservées (dont CGNAT et NAT64) bloquées à la connexion (contre le DNS rebinding), redirections limitées. Avec un proxy sortant (`HTTPS_PROXY`), la destination est résolue et vérifiée avant de confier la requête au proxy, seul autorisé à avoir une adresse privée. |
| Force brute sur la connexion | 5 essais par 15 minutes et par adresse ; derrière `-behind-proxy`, l'adresse est la dernière de `X-Forwarded-For` (ajoutée par le proxy, non falsifiable si Vigil n'est joignable que par lui). Double authentification TOTP. |
| Injection de formules (exports CSV) | Toute cellule commençant par `=`, `+`, `-`, `@`, tabulation ou retour chariot est préfixée d'une apostrophe. |
| E-mail | Serveur SMTP fixé par l'exploitant ; STARTTLS exigé par défaut, sans repli en clair ; pas de mot de passe envoyé sans TLS (sauf à la machine locale) ; destinataires validés (pas d'injection d'en-têtes). |
| Fichiers malveillants (SBOM, VEX, flux) | Taille bornée, pas d'entités XML externes, BOM UTF-8 retiré, validation des champs. |
| Exposition en clair | Refus d'écouter hors `127.0.0.1` sans TLS ou `-behind-proxy`. |
| Fuite de secrets | URL de webhook masquées dans l'interface et les erreurs, jetons affichés une seule fois, erreurs génériques côté client et détails dans les journaux. |
| Chaîne d'approvisionnement | 3 dépendances directes (voir DEPENDENCIES.md). En CI : govulncheck, gosec, staticcheck, CodeQL, revue des dépendances, recherche de secrets (gitleaks, tout l'historique), scan de l'image (Trivy), SBOM ; actions épinglées par SHA et images de base par digest, mises à jour par Dependabot. Builds reproductibles, checksums, SBOM et attestation de provenance signée pour chaque release. |
| Sources compromises ou erronées | Les sources externes peuvent créer de faux positifs ou en omettre : le triage humain reste la référence, et l'historique conserve chaque changement. |

## Risques acceptés

- **Base SQLite non chiffrée** : quiconque lit le fichier voit l'inventaire et les secrets TOTP. Le
  fichier est créé en `0600` ; chiffrer le disque est recommandé en mode serveur.
- **Secrets TOTP stockés en clair dans la base** (nécessaire pour vérifier les codes).
- **Derrière un reverse proxy joignable autrement que par le proxy**, `X-Forwarded-For` peut être
  forgé et la limitation des tentatives contournée : n'exposez Vigil `-behind-proxy` que sur
  `127.0.0.1` ou un réseau interne (c'est le cas de l'unité systemd et du Compose fournis).
- **Pas de SSO** : hors périmètre pour l'instant.
- **Jetons d'API sans expiration** : à révoquer à la main (Paramètres) quand un pipeline disparaît.
- **Proxy HTTP sortant** : le proxy résout les noms à nouveau ; entre la vérification de Vigil et
  sa résolution, un nom pourrait changer d'adresse (rebinding DNS). Le proxy doit lui-même refuser
  les destinations internes.
