# Modèle de menace

Modèle volontairement court, à relire à chaque évolution notable. Les mesures citées sont
repérables dans le code par le commentaire `SECURITY:`.

## Ce que l'on protège

- **L'inventaire et les vulnérabilités** : ils révèlent la surface d'attaque de l'organisation
  (versions vulnérables non corrigées). C'est la donnée la plus sensible.
- **Les secrets** : mots de passe (hachés), sessions, jetons d'API, secrets TOTP, URL de webhooks et de flux (qui peuvent porter une clé).
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
| Vol ou devinette de mot de passe | argon2id, 12 caractères minimum (comptés en caractères, pas en octets) et 1 024 octets au plus, partout (installation, connexion, changement, ligne de commande ; un mot de passe plus long est refusé avant le calcul), refus d'un nouveau mot de passe parmi les 3 000 plus courants, casse ignorée (liste embarquée, registre A77), limitation des échecs par adresse et par compte (mémoire bornée), temps constant si l'utilisateur n'existe pas, TOTP optionnel avec anti-rejeu atomique. |
| Vol de session | Jeton aléatoire 256 bits stocké haché, cookie `HttpOnly`, `SameSite=Strict`, `Secure` et préfixe `__Host-` en HTTPS, expiration 12 h. Activer le TOTP exige le mot de passe, le désactiver un code (essais limités par utilisateur) ; activer ou désactiver le TOTP ou changer de mot de passe ferme les autres sessions, et chacun peut les fermer à la demande (Mon compte → « Fermer mes autres sessions »). |
| Départ d'un utilisateur, compte compromis | Un administrateur désactive le compte (Paramètres → Utilisateurs ou `vigil user disable`) : connexion refusée, sessions fermées aussitôt, jetons d'API qu'il a créés suspendus tant qu'il reste désactivé (la liste des jetons le montre), nom conservé dans l'historique et le journal d'audit. Changement de rôle immédiat ; mot de passe provisoire généré ; au moins un administrateur actif reste toujours. Un nouveau compte ne peut pas porter le nom d'un autre à la casse près (« Alice » et « alice »). |
| CSRF | Jeton synchroniseur sur toute requête modifiante d'une session, vérification `Origin` / `Sec-Fetch-Site`, `SameSite=Strict`. La connexion et l'installation, faute de session, n'ont que la vérification d'origine (voir « Risques acceptés »). |
| XSS | `html/template` (échappement contextuel), CSP stricte sans script, pas de HTML venant des sources. |
| Injection SQL | Requêtes exclusivement paramétrées. |
| Élévation de privilèges | Rôle vérifié côté serveur sur chaque route ; jeton d'API limité à un projet. |
| Prise de contrôle à l'installation | Le premier administrateur ne peut être créé que depuis la machine locale, en une seule instruction (deux formulaires simultanés ne créent pas deux comptes) ; une instance locale refuse les requêtes adressées à un autre nom que `localhost` ou `127.0.0.1` (une page web qui ferait pointer son domaine sur la machine, *DNS rebinding*, ne peut pas la configurer) ; derrière un reverse proxy (`-behind-proxy`), ou si une requête porte des en-têtes de proxy, la page de configuration est désactivée et l'administrateur se crée en ligne de commande. |
| SSRF via flux ou webhooks | Client dédié : HTTPS uniquement, IP privées, locales et réservées (dont CGNAT, NAT64 et la forme « IPv4 traduite » de SIIT) bloquées à la connexion (contre le DNS rebinding), redirections limitées (5 au plus, en HTTPS, règle commune à toutes les sources : `netsafe.CheckRedirect`). Avec un proxy sortant (`HTTPS_PROXY`), la destination est résolue et vérifiée avant de confier la requête au proxy, seul autorisé à avoir une adresse privée. |
| Force brute sur la connexion | 5 essais par 15 minutes et par adresse (un bloc IPv6 /64 compte pour une adresse), 10 par compte quelle que soit l'adresse ; l'essai est compté avant la vérification (pas de rafale parallèle) et une connexion réussie n'efface que son propre essai. Les jetons d'API invalides sont comptés de même par adresse (même règle du /64), à part des connexions. Derrière `-behind-proxy`, l'adresse est la dernière de `X-Forwarded-For` (ajoutée par le proxy, non falsifiable si Vigil n'est joignable que par lui). Double authentification TOTP. |
| Saturation mémoire par la connexion | Au plus 4 calculs argon2 (64 Mio chacun) en même temps ; les suivants attendent. |
| Injection dans les messageries | Le texte venant des sources, des flux et des SBOM est neutralisé avant le digest Markdown et les alertes : pas de mention (`@channel`, `<!channel>`), de lien déguisé ni de balise. Un lien d'actualité n'est conservé que s'il s'agit d'une URL http(s) valide, sans caractère de contrôle ni identifiants, et la cible d'un lien Markdown encode espaces et caractères de contrôle (un saut de ligne couperait le lien). |
| Injection de formules (exports CSV) | Toute cellule commençant par `=`, `+`, `-`, `@`, tabulation ou retour chariot est préfixée d'une apostrophe, de même qu'un tel caractère placé dans une valeur après une virgule, un point-virgule, une tabulation ou un saut de ligne, éventuellement suivis d'espaces : un tableur qui découpe sur un autre séparateur, ou qui retire les espaces des cellules, y commencerait une cellule. Une espace seule ne compte pas (« 2.0 - 2.5 » reste intact) : un import qui découpe sur l'espace n'est pas couvert. L'import retire exactement ces apostrophes : un export relu redonne les valeurs exportées. |
| E-mail | Serveur SMTP fixé par l'exploitant ; STARTTLS exigé par défaut, sans repli en clair ; pas de mot de passe envoyé sans TLS (sauf à la machine locale) ; destinataires et expéditeur (`-smtp-from`, vérifié au démarrage) validés par la même règle : adresses simples seulement, avec un seul `@`, sans espace ni caractère `<>()[],;:\"` dans l'adresse (une adresse entre guillemets, que `net/mail` dépouille de ses guillemets, ajouterait des paramètres à `RCPT TO` ou `MAIL FROM`, ou un second `@`), pas d'injection d'en-têtes. |
| Fichiers malveillants (SBOM, VEX, flux) | Taille bornée, pas d'entités XML externes, BOM UTF-8 retiré, validation des champs ; 500 actualités par collecte d'un flux, dates futures ramenées à aujourd'hui, 20 000 analyses par document VEX, 50 pages par requête NVD, scores EPSS hors de 0..1 ignorés. Un SBOM sans composant exploitable est refusé (il effacerait l'historique de triage du projet). |
| Exposition en clair | Refus d'écouter hors `127.0.0.1` sans TLS ou `-behind-proxy`. |
| Fuite de secrets | URL de webhook et de flux masquées dans l'interface et retirées des erreurs (`netsafe.WithoutURL`), jetons affichés une seule fois, erreurs génériques côté client et détails dans les journaux. À l'échec d'une connexion, le nom saisi n'est journalisé que s'il est celui d'un compte : un mot de passe tapé dans le champ du nom n'y finit pas. |
| Chaîne d'approvisionnement | 3 dépendances directes (voir DEPENDENCIES.md). En CI : govulncheck, gosec, staticcheck, CodeQL, revue des dépendances, recherche de secrets (gitleaks, tout l'historique), scan de l'image (Trivy), SBOM ; actions épinglées par SHA et images de base par digest, mises à jour par Dependabot. Builds reproductibles, checksums, SBOM et attestation de provenance signée pour chaque release. |
| Sources compromises ou erronées | Les sources externes peuvent créer de faux positifs ou en omettre : le triage humain reste la référence, et l'historique conserve chaque changement. Ce qu'elles envoient est vérifié avant d'être stocké (`tracking.sanitize`) : échelle d'une base traduite (`MODERATE`, `Important`), autre sévérité remplacée par celle du score CVSS, sinon tenue pour inconnue ; score CVSS hors de 0..10 ignoré, résumé, description, alias et références bornés ; échéance KEV gardée seulement si c'est une date. Chaque réponse est lue dans une borne : plus grosse, c'est une erreur, jamais une réponse tronquée. D'un refus, seule la raison donnée par la source est affichée, sur une ligne de 200 caractères au plus, jamais la réponse brute. |

## Risques acceptés

- **Base SQLite non chiffrée** : quiconque lit le fichier voit l'inventaire et les secrets TOTP. Le
  fichier est créé en `0600` ; chiffrer le disque est recommandé en mode serveur.
- **Secrets utilisables stockés en clair dans la base** : secrets de double authentification,
  URL des webhooks, URL des flux qui portent une clé. Vigil s'en sert (calcul du code attendu,
  envoi du message) au lieu de seulement les vérifier : ils ne peuvent pas être hachés comme les
  mots de passe et les jetons. Pas de chiffrement applicatif, pour n'avoir aucune clé à gérer
  (registre A50) : la base et ses sauvegardes se protègent par le chiffrement du disque et des
  copies hors machine ; en cas de fuite, `vigil user reset-totp -all` et la rotation des URL les
  rendent sans valeur (OPERATIONS.md, « Fuite de la base ou d'une sauvegarde »).
- **Les requêtes aux sources publiques révèlent une partie de l'inventaire** : purl et CPE à OSV et
  à la NVD, et, pour les actifs détectés par leur nom, ce nom tel quel. Un nom d'actif ne doit donc
  pas contenir d'information interne (nom de serveur, de client) ; renseignez-la dans les notes ou
  les étiquettes, qui ne sortent pas.
- **Derrière un reverse proxy joignable autrement que par le proxy**, `X-Forwarded-For` peut être
  forgé et la limitation des tentatives contournée : n'exposez Vigil `-behind-proxy` que sur
  `127.0.0.1` ou un réseau interne (c'est le cas de l'unité systemd et du Compose fournis).
- **Pas de SSO** : hors périmètre pour l'instant.
- **Mots de passe courants hors de la liste ou déjà en place** : seuls les 3 000 mots de passe de
  12 caractères ou plus les plus courants sont refusés, sans consulter de service en ligne de mots
  de passe divulgués ; une variante (un chiffre ajouté) passe. Le contrôle porte sur le mot de passe
  que l'on choisit, pas sur la connexion : un mot de passe déjà en place reste valable jusqu'à son
  prochain changement (registre A77).
- **Verrouillage d'un compte par un tiers** : dix échecs en 15 minutes bloquent le compte pendant
  ce délai, même pour son titulaire. C'est le prix de la limite par compte.
- **Connexion forcée depuis un navigateur ancien** : les formulaires de connexion et d'installation
  n'ont pas de jeton CSRF, faute de session. Ils refusent une requête venue d'un autre site d'après
  les en-têtes `Origin` et `Sec-Fetch-Site`, que les navigateurs actuels envoient sur tout envoi de
  formulaire d'un site à l'autre. Un navigateur qui n'envoie ni l'un ni l'autre pourrait être
  connecté, à l'insu de son utilisateur, au compte d'un attaquant, qui verrait alors ce qu'il y
  saisit. L'origine est comparée sur l'hôte seulement : derrière un reverse proxy, Vigil ne voit pas
  le schéma employé par le navigateur. Un jeton avant la connexion (cookie en double soumission)
  couvrirait ce cas au prix d'un état avant la connexion : écarté tant que ces navigateurs restent
  marginaux (audit de code de novembre 2026, S15).
- **Journaux conservés par défaut sans limite** : pour la traçabilité, le journal d'audit et
  l'historique de triage ne sont pas purgés. `-audit-retention-days` limite la durée du journal
  d'audit quand une politique l'impose (il contient des noms et des adresses IP) ; l'historique de
  triage n'est jamais purgé.
- **Double authentification facultative par défaut** : Paramètres → Utilisateurs permet de
  l'exiger des administrateurs ou de tous ; c'est recommandé en mode serveur.
- **Jetons d'API sans expiration** : à révoquer à la main (Paramètres) quand un pipeline disparaît.
- **Proxy HTTP sortant** : le proxy résout les noms à nouveau ; entre la vérification de Vigil et
  sa résolution, un nom pourrait changer d'adresse (rebinding DNS). Comme seul HTTPS est permis et
  que le certificat est vérifié contre le nom, aucune requête n'atteint un service interne : au plus
  une tentative de connexion (sondage de ports). Le proxy devrait lui-même refuser les destinations
  internes.
