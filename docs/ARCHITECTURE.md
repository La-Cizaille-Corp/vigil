# Architecture et arbitrages

Ce document décrit comment Vigil est construit **et pourquoi**. Chaque choix structurant est
consigné avec les options écartées et ses conséquences, pour qu'un futur mainteneur puisse le
remettre en cause en connaissance de cause plutôt que par oubli du contexte.

## 1. Objectif et cible

Outil open source de **veille de sécurité** pour petites structures (PME, collectivités, équipes
sécurité réduites, consultants) : inventorier ce qu'on utilise, savoir quelles vulnérabilités le
touchent, suivre leur traitement, suivre l'actualité des menaces et des réglementations, et
recevoir un digest régulier.

Positionnement retenu après comparaison avec l'existant : une version **légère** de ce que font
OpenCVE (alertes CVE), OWASP Dependency-Track (SBOM, VEX) et Taranis AI (veille OSINT) — un seul
binaire, sans infrastructure, licence OSI (Apache-2.0). Vigil ne cherche pas leur profondeur :
pas de plateforme de threat intelligence (pas d'IOC, pas de STIX), pas d'analyse de code.

## 2. Principes directeurs

Ils tranchent les arbitrages quand deux options se valent :

1. **Simplicité d'exploitation** : un binaire, une base dans un fichier, zéro service annexe.
2. **Sécurité par défaut, proportionnée** (OWASP) : sûr sans configuration, sans complexité
   gratuite ; chaque mesure répond à une menace du [modèle de menace](THREAT_MODEL.md).
3. **Auditabilité** : peu de dépendances, code lisible, SQL écrit à la main, points sensibles
   marqués `// SECURITY:`.
4. **Honnêteté du résultat** : l'outil alerte, l'humain trie. Pas de promesse de correspondance
   parfaite là où les données sources ne le permettent pas.
5. **Pérennité pour un mainteneur seul** : périmètre serré, bibliothèque standard d'abord.

## 3. Vue d'ensemble

```
cmd/vigil              CLI : serve, sync, digest, import-sbom, backup, check, user
internal/store         SQLite, migrations, toutes les requêtes SQL, sauvegardes
internal/inventory     Validation et normalisation des actifs
internal/sbom          Lecture CycloneDX / SPDX (JSON) → actifs
internal/vex           Export / import VEX CycloneDX
internal/sources/osv   Client OSV.dev (paquets identifiés par purl)
internal/sources/nvd   Client NVD API 2.0 (produits identifiés par CPE)
internal/sources/kev   Catalogue CISA Known Exploited Vulnerabilities
internal/sources/epss  Scores FIRST EPSS
internal/cvss          Calcul du score CVSS 3.x depuis un vecteur
internal/tracking      Synchronisation inventaire ↔ sources, enrichissement, statuts VEX
internal/cti           Flux RSS/Atom, étiquetage pays / secteur / réglementation
internal/digest        Génération du digest (Markdown + HTML)
internal/notify        Envoi des digests aux webhooks
internal/netsafe       Client HTTP anti-SSRF pour les URL fournies par les utilisateurs
internal/auth          argon2id, jetons, TOTP, limitation des tentatives, rôles
internal/web           Handlers HTTP, middleware de sécurité, templates, API CI
deploy/                Docker Compose + Caddy, unité systemd, exemple d'environnement
```

Les dépendances entre paquets vont dans un seul sens : `web` et `cmd` orchestrent ; `tracking`,
`cti`, `digest` portent la logique ; `store` est le seul à parler SQL ; les `sources` ne
connaissent que HTTP et leur format. Aucune interface n'est introduite sans deux
implémentations réelles.

### Synchronisation des vulnérabilités

Lancée périodiquement, depuis l'interface (tout l'inventaire, ou un seul actif : à l'ajout, à la
modification, ou sur demande), par l'API après un import SBOM, ou par `vigil sync`.

1. `tracking.Syncer` liste les actifs : ceux qui ont un purl (ou écosystème + nom + version) vont
   vers OSV ; ceux qui n'ont qu'un CPE vont vers la NVD.
2. OSV : une requête `querybatch` pour tout l'inventaire, puis téléchargement des seuls avis
   nouveaux ou modifiés. NVD : requêtes par CPE limitées à la période de suivi, espacées selon la
   limite de débit.
3. Enrichissement : CVE croisées avec CISA KEV et EPSS, avant les findings (voir A31). Une panne
   de ces sources est journalisée sans faire échouer la synchronisation.
4. `findings` : création si nouveau et dans la période de suivi de l'actif, réouverture si résolu
   automatiquement puis signalé à nouveau, résolution automatique si la source ne le signale plus
   (version mise à jour).
5. `cti.Collector` récupère les flux ; les items reçoivent pays, secteurs et réglementations.
   Purge après 180 jours.

### Digest

Couvre la période depuis le digest précédent (7 jours pour le premier) : nouvelles
vulnérabilités, vulnérabilités ouvertes, synthèse par statut, veille menaces filtrée, veille
réglementaire. Stocké (Markdown + HTML), consultable, exportable, envoyé aux webhooks.

## 4. Registre des arbitrages

Format : **décision** — contexte, options écartées, conséquences assumées.

### Langage, forme, interface

**A1. Go.** Il fallait un langage compilé, multiplateforme, sûr en mémoire et lisible. Rust :
plus sûr encore, mais courbe d'apprentissage et temps de compilation pénalisants pour des
contributions occasionnelles. Python : rapide à écrire, mais distribution pénible (interpréteur,
environnements) et typage faible. Go apporte un binaire statique, une compilation croisée
triviale, une bibliothèque standard couvrant HTTP, templates, crypto et SQL, et une compatibilité
ascendante forte. *Conséquence* : code un peu plus verbeux, assumé.

**A2. Un binaire unique, interface web embarquée.** Options : CLI seule, client lourd, SPA +
API. La CLI seule ne convient pas au suivi collaboratif ; un client lourd multiplie les
plateformes. L'interface est servie par le binaire (`embed`), ce qui permet le mode local comme
le mode client/serveur avec le même livrable.

**A3. Rendu serveur sans JavaScript.** Une SPA (React, htmx…) ajoute une chaîne de build, des
dépendances npm et une surface XSS. `html/template` échappe selon le contexte et permet une CSP
`default-src 'none'`. htmx, prévu initialement, s'est révélé inutile : les formulaires classiques
suffisent. *Conséquence* : interface sobre, rechargements de page complets.

**A4. Interface et documentation en français, code et commentaires en anglais.** La cible
première est francophone (CERT-FR, ANSSI, NIS2) ; le code reste accessible à tout contributeur.
Les codes techniques (sévérités, rôles, types de webhook, étiquettes) sont affichés par leur
libellé français ; les messages d'erreur Go restent en minuscules (convention Go) et sont mis en
forme de phrase à l'affichage.

**A33. Conventions d'interface communes.** Relevées lors d'une passe de cohérence :
- une action destructive (actif, flux, webhook, jeton) passe par une confirmation (`<details>`,
  sans JavaScript) et un bouton rouge explicite (« Confirmer la suppression ») ;
- après une modification, on revient sur l'objet modifié ; chaque page de détail a un lien de
  retour vers sa liste ; le menu indique la page courante ;
- les listes vides ont un message ; les choix multiples sont des cases à cocher, jamais des
  `<select multiple>` (Ctrl+clic méconnu, inutilisable au tactile) ;
- les boutons nomment l'action et l'objet (« Ajouter le flux », « Importer le SBOM ») ;
- un lecteur voit les valeurs en lecture seule, pas les liens vers des actions refusées ;
- chaque compte peut changer son mot de passe (mot de passe actuel exigé, tentatives limitées,
  autres sessions fermées).

### Données

**A5. SQLite plutôt que PostgreSQL.** PostgreSQL impose un service à installer, sauvegarder,
mettre à jour : contraire au principe 1. Pour la cible (quelques milliers d'actifs, quelques
utilisateurs), SQLite tient largement la charge. Mode WAL (lectures pendant les écritures,
résistance aux coupures), une seule connexion (pas de verrouillage à raisonner), `busy_timeout`.
*Conséquences* : une seule instance de Vigil par base (pas de haute disponibilité active-active) ;
la base devient critique, d'où A6. PostgreSQL ne se justifierait qu'avec plusieurs instances.

**A6. Sauvegardes cohérentes intégrées.** Copier le fichier pendant une écriture peut produire
une copie incohérente (le WAL contient les dernières transactions). `VACUUM INTO` produit un
instantané cohérent même pendant les écritures ; la copie est vérifiée (`integrity_check`),
créée en `0600`, écrite dans un fichier temporaire puis renommée (une sauvegarde ratée n'écrase
jamais une bonne). Sauvegardes planifiées avec rotation dans `serve`, commande `backup`
ponctuelle, Litestream documenté pour le continu. Voir [OPERATIONS.md](OPERATIONS.md).

**A7. Pilote `modernc.org/sqlite` (Go pur).** `mattn/go-sqlite3` exige CGO : compilation
croisée et image distroless plus complexes. modernc garde le binaire statique, au prix d'une
dépendance volumineuse à mainteneur unique — risque principal de la chaîne d'approvisionnement,
avec un plan B documenté dans [DEPENDENCIES.md](DEPENDENCIES.md) et des tests de contrat du
stockage.

**A8. SQL écrit à la main, migrations numérotées embarquées.** Un ORM masque les requêtes et
complique l'audit. Toutes les requêtes sont dans `internal/store`, toujours paramétrées ; les
seules parties dynamiques (filtres) n'assemblent que des expressions de colonnes fixes. Les
migrations sont appliquées au démarrage, dans l'ordre, une seule fois ; une base ancienne
(sauvegarde) est donc mise à niveau automatiquement.

**A9. Pas de miroir de la NVD.** OpenCVE montre le coût d'un miroir complet (plusieurs Go,
import long). Vigil interroge les sources à la demande pour son inventaire et ne stocke que ce
qui le concerne.

### Vulnérabilités

**A10. OSV comme source principale, par purl.** OSV agrège GHSA, PyPI, npm, Go, RustSec, les
distributions Linux, avec des plages de versions exploitables par machine : correspondance de
version fiable. La NVD est en retard d'analyse depuis 2024 et ses CPE sont incohérents.
*Conséquence* : la qualité dépend de l'identifiant ; un SBOM donne les meilleurs résultats.

**A11. NVD pour les produits sans purl, par CPE, avec trois modes.** Matériels, OS, logiciels
d'éditeur n'ont pas de purl. Le CPE est interrogé dans la NVD selon les versions choisies par
actif : la version de l'actif (correspondance faite par la NVD), toutes les versions du produit
(idée « abonnement » d'OpenCVE : quand la version exacte n'est pas fiable, mieux vaut tout voir et
trier), ou à partir d'une version. La période de suivi (A31) s'applique en plus. Débit adapté à
la limite NVD (5 requêtes / 30 s sans clé). *Conséquence* : plus de bruit qu'OSV, triage humain
attendu (principe 4). Un ancien mode « nouvelles CVE des 120 derniers jours » glissait avec le
temps : une CVE sortie de la fenêtre était résolue automatiquement à tort. Il a été remplacé par
la période de suivi, à date de début fixe.

**A12. Un actif avec purl et CPE n'est interrogé que par son purl.** Interroger les deux
doublerait les alertes (GHSA et CVE pour la même faille) et le CPE est moins précis. Il n'y a pas
de rapprochement entre deux actifs distincts décrivant le même produit : la consigne est d'en
déclarer un seul.

**A13. Statuts CycloneDX / VEX.** Des statuts maison auraient été plus « parlants » mais non
interopérables. Les états VEX (`in_triage`, `exploitable`, `resolved`, `not_affected` +
justification, `false_positive`) sont libellés en français dans l'interface, et l'export /
import VEX permet l'échange avec Dependency-Track, les clients ou les auditeurs. L'import
rapproche par purl ou CPE et par identifiant ou alias (CVE ↔ GHSA).

**A14. Résolution et réouverture automatiques.** Si la source ne signale plus une vulnérabilité
(montée de version), elle passe en `resolved` ; si elle réapparaît, elle est rouverte. Une
analyse humaine `not_affected` ou `false_positive` n'est jamais écrasée. Chaque changement est
historisé. La comparaison se fait sur la liste des identifiants signalés, pas sur des
horodatages (une première version horodatée échouait quand deux synchronisations tombaient dans
la même seconde).

**A31. Période de suivi par actif : 120 jours avant l'ajout par défaut, KEV toujours signalées.**
Ajouter FortiOS 7.2.4 avec tout l'historique remontait 117 CVE d'un coup : un arriéré que personne
ne trie, qui noie les nouveautés. Vigil est un outil de veille : chaque actif ajouté (à la main
ou par SBOM) suit par défaut les vulnérabilités publiées depuis 120 jours avant son ajout, puis
toutes les nouvelles. La date de début est fixe (pas une fenêtre glissante, voir A11) et
modifiable ; vide = tout l'historique. Garde-fou : une vulnérabilité plus ancienne est quand même
signalée si elle est activement exploitée (CISA KEV), d'où l'enrichissement KEV avant la
création des findings, et la requête NVD `hasKev`. Un finding déjà créé n'est jamais retiré
parce qu'on raccourcit la période, ni résolu automatiquement pour une vulnérabilité antérieure à
la période (la source n'a pas forcément été interrogée dessus). La NVD n'acceptant que des
plages de 120 jours, une période de plus de deux ans est interrogée sans date puis filtrée. Les
actifs existants gardent tout leur historique (pas de changement silencieux). *Conséquence* :
un audit complet demande de vider la date ; l'état de la synchronisation indique combien de
vulnérabilités ont été ignorées.

**A32. État de la synchronisation visible, analyse d'un seul actif.** Sans JavaScript, une
synchronisation en arrière-plan ne donnait aucun retour. Le bouton « Synchroniser l'inventaire »
est présent sur le tableau de bord, l'inventaire et les vulnérabilités, et ramène à la page
d'origine (liste blanche de chemins, pas de redirection ouverte). L'état courant ou le dernier
résultat (nouvelles, rouvertes, corrigées, ignorées, erreur) est affiché à côté ; il est gardé
en mémoire, car il ne concerne que le processus en cours. Ajouter, modifier ou « Analyser » un
actif lance son analyse seule ; si une synchronisation est en cours, l'analyse attend qu'elle
finisse au lieu d'être perdue.

**A15. Priorisation KEV > EPSS > sévérité, plutôt que CVSS seul.** Le CVSS mesure la gravité
théorique, pas la probabilité d'exploitation. Exploitation avérée (KEV) d'abord, puis probabilité
EPSS ≥ 10 %, puis sévérité. Le score CVSS reste affiché et filtrable.

**A16. Score CVSS calculé localement (3.x).** OSV publie souvent un vecteur sans score. La
formule officielle FIRST 3.0/3.1 tient en quelques dizaines de lignes, testées sur des vecteurs
de référence : pas de dépendance. Le CVSS 4.0 (formule par tables, bien plus complexe) n'est pas
calculé : score inconnu si c'est le seul vecteur, la sévérité textuelle restant disponible.

### Veille

**A17. Étiquetage CTI par la source, puis par mots-clés, sans NLP.** Un modèle de langage
améliorerait le rappel mais coûterait en ressources (Taranis : 16 Go de RAM), en dépendances et
en prévisibilité. Règle : la source donne d'abord ses étiquettes (un flux CERT national = son
pays), les mots-clés complètent (mots entiers, insensible à la casse et aux accents). Les
acronymes ambigus sont évités (« CRA » seul n'est pas retenu). *Conséquence* : faux positifs et
oublis possibles ; les filtres servent à trier, pas à garantir.

**A18. Trois dimensions : pays, secteur (liste NIS2), réglementation.** La veille réglementaire
(NIS2, CRA, DORA, RGPD, AI Act, ISO 27001, SecNumCloud…) suit la même mécanique, avec des sources
officielles par défaut (Commission européenne, CNIL, EDPB, EBA). Les flux ISO et EUR-Lex ont été
écartés : trop volumineux et majoritairement hors sujet. La veille réglementaire ignore les
filtres pays / secteur : une réglementation concerne tous ceux qu'elle couvre.

**A35. Tableau de bord : indicateurs d'action et graphiques SVG rendus par le serveur.** Les
indicateurs retenus répondent à « que faire maintenant ? » plutôt qu'à « combien ? » : à traiter en
priorité (KEV ou EPSS >= 10 %, cliquable vers la liste exacte), vulnérabilités ouvertes, exploitées
avec échéance CISA dépassée, en attente d'analyse depuis plus de 30 jours, délai moyen de traitement
sur 90 jours (de la détection à la clôture : corrigée, non affectée ou faux positif) et couverture de
détection (actifs vérifiés automatiquement). Graphiques : répartition par sévérité (anneau),
activité hebdomadaire nouvelles / traitées sur 12 semaines, actifs les plus exposés. Une
bibliothèque de graphiques en JavaScript aurait cassé la CSP et ajouté une dépendance npm : le
serveur calcule la géométrie et produit du SVG ; couleurs par classes CSS (thèmes clair et sombre),
info-bulle native (`<title>`) sur chaque marque, tableau des données sous chaque graphique, aucun
attribut `style`. Palettes vérifiées avec un validateur (daltonisme, contraste) : la sévérité est
une rampe ordinale d'une seule teinte (rouge), l'activité un couple bleu / vert d'eau.

**A34. Plusieurs pays, secteurs et réglementations par flux, modifiables.** Un flux européen ou
un site de normalisation couvre souvent plusieurs pays ou textes : un sélecteur unique obligeait
à choisir. Les étiquettes d'un flux se modifient après coup (y compris celles des flux par
défaut) et sont réappliquées aux actualités déjà collectées.

**A19. Digest « depuis le précédent ».** Une fenêtre fixe (7 jours) ferait manquer ou répéter
des éléments selon la fréquence de génération. Formats : Markdown (webhooks, export) et HTML
(interface). Webhooks au format le plus simple commun à Slack, Mattermost et Teams (champ
`text`), plus un JSON générique pour les intégrations.

### Sécurité

**A20. Comptes locaux, sans SSO.** Le SSO (OIDC, SAML) ajoute une dépendance lourde et une
configuration délicate ; hors périmètre tant que la demande n'existe pas. Mots de passe en
argon2id, sessions côté serveur (jeton aléatoire stocké haché), trois rôles (lecture, analyste,
administrateur) vérifiés sur chaque route.

**A21. TOTP implémenté en interne.** RFC 6238 en une trentaine de lignes (vecteurs de la RFC en
test) plutôt qu'une bibliothèque. Anti-rejeu atomique en base, essais limités, désactivation
soumise à un code, autres sessions fermées à chaque changement, récupération par la CLI.

**A22. Le premier administrateur ne se crée que depuis la machine elle-même.** Sinon un serveur
fraîchement exposé peut être réclamé par n'importe qui. Derrière un reverse proxy, toutes les
requêtes semblent locales : la page est alors désactivée et la création passe par la CLI
(défaut découvert en revue de sécurité).

**A23. Refus d'écouter en clair hors de `127.0.0.1`.** Sans TLS natif ni `-behind-proxy`
explicite, le serveur refuse de démarrer sur une interface réseau.

**A24. Client HTTP anti-SSRF pour les URL saisies.** Flux et webhooks sont des URL fournies par
les utilisateurs : contrôle à la connexion (après résolution DNS, contre le DNS rebinding) des
adresses privées, locales et réservées ; redirections limitées et en HTTPS ; proxy de
l'environnement ignoré (il masquerait la destination réelle). Les sources fixes (OSV, NVD…)
utilisent un client ordinaire.

**A25. API par jeton limité à un projet.** Les pipelines CI poussent leur SBOM via
`PUT /api/v1/projects/{projet}/sbom`. Un jeton n'écrit qu'un seul projet (moindre privilège),
est stocké haché, affiché une seule fois, préfixé `vgl_` (repérable par les scanners de secrets).
*Limite assumée* : pas d'expiration, révocation manuelle.

### Construction, distribution, exploitation

**A26. Trois dépendances directes.** Chaque ajout se justifie dans
[DEPENDENCIES.md](DEPENDENCIES.md). TOTP, CVSS, parsing SBOM / VEX / RSS et clients d'API sont
écrits en interne car simples ; argon2 (cryptographie) et SQLite (moteur) ne le sont pas.

**A27. Configuration par options et variables d'environnement, sans fichier de configuration.**
Un format de fichier à part (YAML…) serait une dépendance et une source d'erreurs de plus. Chaque
option `-nom` peut venir de `VIGIL_NOM` ; la ligne de commande l'emporte. Convient au binaire,
à systemd (`EnvironmentFile`) et à Docker (`env_file`).

**A28. Binaire d'abord, Docker en option.** Le binaire Go suffit (systemd fourni). L'image
existe pour les équipes dont l'exploitation passe par des conteneurs : distroless, non-root,
lecture seule hors `/data`. Le Compose d'exemple ajoute Caddy pour le HTTPS automatique, puisque
l'image n'écoute pas en clair sur le réseau sans proxy.

**A29. Releases vérifiables.** GoReleaser : builds reproductibles (`-trimpath`, horodatage du
commit), six plateformes, checksums, SBOM par archive, attestation de provenance signée ; release
créée en brouillon et publiée après relecture.

**A30. Chaîne d'approvisionnement défendue en profondeur.** Voir
[CONTRIBUTING.md](../CONTRIBUTING.md) et [DEPENDENCIES.md](DEPENDENCIES.md) : actions épinglées
par SHA, images par digest, outils versionnés, délai de 7 jours avant toute mise à jour non
urgente, détection des nouvelles capacités (capslock), recherche de secrets sur tout
l'historique, analyse statique et CodeQL, revue des dépendances, scan de l'image.

## 5. Écarté ou différé

| Sujet | Décision | Raison |
|---|---|---|
| IOC, STIX, MISP | Écarté | Domaine des plateformes de threat intelligence (OpenCTI, MISP) ; export éventuel si demande. |
| PostgreSQL, haute disponibilité | Différé | Inutile pour la cible ; sauvegardes et Litestream couvrent la résilience. |
| SSO (OIDC / SAML) | Différé | Dépendance et configuration lourdes ; à reconsidérer sur demande. |
| NLP / LLM pour la CTI | Différé | Ressources et imprévisibilité ; jamais obligatoire si ajouté. |
| CVSS 4.0 | Différé | Formule complexe ; peu de vecteurs 4.0 seuls aujourd'hui. |
| Rapprochement d'actifs en double (purl ↔ CPE) | Différé | Correspondance purl ↔ CPE peu fiable ; consigne : un actif par produit. |
| Expiration des jetons d'API | Différé | Révocation manuelle suffisante à ce stade. |
