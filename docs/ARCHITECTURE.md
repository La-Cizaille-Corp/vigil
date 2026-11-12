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
internal/sources       Requête commune des sources : statut, lecture bornée, décodage, essais
internal/sources/osv   Client OSV.dev (paquets identifiés par purl)
internal/sources/nvd   Client NVD API 2.0 (produits identifiés par CPE)
internal/sources/kev   Catalogue CISA Known Exploited Vulnerabilities
internal/sources/epss  Scores FIRST EPSS
internal/cvss          Calcul du score CVSS 3.x depuis un vecteur
internal/tracking      Synchronisation inventaire ↔ sources, enrichissement, statuts VEX, classement d'urgence
internal/cti           Flux RSS/Atom, étiquetage pays / secteur / réglementation
internal/digest        Génération du digest (Markdown + HTML)
internal/fr            Dates et nombres à la française (pages, digest, alertes, CSV)
internal/notify        Digests et alertes vers les webhooks et par e-mail (SMTP)
internal/netsafe       Client HTTP anti-SSRF pour les URL fournies par les utilisateurs
internal/limit         Lecture bornée des réponses réseau et des fichiers déposés
internal/auth          argon2id, mots de passe courants refusés, jetons, TOTP, limitation des tentatives, rôles
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
   vers OSV ; ceux qui n'ont qu'un CPE, ou qu'un nom, vont vers la NVD.
2. OSV : une requête `querybatch` pour tout l'inventaire, puis téléchargement des seuls avis
   nouveaux ou modifiés ; un paquet aux avis trop nombreux pour une réponse est lu en entier la
   première fois (A55), puis seulement pour ce qui a changé d'après sa liste légère (A90).
   Certains paquets sont lus en entier d'emblée et comparés ici (A51, A56) ; les avis qu'ils laissent hors
   période sont relus s'ils sont probablement exploités (A31). NVD : requêtes par CPE
   limitées à la période de suivi, espacées selon la limite de débit, renvoyées après une panne
   passagère. Un actif qu'une source n'a pas pu vérifier est signalé et ne bloque pas les autres.
   Les avis d'un actif sont enregistrés ensemble, une fois ses sources lues (A57).
3. Enrichissement : CVE croisées avec CISA KEV et EPSS, avant les findings (voir A31) ; le
   catalogue KEV est lu une fois par synchronisation, chaque CVE demandée une fois à EPSS (y compris
   celles des avis anciens relus pour la garde de A31), et seuls les changements écrits, en une
   transaction ; l'analyse d'un seul actif n'enrichit que ses avis. Une panne de ces sources est
   journalisée sans faire échouer la synchronisation.
4. `findings` : une ligne par CVE (A80), les avis groupés et les seconds avis d'une CVE repliés ;
   création si nouveau et dans la période de suivi de l'actif, réouverture si résolu
   automatiquement puis signalé à nouveau, résolution automatique si la source ne le signale plus
   (version mise à jour). Les écritures d'un actif forment une transaction : tout ou rien (A57).
5. Alertes immédiates (A37) : les vulnérabilités ouvertes devenues urgentes sont envoyées aux
   canaux qui les demandent, une fois par niveau d'urgence.
6. `cti.Collector` récupère les flux ; les items reçoivent pays, secteurs et réglementations, et
   leurs identifiants CVE sont indexés (A40). Purge après 180 jours.

### Digest

Couvre la période depuis le digest précédent (7 jours pour le premier), dans l'ordre des niveaux
(A87) : urgentes, nombres par niveau (nouvelles et au total, corrigées comprises), nouvelles
vulnérabilités ouvertes regroupées par éditeur (A47) puis les plus urgentes, hors délai, actualités
citant l'inventaire, vulnérabilités ouvertes par éditeur, veille menaces filtrée, veille
réglementaire ; chaque liste est bornée à 50 lignes. Stocké (Markdown + HTML), consultable,
exportable, envoyé aux webhooks.

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
forme de phrase à l'affichage. Leur langue suit leur lecteur : français pour une erreur faite pour
l'écran ou la ligne de commande (saisie, fichier importé, URL refusée, collecte déjà en cours),
anglais pour une erreur interne et pour le journal du service, messages comme clés, que lisent aussi
des outils. La raison technique d'un échec de source reste celle de la source (`HTTP 503`,
`HTTP 404 (Invalid apiKey.)`). L'audit de code de novembre 2026 en relevait deux exceptions ; dix-sept
messages du journal étaient en fait en français, tous passés en anglais.

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
- *Téléphone et accessibilité* (audit d'ergonomie de la 0.4.1, lot 6) : sous 700 px, chaque tableau se lit
  en cartes (classe `cards`, une étiquette `data-label` par cellule, le nom en tête `title`, les boutons sur
  toute la largeur `actions`), au lieu de défiler de côté avec ses actions hors de l'écran. Ces tableaux
  écrivent leurs rôles (`table`, `rowgroup`, `row`, `columnheader`, `cell`), qu'une mise en page en grille
  retire dans certains navigateurs (Safari avec VoiceOver). Une vulnérabilité y tient en une carte compacte :
  niveau, sévérité et scores, identifiant, alias plafonnés, résumé, puis actif, version corrigée, statut et
  échéance deux à deux, au lieu d'onze rangées étiquetées. Une liste triable s'y trie par une liste « Trier
  par » et un bouton (`sortForm`, qui garde filtres et niveau) : ses titres de colonnes sont masqués. La case
  de sélection mesure 22 px dans une cible de 44 px, toute la cellule la coche (WCAG 2.5.8). L'en-tête tient
  en deux lignes : le logo et le compte, puis le menu sur une ligne qui défile ; le style du bandeau ne vise
  plus que `body > header`, et les en-têtes d'éditeur de la recherche CPE ne se collent plus en haut de
  l'écran. Un champ a le fond d'une carte et un bord à 3:1 au moins sur la carte comme sur la page
  (WCAG 1.4.11), et 16 px de texte sur téléphone, qui sinon agrandit la page. Un lien vers un autre site dit
  en texte masqué qu'il ouvre un nouvel onglet (`newTab`), un lien répété nomme son objet (« Utiliser F5 NGINX
  1.34.2 »). *Écarté* : des liens de tri en ligne au-dessus des cartes (trois lignes de liens de 16 px de
  haut). *Différé* : le digest, dont le HTML est écrit une fois, à sa génération, et que le lot 5 de l'audit
  (digest par niveaux) réécrit ; ses tableaux défilent de côté sur téléphone et ses liens vers la veille ne
  disent pas encore qu'ils ouvrent un onglet. *Non vérifié* : un vrai lecteur d'écran.

**A79. Dates et nombres à la française, écrits par un seul paquet.** L'audit de code de novembre 2026
relevait trois formateurs de décimales et deux conventions (le point pour le CVSS et l'EPSS à l'écran et dans
le digest, la virgule pour les jours, les graphiques et le CSV), une alerte qui arrondissait l'EPSS à l'entier,
un CVSS de 0 masqué par le digest mais affiché par l'interface, le format de date répété dans une dizaine
d'endroits, et les fonctions de template (date, statut, sévérité, EPSS) recopiées entre `web` et `digest`. Le
paquet `fr` écrit la convention et l'applique : un jour `09/02/2026` (`Date`, sans changer de fuseau : une
échéance est un jour, pas un instant), sans l'année sur l'axe d'un graphique (`DayMonth`), un moment
`09/02/2026 14:05` en heure locale (`DateTime`) ; la virgule décimale partout, à l'écran, dans le digest, les
alertes et le CSV, sans séparateur de milliers (`Decimal`) ; un score (CVSS, EPSS en pourcentage) à une
décimale, 0 compris, vide s'il est inconnu (`Score`) ; un pourcentage avec une espace avant le signe, `12,3 %`
(`Percent`) ; des jours `< 1 j`, `3,5 j`, `12 j` (`Days`). Les pages et le digest partagent leurs fonctions
de template, sous les mêmes noms : `fr.Funcs` (`date`, `day`, `cvss`, `epss`, `days`, `join`) et
`tracking.TemplateFuncs`, les mots des vulnérabilités (`band`, `sevLabel`, `statusLabel`) ; `fr` n'importe
rien de Vigil, tout paquet peut s'en servir. Restent au point ce que lit une machine : la valeur d'un champ `type="number"`
(format HTML), les coordonnées SVG, le JSON des webhooks ; les dates ISO des exports CSV et des noms de
fichier ne changent pas. Le champ caché du jeton CSRF est un seul modèle, appelé par chaque formulaire :
`{{template "csrf" .CSRF}}`. Les étiquettes proposées sous le champ d'un actif sont lues par le handler ; une
erreur de lecture donne une erreur 500 au lieu d'une page sans suggestions. *Écarté* : le point pour les
scores (l'usage des bases de vulnérabilités, mais deux conventions sur une même page) ; une espace insécable
avant `%` (le reste de l'interface écrit une espace simple ; repris par A84 : `Percent` et `Days` l'écrivent,
car « % » passait seul à la ligne dans une colonne étroite ou une phrase sur téléphone). *Conséquences* : CVSS et EPSS s'affichent `9,8`
et `12,3 %` à l'écran et dans le digest ; un CVSS de 0 s'affiche `0,0`, dans le digest aussi ; l'alerte donne
l'EPSS à une décimale (`EPSS 12,3 %` au lieu de `EPSS 12 %`) ; le CSV ne change pas, il avait déjà la virgule.

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
ponctuelle, Litestream documenté pour le continu. Voir [OPERATIONS.md](OPERATIONS.md). Une seule
rotation sert aux sauvegardes planifiées et aux copies prises avant une mise à jour du schéma : elle
les ordonne par la date écrite dans leur nom, qu'une copie déplacée ou restaurée ne change pas
(les copies `.bak` étaient ordonnées par la date du fichier) ; un fichier dont le nom n'est pas
celui qu'elle écrit, comme une copie faite à la main, n'est ni compté ni effacé ; le fichier
temporaire d'une copie interrompue, copie complète de la base, est retiré après une heure, pour les
copies `.bak` comme pour les sauvegardes.

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
la période de suivi, à date de début fixe. Un CPE ne se découpe qu'à un endroit, `nvd.SplitCPE`,
qui garde les deux-points échappés des noms du dictionnaire (`lemonldap\:\:ng`) et ne rend que
les 13 champs d'un CPE 2.3 : requêtes NVD, recherche dans le dictionnaire, versions corrigées et
éditeur ou produit de l'inventaire l'appellent ; `inventory` l'importe comme il importe déjà `osv`
pour les purl. Écarté : un découpage par « : » à chaque endroit, qui refusait ces CPE au suivi et
les coupait en deux dans la recherche. `SplitCPE` vérifie aussi la forme : champs non vides, partie
`a`, `o`, `h` ou `*`, ni espace ni caractère de contrôle, pas de barre oblique finale. Un actif
n'accepte que ces CPE (`inventory.Validate` ne vérifiait que le préfixe `cpe:2.3:`, et la NVD
refusait les autres à chaque synchronisation) ; le CPE mal formé d'un composant de SBOM est retiré,
le composant gardé par son purl. Un nom d'éditeur ou de produit s'affiche sans ses échappements
(`nvd.Unescape` : `lemonldap::ng`, `At&t`), la valeur stockée et envoyée à la NVD les gardant.

**A12. Un actif avec purl et CPE n'est interrogé que par son purl.** Interroger les deux
doublerait les alertes (GHSA et CVE pour la même faille) et le CPE est moins précis. Il n'y a pas
de rapprochement entre deux actifs distincts décrivant le même produit : la consigne est d'en
déclarer un seul.

**A51. Version `latest` : seules les vulnérabilités sans version corrigée connue.** Un service
en ligne, un navigateur ou un logiciel mis à jour automatiquement n'a pas de version stable à
déclarer. Résoudre « la dernière version » demanderait un registre par écosystème (et n'existe pas
pour les produits) ; Vigil lit plutôt l'avis lui-même : l'actif est affecté si une plage reste
ouverte. OSV : la dernière étape d'une plage du paquet est `introduced` (aucun correctif) ou
`last_affected` (affectée jusqu'à une version, sans correctif indiqué : prudence). NVD : produit
affecté sans borne haute ; une borne incluse (« jusqu'à 7.2.13 ») vaut correction dans la version
suivante, car c'est ainsi que les bulletins d'éditeurs (Fortinet, Oracle, Adobe) sont transcrits ;
la traiter comme ouverte signalerait presque toutes leurs CVE. Pour un paquet, OSV est interrogé
sans version (`/v1/query`, avis complets, un appel par paquet) et seuls les avis retenus sont
stockés. *Conséquence* : quand le correctif sort, la source le signale et la vulnérabilité est
résolue automatiquement (A14), ce qui correspond à un actif qui se met à jour. Un correctif
publié mais pas encore installé n'est pas signalé : c'est l'hypothèse même de `latest`.

**A52. Détection par le nom, sans purl ni CPE.** Beaucoup d'actifs sont saisis par leur seul nom :
ils n'étaient pas vérifiés. Ils sont désormais cherchés dans les descriptions des CVE de la NVD
(phrase exacte, `keywordSearch` + `keywordExactMatch`, même période de suivi et même requête KEV
qu'un CPE). Un essai réel a montré le bruit d'une recherche brute : 176 CVE pour « Apache HTTP
Server 2.4.62 », dont Shellshock et des CMS qui citent simplement le serveur. Règles retenues :
une CVE analysée n'est gardée que si un de ses produits correspond au nom (tous les mots du nom
dans l'éditeur et le produit du CPE, ou tous les mots du produit dans le nom) et que la version
de l'actif est dans une de ses plages, ou est la version citée (mise à jour comprise :
`22.7:r2.1` pour Ivanti 22.7R2.1, `22.7:-` pour la 22.7 seule) ; une CVE en attente d'analyse
(sans configuration) est gardée, ce qui fait remonter les failles récentes avant la NVD. Résultat
sur le même essai : 65 CVE pour Apache, 36 au lieu de 56 pour Ivanti Connect Secure 22.7R2.3,
toutes postérieures à la version. Les composants de SBOM sans purl sont exclus (noms génériques,
volume). *Conséquence* : résultats à vérifier, signalés comme tels ; un nom qui ne correspond à
aucun produit de la NVD (« FortiGate » pour `fortios`) ne garde que les CVE en attente d'analyse :
le CPE reste la voie précise. Le nom part à la NVD (modèle de menace).

**A53. Suffixes de version : mise à jour au-dessus, pré-version en dessous.** La comparaison
plaçait toute lettre après les chiffres en pré-version (1.4.0-beta1 < 1.4.0), donc 22.7R2.3
avant 22.7 : une CVE « avant 22.7 » touchait à tort Ivanti 22.7R2.3. Seuls les libellés connus de
pré-version (alpha, beta, rc, dev, snapshot, preview…, et a, b, c, m suivis d'un nombre : 2.0a1,
3.0-M1) restent en dessous ; les autres sont des mises à jour (22.7R2, 9.5p1 d'OpenSSH, 1.1.1w
d'OpenSSL, 2.4.0-r1 d'Alpine). La comparaison ignore la casse.

**A54. Tri par les titres de colonnes et filtres en listes, sans JavaScript.** Chaque titre de
colonne est un lien (`?sort=…&dir=…`) qui garde les filtres et inverse l'ordre au second clic ;
`aria-sort` et la feuille de style disent l'ordre courant. Le tri se fait en Go sur la liste chargée
entière (un tri SQL ne saurait pas comparer des versions, A53, ni l'ordre des statuts et des
criticités) ; depuis A85, seule la page rendue est ensuite coupée. Les valeurs absentes restent en fin de liste dans les deux sens. CVSS et EPSS
deviennent des colonnes, ce qui remplace la liste « Tri » du formulaire. Sur téléphone, les titres
restent visibles au-dessus des cartes. Dans l'inventaire, projets et étiquettes passent de rangées
de liens, d'autant plus hautes que l'inventaire est varié, à deux listes déroulantes combinables ;
sans JavaScript, elles demandent un clic sur « Filtrer ». Les raccourcis des vulnérabilités, en
nombre fixe et d'un seul clic, restent des liens, sur la ligne des boutons du formulaire.

**A55. Paquets de distribution : silence ou faux positifs, selon la façon de les interroger.** Le
noyau d'une distribution n'était jamais détecté, et il a révélé des causes générales. D'abord,
`querybatch` rend mille avis par requête, triés par identifiant, et le jeton de page suivante était
ignoré : pour `linux` dans Debian (14 855 avis pour une version), la première page s'arrête à des CVE de
2023, toutes hors de la période de suivi ; `chromium` dépasse aussi la limite. Suivre le jeton puis
télécharger chaque avis demanderait près de 15 000 requêtes : quand une réponse a une suite, l'actif est
relu par `/v1/query`, qui rend les avis entiers, et seuls ceux publiés dans la période de suivi ou
exploités (KEV) sont stockés. Depuis A90, cette lecture complète n'est refaite que si la liste légère
de `querybatch`, suivie de page en page, a trop changé ; sinon seuls les avis nouveaux ou modifiés
sont téléchargés. La date de modification ne permet pas de les écarter plus tôt : presque
tous ont été modifiés dans les 120 derniers jours. Une page pouvant dépasser 64 Mo, elle est lue avis
par avis. Ensuite, OSV ne rend rien pour un purl Debian qui porte le qualificatif `distro`, présent sur
tous les paquets des SBOM, et il ne connaît que les paquets sources (`openssl`, pas `libssl3`) : les
qualificatifs sont retirés, `upstream` (Syft) et la propriété `SrcName` (Trivy) donnent le paquet
source, et une petite table ramène les paquets binaires du noyau au leur, car `linux-signed-amd64` n'est
pas plus connu d'OSV. Enfin, sans la version de la distribution, la version de l'actif est comparée aux
avis de toutes les autres, où toute version de Debian 12 est inférieure au correctif de Debian 14. Sur
120 jours, `linux` en donne 5 636 pour la 6.1.76-1 comme pour la 6.1.170-1, alors que `Debian:13` passe
de 4 463 en 6.12.60-1 à 676 en 6.12.113-1. Alpine ne répond rien du tout sans elle. Le qualificatif
`distro` devient donc l'écosystème de la version (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.18`) ; le
formulaire propose ces écosystèmes, et la page d'un actif signale ceux qui n'en ont pas. Red Hat reste
global : ses écosystèmes dépendent du dépôt (`Red Hat:enterprise_linux:9::baseos`). Le champ `upstream`
des avis sert d'alias : c'est par lui que `DEBIAN-CVE-…` reçoit ses signaux KEV et EPSS.

**A56. Le noyau Linux est un paquet comme un autre.** Une première version le traitait à part (noms
reconnus, CPE détournés, NVD en complément), pour un seul produit et avec autant de cas à expliquer. Le
modèle reste donc unique : `linux` dans `Debian:13`, `kernel` dans `AlmaLinux:9`, ou `Kernel` dans
l'écosystème `Linux` pour le noyau officiel. Cet écosystème n'a qu'une particularité, exprimée de façon
générale par `osv.ComparesVersions` : OSV y a les plages de kernel.org, par branche stable, mais ne les
compare pas à la version demandée. Le paquet est alors lu en entier (31 000 avis, 150 Mo, moins de
3 minutes), une fois par synchronisation quel que soit le nombre d'actifs, et comparé ici par le code
qui sert déjà à `latest` (A51). *Conséquences* : un CPE `linux_kernel` ne voit que ce que la NVD a analysé
(979 CVE sur 120 jours, contre 5 648 citant « Linux Kernel ») et un actif seulement nommé ainsi garde
toutes celles sans analyse : le formulaire et le README orientent vers l'écosystème. Ce dernier ne couvre
que ce que kernel.org a publié (pas CVE-2024-1086, exploitée, antérieure à son rôle d'autorité), que la
voie par distribution voit. Sur le noyau officiel, les correctifs reportés par une distribution sont
inconnus : le noyau d'une distribution doit rester un paquet de celle-ci.

**A57. Avancement et échecs visibles.** Une synchronisation pouvait durer sans autre indication
que son heure de début, et un actif qu'une source n'avait pas pu vérifier ne laissait qu'une ligne de
journal : la NVD répond souvent 503 un moment, et une seule requête perdue sur les sept d'un actif
suffisait. L'état indique désormais le nombre d'actifs vérifiés, ce qui est en cours et une barre
(`<progress>`, aucun JavaScript) ; le tableau de bord et la page de suivi se rechargent seuls, mais
pas l'inventaire ni les vulnérabilités, où cela ferait perdre une saisie. La NVD est réinterrogée après
une panne passagère (10 puis 30 secondes), OSV aussi (5 puis 15 secondes), où un seul incident réseau
sur la requête groupée faisait échouer toute la synchronisation. Les actifs non vérifiés sont comptés dans le résultat,
avec la raison pour qui peut agir, et gardent leurs vulnérabilités. La limite d'une synchronisation
lancée depuis l'interface passe de 15 minutes à 2 heures : sans clé NVD, une vingtaine d'actifs suivis
par CPE ou par nom la dépassaient, et tout le résultat était perdu.
*Une transaction par actif* (audit du code de la 0.4.2, D4, décision de novembre 2026). Chaque avis,
chaque vulnérabilité trouvée et chaque signal KEV ou EPSS était écrit dans sa propre transaction,
donc avec une écriture forcée sur le disque : environ 3,3 s pour enregistrer les 3 000 avis d'un
paquet sur un poste de développement, 1,9 s pour les retrouver inchangés ; 0,34 s et 0,22 s
désormais (`BenchmarkSync`). Les écritures d'un actif sont groupées (`Store.InTx`) : ses vulnérabilités
trouvées, rouvertes ou résolues et le nombre d'avis plus anciens que sa période, en une transaction,
après les lectures dont elles dépendent ; ses avis, en une transaction une fois toutes ses sources
lues, par lots de 500 (ou 8 Mo) pour une liste longue, car un seul avis à la fois est lu du réseau
(A62). Un échec annule le lot de cet actif seulement : il est compté « non vérifié » avec la raison,
garde ses vulnérabilités telles qu'elles étaient, et les autres actifs continuent (une erreur
d'écriture arrêtait toute la synchronisation, en laissant l'actif à moitié enregistré). Les avis
d'un actif dont une source échoue en cours de lecture ne sont pas gardés. Le réseau n'est jamais lu
pendant une transaction : elle tient la seule connexion à la base (A5), que l'interface attend.
Écartés : une transaction pour toute la synchronisation (une panne en fin de course perdrait tout,
et l'interface attendrait des minutes) ; garder tous les avis d'un actif en mémoire jusqu'à la fin,
contraire à A62 pour un noyau ; une transaction tenue pendant la lecture d'OSV, qui bloquerait
l'interface pendant des minutes. La migration 016 ajoute les deux index qui manquaient : l'historique
d'une vulnérabilité (sa page, les règles d'écart à chaque synchronisation, la suppression d'un actif)
et les vulnérabilités qu'écarte une règle ne sont plus lus en parcourant toute la table
(`TestHistoryQueriesUseIndexes`).

**A60. Un seul classement, en quatre niveaux.** Les raccourcis (non traitées, prioritaires, critiques
et hautes, hors délai) se recouvraient et ne disaient pas où commencer, surtout sur les volumes d'un noyau.
Quatre niveaux exclusifs les remplacent, calculés pour tout produit : Urgentes, À planifier, À surveiller,
Écartées, avec leur nombre. Ce sont les classes des alertes (A37) : une alerte et un niveau disent la même
chose. Le CVSS seul ne trie pas : sur le noyau Debian 6.12.60-1, 90 % des CVE notées sont à 7 ou plus, plus de la
moitié ne sont pas notées, et les 4 exploitées ne sont pas à 9. *Conséquence* : le niveau À planifier reste
gros sur un vieux noyau ; c'est la mise à jour qui le réduit, pas le classement. Les délais de traitement et
le filtre « Hors délai » restent, dans les filtres. Depuis A78, le niveau se lit sur la classe d'alerte
calculée par la requête (`Finding.Class`), au lieu d'une copie de la règle en Go, et le statut Exploitable
range une vulnérabilité parmi les Urgentes.

**A61. Écarter par un texte, pas par une notion de composant.** Une version ne dit pas si un composant est
présent : sur un serveur sans ces matériels, `drm`, `wifi` ou `bluetooth` pèsent au moins un quart des CVE du
noyau, qui sont de vrais faux positifs. Une première idée les regroupait par composant, en analysant le début
des descriptions : c'était propre au noyau, et approximatif. Le mécanisme retenu vaut pour tout produit : un texte
cherché dans l'identifiant et le résumé (ce que l'analyste voit), sur un actif. On voit la liste avant d'écarter.
Elles passent en « Non affecté – code vulnérable absent », avec la règle dans leur historique, donc dans le
VEX ; la règle s'applique aux suivantes, avant les alertes. Trois garde-fous : une vulnérabilité exploitée ou
probable reste visible et revient si elle le devient, une décision prise par quelqu'un n'est jamais changée, et
supprimer la règle défait ce qu'elle a fait.

**A62. Une base qui reste légère : ne garder d'un avis que ce qui est relu.** Lors de l'essai réel de
la 0.4, la base pesait 1,9 Go pour 8 actifs : 3 146 avis Ubuntu de 600 Ko chacun, listant 257 paquets avec
leurs binaires et leurs versions. Chaque sauvegarde et chaque copie de mise à jour héritait de ce poids.
Vigil ne relit de ces avis que les plages de versions, pour indiquer le correctif : le reste figure déjà dans
ses colonnes, ou n'est jamais lu. Seuls l'identifiant, les paquets et leurs plages sont donc stockés
(`osv.Vuln.Compact`). Une fiche déjà en base garde son ancienne forme jusqu'à sa prochaine modification
chez OSV. Pour ne pas relire un gros paquet inchangé, la liste d'A90 garde aussi, de chacun de ses avis
signalés, gardé ou non, l'identifiant, les deux dates et les autres identifiants : 1,4 Mo pour ce noyau. Autre effet du volume : les tris et les sauvegardes peuvent écrire des fichiers temporaires, or le
conteneur a un système de fichiers en lecture seule. Les données temporaires restent donc en mémoire
(`temp_store`).

**A90. Un gros paquet n'est relu que pour ce qui a changé.** Le noyau Ubuntu 22.04 de la base de l'audit
faisait lire 4,5 Go à OSV à chaque synchronisation : 8 212 avis de 550 Ko en moyenne, 63 pages de
`/v1/query`, de 25 à 55 minutes selon la charge d'OSV ; toutes les 6 heures, 18 Go par jour pour un seul
actif (Debian 13 : 49 Mo).
A55 relisait tout parce que suivre le jeton de `querybatch` puis télécharger chaque avis coûterait près de
15 000 requêtes. Mais cette liste légère (identifiant et date de modification, mille par page) ne pèse que
593 Ko pour ce noyau, en 9 pages et 40 secondes, et dit ce qui a changé. La synchronisation garde donc,
pour chaque requête de ce genre (paquet, écosystème, version), ce qu'il lui faut de chaque avis signalé :
identifiant, dates de modification et de publication, autres identifiants (alias, avis d'origine),
vérifiés comme ce que la base garde (A69, `listed.checked`). C'est
ce que demandent la période de suivi et sa garde KEV et EPSS (A31) et le repli d'une CVE (A80), y compris
pour les avis que la base ne garde pas (A62) : table `osv_lists`, migration 020, 1,4 Mo pour ce noyau.
À la synchronisation suivante, d'après la liste légère :
- rien n'est téléchargé si elle n'a pas changé : avis signalés, période, garde KEV et EPSS et repli sont
  calculés comme après une lecture complète, la liste tenant lieu des avis ;
- les avis nouveaux ou modifiés sont lus un à un (`/v1/vulns`), ainsi que ceux que l'actif peut désormais
  signaler sans les avoir en base (période reculée, CVE devenue exploitée) ; un avis ancien probablement
  exploité (A31) n'est plus retéléchargé à chaque fois s'il est en base tel quel ;
- le paquet est relu en entier, comme avant : sans liste (première synchronisation, autre version), si la
  liste légère ne peut être lue, si plus d'un dixième des avis sont à relire, et une semaine après la
  dernière lecture complète.
Les actifs qui posent la même requête (deux serveurs au même noyau) partagent la liste : le second ne
relit rien, au lieu de 4,5 Go chacun. La liste est enregistrée avec les avis de l'actif, dans la
transaction de son dernier lot (A57), et n'est pas gardée si une source échoue : l'actif reste « non
vérifié », comme avant. *Le dixième* : un avis Ubuntu se lit seul en 0,65 s, contre 0,2 à 0,4 s dans une
lecture complète, un avis Debian en 0,2 s contre 6 ms ; en deçà, les lectures une à une coûtent au plus un
dixième des octets d'une lecture complète, et 2 à 3 minutes au plus pour un noyau Debian (697 avis). *La semaine* : si OSV
modifiait un avis sans changer sa date, ou si la liste dérivait, l'écart durerait une semaine au plus, pour
une lecture complète par semaine au lieu de quatre par jour. *Correction* : OSV écrit la date de
modification à la microseconde dans `querybatch` et à la nanoseconde dans un avis ; la comparaison
littérale retéléchargeait à chaque synchronisation les avis inchangés d'un petit paquet dont la date a des
nanosecondes (`osv.SameModified` compare désormais toutes ces dates). *Écartés* : une empreinte par actif,
qui dirait seulement si la liste a changé, alors que KEV et EPSS changent sans que l'avis change et que le
repli a besoin des avis non gardés ; la liste en mémoire, perdue à chaque redémarrage et inutile à
`vigil sync` ; une liste par actif ; repartir du jeton de la réponse groupée du début de la
synchronisation, qui a pu expirer quand vient le tour de l'actif, pour économiser une page de 70 Ko ; pour
un avis modifié que la base ne garde pas, se fier à ses dates et alias d'avant (ils ne changent presque
jamais, mais rien ne le garantit) ; l'archive de tout l'écosystème, sur un autre hôte et de plusieurs Go.
*Conséquences*, mesurées sur une copie de la base de l'audit (noyaux Ubuntu 22.04 et Debian 13), deux
synchronisations de suite : avant, 4,5 Go et 54 à 55 minutes pour le noyau Ubuntu (63 pages et 9 avis
probables retéléchargés), 50 Mo et 42 à 54 secondes pour le noyau Debian, à chaque fois ; désormais, la
première lit autant, la suivante 593 Ko en 40 secondes et 504 Ko en 28 secondes (la synchronisation
entière : 80 secondes au lieu de 55 minutes), et trouve exactement les mêmes vulnérabilités, statuts,
versions correctives, replis et avis en base que deux lectures complètes. 20 avis Ubuntu modifiés coûtent
20 requêtes, 10 Mo et 13 secondes. Mais Ubuntu régénère les avis de tout son noyau à chaque publication
d'un de ses noyaux : 8 095 des 8 215 avis de cette version ont changé de date le 12 novembre 2026, et
l'historique du dépôt d'Ubuntu en compte 56 en 104 jours, dans 56 des 414 créneaux de 6 heures. La lecture
complète reste donc due environ une synchronisation sur sept pour ce noyau, soit 2,5 Go par jour au lieu
de 18 ; seule une source aux dates plus stables ferait mieux. La première synchronisation après la mise à
jour lit tout, faute de liste. Les paquets lus en entier d'emblée (`latest`,
écosystème `Linux`, A51 et A56) ne sont pas concernés : leur liste devrait garder les plages de chaque avis.

**A63. Une seule version fait foi : le champ Version.** Un actif peut porter sa version à deux endroits : le
champ Version et le purl. Le purl l'emportait : changer le champ Version laissait OSV interrogé sur l'ancienne
version, et la vulnérabilité restait ouverte alors que la page affichait la nouvelle. Le champ Version, celui que
l'on met à jour et que les pages affichent, l'emporte désormais dès qu'il diffère du purl (`osv.PURLQuery`), y
compris sur la version du paquet source (`upstream=glibc@2.36`). Le purl n'est pas réécrit : il reste la clé
d'un composant de SBOM. La règle s'appliquant à la requête, elle vaut aussi pour les actifs déjà en base. Pour
qu'une modification du seul purl garde son effet, le champ la reprend à l'enregistrement
(`inventory.FollowPURL`). *Conséquence* : une page peut montrer un purl et une version différents ; c'est la
version qui est vérifiée. Un SBOM qui sépare l'époque de la version (`1:3.0.7`, purl `@3.0.7?epoch=1`) est
désormais vérifié avec son époque.

**A64. La version corrective est enregistrée à la synchronisation.** Les tableaux de vulnérabilités indiquent,
pour chaque ligne, la version qui la corrige pour l'actif (colonne « Corrigée en », export CSV). La relire dans
l'avis à chaque affichage prendrait 0,9 s pour les 3 162 vulnérabilités d'un noyau Ubuntu, dont les avis pèsent
50 Ko en moyenne (34 ms pour les 4 467 d'un noyau Debian). Elle est donc calculée à la synchronisation, par la
règle de la page d'une vulnérabilité (`tracking.FixedIn` : la fin des plages qui contiennent la version de
l'actif), et gardée avec elle (`findings.fixed_in`). *Conséquences* : la colonne se remplit à la première
synchronisation après la mise à jour ; une vulnérabilité que la source ne signale plus garde la dernière
valeur connue, et celles déjà corrigées avant la mise à jour restent vides. Un actif à sa dernière version
(`latest`) n'en a pas : ses plages sont les ouvertes.

**A65. Un texte se mesure en caractères, et ne se coupe jamais au milieu d'un.** Neuf fonctions
raccourcissaient un texte, en octets ou en caractères ; trois coupaient au milieu d'un caractère accentué et
laissaient de l'UTF-8 invalide en base, et une analyse VEX accentuée, coupée à 4 000 caractères, était refusée
à 4 000 octets. Le paquet `clip` les remplace : les limites sur ce qu'écrivent les utilisateurs et les sources
comptent des caractères (`Text`, `Prefix`, `Fits`) ; seul le budget d'un message envoyé ailleurs reste en
octets (`Bytes`). *Conséquence* : les limites de saisie déjà comptées en octets (nom d'utilisateur, projet)
restaient à harmoniser ; c'est fait depuis l'audit de code de novembre 2026 (nom d'utilisateur, noms de flux,
de canal et de jeton, projet, filtre d'étiquette, dans l'interface comme en ligne de commande), avec une
constante par limite partagée (`auth.MaxUsernameLength`, `inventory.MaxProjectLen`, et `clip.MaxName` pour les
noms de flux, de canal, de jeton et de groupe, qui avait deux copies, revue 0.5.0, W10). Seul le mot de passe
reste borné en octets (`auth.MaxPasswordBytes`), car la borne porte sur ce que reçoit argon2.

**A66. La liste des vulnérabilités s'ouvre sur ce qui reste à traiter.** Elle montrait tout par défaut, y
compris les corrigées, et les nombres des niveaux ne faisaient pas son total. Elle s'ouvre désormais sur les
ouvertes, la somme des trois premiers niveaux ; les corrigées ont leur onglet, « Toutes » réunit tout. Un filtre
de statut garde la liste entière, pour qu'un statut demandé (« Corrigé ») soit montré. L'export suit la page.
Depuis A84, les écartées et les corrigées forment un groupe à part, et « Toutes » n'est plus qu'un lien discret.

**A84. Un seul vocabulaire, celui des niveaux, et la raison de chacun.** L'audit d'ergonomie de la 0.4.1
(lot 2) relevait quatre noms pour un même concept (« À traiter en priorité », « Urgentes », « Prioritaire »,
« Exploitées ou probables ») et deux URL (`priority=1`, `level=urgent`), une colonne Priorité qui affichait la
sévérité (« Moyenne » dans les Urgentes), une page de vulnérabilité qui ne disait jamais son niveau ni pourquoi,
des tableaux du tableau de bord qui mêlaient les corrigées, et un lien « de la semaine » qui ouvrait toute la liste.
- *Un mot, une URL* : « Urgentes » et `level=urgent` partout : carte du tableau de bord, titre et liens des
  alertes (« 3 vulnérabilités urgentes et 2 à planifier », un lien par niveau annoncé), réglages des canaux
  (« Urgentes seulement », « Urgentes et À planifier », « Aucune alerte immédiate »). La case « Prioritaire »
  quitte les filtres, et `FindingFilter.Priority` le stockage : le niveau la remplace. Les liens déjà envoyés
  (`/findings?priority=1` des alertes, favoris) sont redirigés pour de bon (301) vers `level=urgent`, leurs
  autres filtres gardés ; l'export CSV de même.
- *La raison vient de la règle du classement* : chaque ligne commence par la pastille de son niveau, puis la
  bande de sévérité et ce qui rend la vulnérabilité urgente (« exploitée (CISA KEV) », « jugée exploitable »,
  « EPSS 12,3 % ») ou, à planifier par son seul score, « CVSS 7,5 ». La page d'une vulnérabilité s'ouvre sur
  « Niveau : Urgente, car la probabilité d'exploitation EPSS est de 74,8 % (seuil 10,0 %) ». Ces textes
  (`tracking.Reason`, et `explain` pour la page) lisent la règle là où elle est : `urgency`, la première clé de
  `ComparePriority`, et le niveau (`Level`, la classe d'alerte). L'alerte emploie `Reason`, qui remplace sa
  copie de la règle. Le seuil CVSS de la classe « sévère » est écrit une fois, `store.SevereCVSS`, comme
  `LikelyEPSS`. Une vulnérabilité écartée ou corrigée garde « exploitée (CISA KEV) » comme fait, à la place de
  l'ancienne mention « Exploitée ».
- *Pastilles* : Ouvertes (défaut, la somme des trois niveaux ouverts) · Urgentes · À planifier · À surveiller,
  puis, séparées, Écartées · Corrigées ; « Toutes » devient un lien discret. Les trois groupes font le total.
- *Tableau de bord* : les nouvelles vulnérabilités sont les ouvertes, comme la liste où elles mènent ; le lien
  « Voir les N vulnérabilités ouvertes de la semaine » porte un vrai filtre de période, `since=7` (en jours, de
  1 à 3 650, un champ des filtres), au lieu de la liste entière triée par date. L'anneau mène aux ouvertes d'une
  sévérité sans filtre de statut, donc avec la pastille « Ouvertes ».
- *Mots* : « Plus de filtres (2 appliqués) » au lieu de « (actifs) », qui se lisait « filtres d'actifs » ;
  « Activé » / « Désactivé » pour un compte. CVSS et EPSS sont alignés à droite et ne se coupent pas (classe
  `num`, `white-space: nowrap`), la raison d'une ligne non plus. Dans une phrase (« … est de 74,8 % » sur la
  page d'une vulnérabilité, à 375 px), « % » passait encore seul à la ligne : `fr.Percent` et `fr.days`
  écrivent une espace insécable avant leur unité, ce qu'A79 avait écarté.

*Écarté* : garder `priority=1` comme synonyme silencieux de `level=urgent` (deux URL pour une liste, et le
formulaire de filtres l'aurait perdu) ; écrire le seuil dans la raison d'une ligne (« EPSS ≥ 10 % », comme la
maquette) : la valeur sert telle quelle à l'alerte, qui n'a pas de colonne EPSS, et le seuil est sur la page de
la vulnérabilité ; garder la case « Prioritaire » à côté du niveau. *Conséquences* : les alertes changent de
titre et de lien (une alerte d'un canal « Urgentes et À planifier » donne un lien par niveau) ; leur JSON garde
ses champs, et `reason` dit « CVSS 7,5 » pour une vulnérabilité à planifier par son score. Les pourcentages et
les jours portent une espace insécable (U+00A0) à l'écran, dans le digest et les alertes ; les nombres écrits en
dur dans les gabarits (« 88 % » de couverture) gardent une espace simple.

**A85. La liste tient le volume : des pages après le tri, des décisions sur toute la liste.** L'audit
d'ergonomie de la 0.4.1 (lot 3) mesurait 7 629 lignes, 6,6 Mo de HTML et 900 000 px pour la liste d'un noyau ;
le triage par lot se cochait ligne à ligne (500 au plus), perdait cases et choix à la moindre erreur, et la page
d'une vulnérabilité ramenait à la liste sans ses filtres.
- *Pages* : la liste est lue, filtrée et triée en entier, en Go (A54), puis seule une page de 100 lignes est
  rendue (`?page=`, « lignes 101 à 200 sur 3 235 », Précédente / Suivante ; un numéro hors bornes montre la page
  la plus proche). Les nombres des niveaux, l'export CSV, la décision sur toute la liste et « Suivante dans la
  liste » lisent la liste entière, par une seule fonction (`listedFindings`) ; changer d'ordre ou de niveau
  revient à la première page. La page d'un actif était coupée de même (`paginate`, commun) ; depuis A86, elle
  ne montre plus que ses dix plus urgentes, et seul l'aperçu d'une règle d'écart y est paginé. La veille, plafonnée à
  200 actualités, a repris `paginate` au lot 5 de l'audit (A87).
  Mesure, copie de la base noyau, page « À planifier » (3 235 vulnérabilités), poste de développement : 2,68 Mo
  et 0,27 s avant, 0,11 Mo et 0,18 s après ; « Toutes » (7 629) : 6,43 Mo et 0,44 s avant, 0,11 Mo et 0,20 s après.
- *Traiter la sélection* : le panneau reste collé au bas de l'écran, sous les cases, et propose « les lignes
  cochées » ou « toute la liste filtrée (N), toutes pages comprises », la liste étant celle que décrit déjà le
  champ `next`. Sur toute la liste, les garde-fous des règles d'écart (A61) : ce qu'une personne a déjà décidé
  ne change pas (`decidedExpr`, désormais partagé avec les règles, par `StatusChange.KeepDecided`), ni ce qui a
  déjà ce statut ; au-delà de 50 vulnérabilités, la page revient avec le nombre exact à confirmer (« Confirmer
  pour 3 235 vulnérabilités »), et une liste qui a changé entre-temps redemande la confirmation. Une
  transaction pour toute la liste : 0,6 s pour 3 235 vulnérabilités sur la base noyau. Le journal d'audit
  donne le nombre changé et celui de la liste (`count=… status=… list=…`).
- *Une décision refusée* (justification manquante, rien de coché) réaffiche la liste d'où elle vient, avec
  les cases cochées, le statut, la justification, le commentaire et la portée choisis, le panneau ouvert et le
  message sous le champ fautif (`tracking.StatusError` nomme le champ ; `aria-invalid`).
- *Retour à la liste* : chaque ligne mène à sa vulnérabilité avec `?back=` (la liste, filtres, ordre et page
  compris), validé par la même liste blanche que `next` (`listPath` : `/findings` ou `/findings?…`, sinon la
  liste par défaut). La page offre « Retour à la liste » et « Suivante dans la liste » ; après « Enregistrer »,
  elle revient avec les deux, la suivante étant lue avant que la décision sorte la vulnérabilité de la liste
  (`then=`). Cela coûte une lecture de la liste entière (0,17 s sur la base noyau), une seule par décision :
  la page qui suit l'enregistrement reprend `then` sans relire la liste (revue de la 0.5.0, W12).
- *VEX* : « Exporter les analyses en VEX » et « Importer un VEX… » rejoignent l'export CSV au-dessus du tableau ;
  l'export dit qu'il prend toutes les analyses (ou celles du projet), sans les autres filtres.

*Écarté* : paginer en SQL (`LIMIT`) : le tri est fait en Go (A54), et les nombres des niveaux comme la décision
sur toute la liste veulent la liste entière ; une case « tout cocher » (impossible sans JavaScript, et bornée à
une page) ; une confirmation `<details>` dont le nombre aurait été celui de l'affichage, pas celui de l'envoi ;
déplacer l'import VEX sur « Ajouter des actifs » (il n'ajoute pas d'actif ; confirmé par A88) ; le
`Referer` pour le retour à la liste (absent selon les navigateurs et la politique de référent). *Conséquences* :
les cases cochées valent pour la page affichée (changer de page les perd, faute de script) ; une décision sur
toute la liste compte comme décision humaine pour les suivantes et pour les règles d'écart ; le rechargement
d'une liste réaffichée après refus renvoie le formulaire (comme toute réponse à un envoi), sans effet tant
qu'il est refusé ou demande confirmation.

**A86. La page d'un actif résume par niveau, sa liste détaille ; le bruit s'écarte d'où on le voit.** L'audit
d'ergonomie de la 0.4.1 (lot 4) trouvait sur la page du noyau Debian 6.12.60-1 des milliers de lignes dans l'ordre
des identifiants, ses 4 urgentes noyées dedans, sans nombre ni lien vers une liste triable : `/findings` n'avait
pas de filtre par actif. L'inventaire ne disait pas quels actifs sont exposés, les règles d'écart (A61) ne se
trouvaient qu'après une recherche sur la page d'un actif, et « Suivre tout l'historique » ajoutait d'un clic des
milliers de vulnérabilités et leurs alertes.
- *Filtre `asset=`* : la liste des vulnérabilités se filtre sur un actif (`FindingFilter.AssetID`, déjà là) ; ses
  niveaux, son ordre, ses filtres, sa pagination, son export et la décision sur toute la liste le gardent, tous
  lisant `listedFindings`. L'actif est nommé en tête (« Vulnérabilités de l'actif linux 6.12.60-1 · tous les
  actifs ») ; le formulaire de filtres et « Réinitialiser » le gardent. *Sécurité* : la portée de la requête est
  dans la requête de la liste (A67) ; un actif hors du périmètre du compte donne une liste vide et « Actif
  introuvable », comme un actif qui n'existe pas, sans son nom (vérifié avec le témoin d'un autre groupe : liste,
  export, décision sur toute la liste).
- *Page d'un actif* : cinq compteurs (Urgentes, À planifier, À surveiller, Écartées, Corrigées), chacun lien vers
  la liste de l'actif à ce niveau. La page lit la liste de l'actif par `listedFindings` et ses compteurs par
  `levelLinks`, comme la liste : un nombre est la longueur de la liste où il mène. Puis « À traiter d'abord » :
  les dix ouvertes les plus urgentes dans l'ordre du classement (A78), donc les urgentes en tête, avec « Voir les
  N urgentes » et « Toute la liste de cet actif : tri, filtres, traitement par lot ». Mesure, copie de la base
  noyau, poste de développement : 86,8 Ko (100 lignes, première page) avant, 19,6 Ko (10 lignes et les
  compteurs) après, 0,04 à 0,06 s dans les deux cas.
- *Écarter le bruit* : un bloc permanent pour les analystes, avec des exemples (`wifi`, `bluetooth`, `drm`), la
  recherche, le nombre trouvé, le bouton, les règles en place et « Réversible : supprimer la règle rétablit ces
  vulnérabilités » ; sans résultat, « Aucune vulnérabilité ne contient « x509 » maintenant : la règle vaudra pour
  les prochaines ». L'aperçu de ce que la règle écarterait reste sur la page, paginé (on voit avant d'écarter).
  Depuis la liste, une recherche (`q=`) propose, par actif concerné, un lien vers cet aperçu : sur la base
  noyau, « Écartez « bluetooth » sur un actif : linux 6.12.60-1 (148) · linux 5.15.0-100.110 (70) ». Ni un actif dont le nom contient le texte (la recherche l'a trouvé par
  son nom, qu'une règle ne lit pas), ni un texte qui ne peut pas être une règle (`fitsRule`, la borne de la
  création) ne sont proposés. Un lecteur voit les règles, pas le bloc.
- *Suivre tout l'historique* : une confirmation `<details>` qui dit le nombre (« Ajouter les 2 487 vulnérabilités
  publiées avant le 08/07/2026, et les alertes qui vont avec ? »), comme les suppressions (A33).
- *Inventaire* : colonnes triables « Urgentes » et « Ouvertes », liens vers la liste de l'actif, lues par une
  requête groupée par actif (`AssetLoads`, celle des actifs les plus exposés du tableau de bord, étendue à tous
  les actifs et à leurs urgentes par `urgentExpr`, la règle des niveaux) ; champ « Chercher un actif » (nom, purl
  ou CPE). Le tableau de bord, qui ne montre pas les urgentes par actif, ne les compte pas : sur la base noyau,
  les lire coûte 0,09 s, les signaux d'exploitation d'une vulnérabilité étant rangés après son avis dans la
  ligne. L'inventaire passe de moins de 0,02 s à 0,16 s sur cette base, le tableau de bord ne change pas.
- *Page d'une vulnérabilité* : titrée par sa CVE seulement quand l'avis n'en nomme qu'une (« CVE-2026-0001
  (RHSA-2026:0001) ») ; un avis de plusieurs CVE garde son nom (USN-8875-1, pas la première de ses 1 902 CVE).
  Au-delà de 20 alias, les trois premiers et un `<details>` pour les autres. L'échéance de traitement disparaît
  quand la vulnérabilité n'est plus ouverte ; une échéance CISA dépassée le dit en rouge. Liens « CVE-… sur tous
  les actifs » (la recherche de la liste) et, pour l'avis d'une distribution ou d'un registre, dont le résumé
  décrit souvent la mise à jour, « Description de CVE-… dans la NVD ».
- *Version vérifiée* : quand le purl porte une autre version que le champ Version (A63), l'inventaire et la page
  de l'actif l'écrivent sous le purl (`inventory.CheckedVersion`).
- *Avis récapitulatifs* (constat 4.7) : réglé par A80, une ligne par CVE, les avis groupés repliés.

*Écarté* : garder la liste complète sur la page de l'actif à côté du lien (deux listes, dont une sans tri ni
lot) ; n'y montrer que les urgentes (un actif sans urgente n'aurait rien à montrer, et ses dix plus urgentes
commencent par elles) ; deux colonnes côte à côte comme la maquette (un tableau de dix colonnes ne tient pas dans
trois cinquièmes de page) ; compter les vulnérabilités de chaque actif de l'inventaire en les lisant toutes ;
masquer la colonne « Actif » d'une liste filtrée sur un actif (le gabarit commun l'aurait demandé à part) ; un
filtre exact par CVE pour « sur tous les actifs ». *Conséquences* : la page d'un actif ne liste plus ses
vulnérabilités, sa liste le fait ; `/assets/{id}?page=` ne pagine plus que l'aperçu d'une règle ; un lien
`/findings?asset=` partagé ne montre rien à qui ne voit pas l'actif ; la recherche d'une CVE courte en trouve
aussi les plus longues (CVE-2022-3114 trouve CVE-2022-31140).

**A87. Le digest suit les niveaux et reste un résumé ; la veille se lit par pages et se compte.** L'audit
d'ergonomie de la 0.4.1 (lot 5) mesurait sur la base noyau un digest de 7 631 lignes et 3 Mo, qui listait
toutes les nouvelles vulnérabilités, corrigées en tête, sans jamais parler de niveau ; la veille empilait 200
actualités sans le dire, sans compteur, la vue « Qui concernent mon inventaire » en dernier, des résumés
coupés au milieu d'un mot.
- *Ordre du digest* : « Urgentes (n) », toutes dates, les plus urgentes d'abord (« nouvelle » pour celles de la
  période) ; « Par niveau », un tableau nouvelles sur la période / au total pour Urgentes, À planifier,
  À surveiller, Écartées puis Corrigées, en nombre seulement ; « Nouvelles vulnérabilités ouvertes » par éditeur
  puis leurs plus urgentes hors urgentes, déjà en tête ; hors délai ; actualités citant l'inventaire ;
  vulnérabilités ouvertes par éditeur ; veille. Les corrigées n'y sont plus listées. Une ligne dit le niveau,
  la sévérité et sa raison (`tracking.Reason`, comme les listes), l'avis, trois alias au plus (`aliases`, passé
  de `web` à `tracking` pour servir aux deux) et l'actif. Le tableau par éditeur compte les urgentes et les
  range en tête (A47 amendé). Les nombres par niveau viennent de `tracking.CountLevels`, que la liste des
  vulnérabilités emploie aussi (`levelLinks`).
- *Borne* : chaque liste (urgentes, nouvelles, hors délai) s'arrête à 50 lignes, suivies de « … et 3 253 autres »
  et d'un lien vers la liste de l'interface (`/findings?level=urgent`, `?since=7`, `?overdue=1`, avec `group=`
  pour le digest d'un groupe). Le Markdown, qui ne connaît pas l'adresse de Vigil, nomme la liste (« dans
  Vigil : la liste des urgentes ») ; le message envoyé se termine déjà par le lien du digest, que construit le
`Notifier` d'après `-base-url`, comme ceux des alertes (revue 0.5.0, C10 : la ligne de commande et la page
avaient chacune leur copie) ; l'alerte d'un canal limité à un groupe mène de même aux listes de ce groupe
(`group=`), et non plus à celles de tout l'inventaire, dont les nombres différaient des siens. Les digests par
  groupe (A68) suivent les mêmes règles, par la même fonction. Mesure sur une copie de la base noyau, ses digests
  effacés pour couvrir les 7 jours par défaut comme l'audit : Markdown 1,87 Mo et 7 698 lignes avant, 10,7 Ko et
  122 lignes après ; HTML 3,28 Mo avant, 26 Ko après. Il tient dans un message de discussion (30 000 octets).
- *Veille* : les 500 actualités les plus récentes d'une vue (`store.MaxCTIItems`, la borne existante), 100 par
  page (`paginate`, celui de la liste des vulnérabilités), groupées par jour de publication ; « 500 actualité(s) ·
  lignes 1 à 100 sur 500 : les 500 plus récentes sur 1 234 » quand la vue en compte plus. Les quatre vues portent
  leur nombre (`Store.CountCTIItems`, qui lit les mêmes actualités que la liste par `ctiQuery`), « Qui concernent
  mon inventaire » en premier, avec le gabarit des niveaux (`levelLink`, `aria-current`). Un résumé est coupé à
  300 caractères et finit par « … » s'il s'arrête avant la fin de sa phrase (`clip.Excerpt`) : The Hacker News
  coupe les siens au milieu d'un mot.

*Écarté* : lister les urgentes sans borne (« en entier », dit l'audit) : 50 lignes couvrent le noyau Ubuntu (27)
et un inventaire qui en aurait plus a besoin de la liste, pas d'un message ; passer l'adresse de Vigil à
`digest.Generate` pour des liens dans le Markdown (un paramètre de plus à ses deux appelants, pour un lien que
le message porte déjà) ; paginer la veille en SQL (`LIMIT … OFFSET`) : 500 actualités se lisent en une requête,
et `paginate` reste la seule façon de couper une liste. *Conséquences* : le digest ne contient plus de résumés
ni la synthèse par statut, que remplacent les nombres par niveau ; la veille lit jusqu'à 500 actualités au lieu
de 200, et cinq comptes par affichage.

**A88. Ajouter des actifs : quatre entrées, un formulaire en trois groupes, des refus qui disent quoi
écrire.** L'audit d'ergonomie de la 0.4.1 (lot 7) relevait une page qui empilait recherche CPE, formulaire de
15 champs, SBOM et CSV sans dire laquelle choisir, avec quatre paragraphes d'aide entre les champs ; un purl
`pkg:npm` sans nom accepté, un actif « nginx » de l'écosystème npm sans version passé en silence à la
recherche par le nom, avec le même message que les autres ; des refus d'import sans les valeurs admises, la
seconde erreur d'une ligne sans son numéro, et l'erreur Go brute d'un SBOM mal formé ; un mot de passe
administrateur saisi une seule fois ; un tableau de bord vide chargé d'indicateurs à zéro ; des listes filtrées
vides qui se disaient vides.
- *Quatre entrées* en tête de « Ajouter des actifs » (un paquet, un produit, un SBOM, un tableau), liens vers les
  sections de la même page. Le formulaire d'un actif, commun à l'ajout et à la page d'un actif, tient en trois
  groupes : ce qu'il faut vérifier (nom, version, type, écosystème, purl, CPE et ses versions suivies), puis
  « Organisation » et « Période de suivi », repliés sauf s'ils portent une valeur ou si le formulaire est refusé ;
  une aide d'une ligne sous chaque champ (`aria-describedby`), l'aide longue repliée. Un CPE choisi dans la
  recherche revient sur ce formulaire, titré « Le produit choisi ».
- *Un refus dans le formulaire refusé* : l'adresse d'un formulaire finit par l'ancre de sa section
  (`/assets/import-csv#csv`), que le navigateur garde pour la page de réponse ; le message s'y affiche
  (`page.ErrorAt`, `errorAt`, modèle `formError`), pas en haut d'une longue page. Le même moyen sert à toute page
  à plusieurs formulaires.
- *Validation* : un purl doit nommer un paquet (`osv.PURLName`) ; un refus nomme la valeur refusée et celles qui
  sont admises (« type « Paquet » inconnu : Paquet / dépendance, Technologie, Produit ou Système d'exploitation
  attendu », `choice.Labels`, `fr.Or`) ; un import CSV donne une erreur par ligne, chacune numérotée, dix au plus ;
  un mot d'un libellé double est admis (« Paquet », « dépendance »), comme le code (« os ») ; un CSV ou un SBOM
  illisible le dit en français, avec la ligne ou l'octet en cause (`csvError`, `sbom.jsonError` : « components
  doit être une liste, pas un texte »).
- *Le message d'un ajout dit la détection retenue* : OSV par le paquet et la version, la NVD par le CPE, ou, en
  le disant, la recherche par le nom (« sans purl, CPE ni version… résultats à vérifier ; une version avec un
  écosystème, ou un CPE, rend la détection exacte ») ou rien (« son purl ne donne pas de version »). Les messages
  restent des clés fixes : aucun texte saisi n'y revient.
- *Première configuration* : le mot de passe se tape deux fois, le nom saisi est gardé après un refus. Tant que
  l'inventaire est vide, le tableau de bord ne montre que « Pour commencer », avec « Ajouter des actifs » en
  bouton principal (un lecteur lit qu'un analyste peut en ajouter). Une liste filtrée vide le dit (« Aucun actif
  ne correspond à ces filtres », « Aucune vulnérabilité ne correspond à ces filtres ») et propose de réinitialiser.

*Écarté* : refuser un écosystème ou un purl sans version (l'audit le proposait aussi) : un export de
l'inventaire réimporté contient les composants de SBOM sans version, et tout le fichier serait refusé ; le
message de l'ajout dit ce qui manque. L'import VEX sur cette page : il n'ajoute pas d'actif, il applique des
analyses aux vulnérabilités, et reste à côté de l'export VEX (A85). Un modèle CSV servi à part : l'export de
l'inventaire en tient lieu, vide quand l'inventaire l'est. *Conséquences* : un purl sans nom, déjà en base, est
refusé à la prochaine modification de l'actif ; les messages d'ajout changent ; un appel à `/setup` sans
`confirm` est refusé.

**A89. Les paramètres en sous-pages, un formulaire refusé tel qu'il a été saisi.** L'audit d'ergonomie de la
0.4.1 (lot 8) mesurait une page de 3 517 px (8 841 sur téléphone) où les canaux, troisième étape de « Pour
commencer », venaient après les filtres, onze flux et 47 cases ; une erreur de formulaire renvoyait en haut et
vidait la saisie (un canal en `http://` : le message 2 700 px au-dessus du formulaire, nom et type perdus) ; des
délais incohérents (haute 5 jours, critique 15) enregistrés sans remarque ; une clé de double authentification
de 32 caractères d'un bloc.
- *Sous-pages*, chacune à son adresse, celle où son formulaire envoie déjà : Alertes (Notifications
  `/settings/webhooks`, Délais de traitement `/settings/sla`), Veille (Filtres `/settings/watch`, Flux
  `/settings/feeds`), Accès (Utilisateurs, Groupes, Jetons d'API `/settings/tokens`, Journal d'audit). Un menu
  les liste à côté de la page (au-dessus sur téléphone), la page courante marquée, les flux en échec comptés
  (« Flux · 1 en échec »). Le menu ne propose que les sous-pages que le rôle ouvre, et il le lit dans la table
  des routes (`pageRoles`, `opens`) : il ne peut pas offrir une page qui refuse. `/settings` mène à la première :
  Notifications pour un administrateur, Filtres de veille pour les autres ; rien ne change pour un lecteur, qui
  voit les filtres et les flux. « Ajouter un flux » est replié. Les sections venues depuis l'audit y ont leur
  place : Groupes et l'accès des comptes sous Accès, le périmètre d'un canal sur Notifications, le groupe d'un
  jeton sur Jetons d'API.
- *Un formulaire refusé revient tel qu'il a été saisi*, son message en lui (le moyen d'A88 : `ErrorAt`, l'ancre
  dans l'adresse du formulaire) : canal (nom, type, URL, alertes, digests, périmètre), flux (nom, URL,
  étiquettes), jeton (nom, projet, groupe), délais. Accepté, il mène en haut de sa sous-page, où est son message
  (`redirect` garde un `#fragment`, sans quoi le navigateur garderait celui du formulaire) ; un jeton créé
  s'affiche en tête de sa sous-page, et l'adresse y mène (`#jeton`, constat 1.4).
- *Mots des alertes* : le choix d'un canal se fait par trois boutons, chacun avec ce qu'il couvre (« Urgentes
  seulement (exploitées, probables ou jugées exploitables) », « Urgentes et À planifier (plus les critiques et
  les hautes) », « Aucune alerte immédiate (digests seulement) ») ; un canal absent le dit (« Sans canal, les
  urgentes n'apparaissent que dans Vigil »).
- *Délais incohérents* : enregistrés, puis signalés sur leur sous-page tant qu'ils ne décroissent pas de Basse à
  Critique (`SLA.Ordered`, 0 étant le plus long).
- *Clé de double authentification* par groupes de quatre caractères (`keyGroups`), les applications ignorant
  les espaces ; son cadre a la largeur de celui du mot de passe.

*Écarté* : refuser des délais incohérents (un choix délibéré reste possible, comme une critique à 0 pour la
suivre ailleurs) ; un QR code de la clé, rendu par le serveur en SVG : une dépendance ou quelques centaines de
lignes d'encodage (A26), pour une saisie qui se fait une fois ; garder `/settings` comme page de tous les
réglages, avec des ancres (une page de 3 500 px, que les sous-pages remplacent) ; une liste des rôles par
sous-page écrite à part (une seconde politique à tenir à côté de la table des routes). *Conséquences* : cinq
pages GET nouvelles (`/settings/watch`, `/settings/feeds`, `/settings/webhooks`, `/settings/sla`,
`/settings/tokens`), dans la table des routes et dans `wantPolicy` ; les liens anciens vers `/settings#canaux`
mènent à la première sous-page ; l'URL tapée d'un canal refusé revient dans le formulaire de celui qui l'a
saisie, jamais celle d'un canal enregistré.

**A69. Ce que les sources envoient est vérifié avant d'être stocké.** OSV et la NVD sont des hôtes fixes
en HTTPS, mais leurs champs étaient stockés tels quels : une sévérité hors de la liste (`IMPORTANT` de
Red Hat, `NONE`, du HTML) n'entrait dans aucun filtre, pas même « Inconnue », un score CVSS de 1e300
dépassait tous les seuils, une description n'avait pas de taille. L'échelle d'une base est traduite à la
source, en un seul endroit (`osv.Vuln.SeverityLabel` : `MODERATE` de GitHub en `MEDIUM`, `Important` de
Red Hat en `HIGH`) ; une valeur inconnue y est remplacée par la sévérité du score CVSS, comme une valeur
absente. Puis une seule fonction, `tracking.sanitize`, s'applique aux deux entrées (avis OSV, fiche NVD) :
sévérité de la liste ou inconnue, score dans 0..10 ou absent, résumé, description, alias et références
bornés, bien au-dessus des avis réels. L'échéance KEV, écrite à part, est vérifiée par son client, comme
les scores EPSS. *Revue de la 0.5.0* : l'identifiant et les dates n'avaient pas de borne (un identifiant
de 10 000 caractères était stocké tel quel, une date `<b>demain</b>` aussi), et la liste légère d'A90 gardait
les autres identifiants tels que lus. Une seule fonction, `listed.checked`, vérifie désormais ce qui
identifie et date un avis, pour la base (`sanitize`) comme pour cette liste (`short`) : un identifiant
vide ou de plus de 100 caractères rend la réponse illisible (l'actif reste « non vérifié »), un alias plus
long est retiré et 2 000 au plus sont gardés, une date qui ne commence pas par un jour, ou de plus de
40 octets, devient inconnue. *Écarté* : couper un identifiant trop long, qui en ferait un autre, ou sauter
l'avis, qui ne serait plus signalé. *Écarté* : stocker `UNKNOWN`, une deuxième forme de l'inconnu à côté de la sévérité vide,
que le digest ne classerait plus d'après le score ; traduire aussi dans le digest, qui ne lit que des
sévérités déjà traduites (aucune version publiée n'a stocké `MODERATE`). *Conséquence* : une fiche déjà
en base est corrigée à sa prochaine écriture : la prochaine modification de l'avis, pour OSV comme,
depuis la revue de la 0.5.0, pour la NVD, dont chaque fiche était réécrite à chaque synchronisation, son
enregistrement brut compris (`storeNVD` réutilise le contrôle `stale` d'OSV, par la date `lastModified`).

*Ordre des sources de la sévérité (novembre 2026).* Plus de la moitié des CVE des noyaux restaient sans
sévérité : 2 354 sur 4 481 pour Debian 13, 1 663 sur 3 151 pour Ubuntu 22.04, sur la période de suivi.
La cause est en amont : sur les 6 248 CVE de kernel.org publiées de juin à novembre, la NVD en a 4 729
au statut « Received », jamais analysées, et kernel.org ne note pas les siennes. Prendre la sévérité de
la NVD a été mesuré et écarté : elle en aurait noté 2 sur 4 000, pour 4 000 appels (une CVE par appel,
7 h sans clé), et pour les CVE notées elle dit déjà ce que Vigil stocke (OSV recopie son vecteur). Ubuntu,
en revanche, donne sa priorité à chaque CVE (type de sévérité OSV `Ubuntu`, de `negligible` à
`critical`), présente dans les avis déjà lus : `SeverityLabel` la prend après l'échelle de la base et le
score CVSS, jamais avant. Elle n'est d'accord avec la sévérité du score que pour 409 des 1 488 avis
Ubuntu notés et plus basse pour 1 073 ; en premier, elle aurait fait passer un millier de lignes
d'« À planifier » à « À surveiller ». En repli, les CVE sans sévérité du noyau Ubuntu passent de
52,8 % à une sur 3 151 ; la page d'une vulnérabilité dit d'une sévérité sans score CVSS qu'elle est
l'évaluation de la source. *Conséquences* : la colonne mêle deux échelles pour Ubuntu, le score quand il
existe, la priorité sinon ; Debian ne publie ni score ni priorité pour ces CVE, qui restent « Inconnue »
(52,5 %) ; à la première synchronisation après la mise à jour, les CVE devenues hautes ou critiques
(125 pour un noyau Ubuntu 22.04) partent en une alerte « sévères » (A37). Le calcul du CVSS 4.0 (A16)
reste différé : les 538 avis Ubuntu qui n'ont qu'un vecteur 4.0 ont tous une priorité.

**A75. Une seule façon d'interroger une source.** Les clients d'OSV, de la NVD, de KEV et d'EPSS
refaisaient chacun la requête, l'en-tête `User-Agent`, le contrôle du statut, la lecture bornée et le
décodage, avec trois formes de message (`status 503`, `HTTP 503`, `nvd : HTTP 404`), deux boucles de
nouvelles tentatives et trois attentes annulables. Deux lectures d'OSV s'arrêtaient en silence à leur
borne (`io.LimitReader`) : la réponse tronquée échouait ensuite en erreur de décodage trompeuse. Un refus
d'OSV recopiait 512 octets de la réponse dans le message affiché. Le paquet `sources` remplace ces copies :
`NewRequest` (agent, corps JSON), `Open` et `Do` (statut, lecture bornée, décodage), `StatusError`,
`Temporary`, `Retry` et `Sleep`. Tout statut autre que 200 est une erreur, affichée `HTTP 404 (raison)` :
la raison est l'en-tête `message` de la NVD ou le champ `message` d'une réponse JSON (OSV), sur une ligne
de 200 caractères au plus. Une lecture qui dépasse sa borne échoue (`limit.Reader`, voir A74), en flux
aussi pour les pages de `/v1/query`. Une requête est renvoyée
après une panne du réseau, à l'aller comme pendant la lecture, un 429 ou un 5xx, et le 403 de la limite
de débit de la NVD ; pas après un autre refus, une redirection refusée par `netsafe.CheckRedirect`
(`netsafe.RedirectError` : vers une URL non https, ou plus de 5), une réponse trop grosse ou illisible, qui
échoueraient de même. Les plafonds de lecture sont ceux mesurés plus bas. Les clients ont la même forme : `URL` (vide : l'API publique), `HTTP` (donné par
`main`), `UserAgent` ; `kev.Client.Catalogue` et `epss.Client.Scores` remplacent les fonctions libres, et
le `Syncer` porte ces deux clients au lieu d'un client HTTP et de deux URL. OSV reçoit de `main` une copie
du client commun, avec sa politique de redirection, au délai `osv.Timeout` (5 minutes). *Écarté* : un
client commun incorporé à chaque source, qui alourdit chaque déclaration ; des délais de nouvelle
tentative réglables par client pour les seuls tests, alors qu'un miroir ou un serveur de test est déjà
réinterrogé sans attente ; les flux CTI et les webhooks, dont les URL sont saisies par les utilisateurs,
dont les erreurs taisent l'adresse et dont la réponse n'est pas du JSON : ils gardent leur requête.
*Conséquences* : des messages d'erreur affichés changent (`HTTP 503` pour toutes les sources, `réponse
illisible`, plus de `temporarily unavailable`) ; une lecture d'OSV coupée en route est désormais renvoyée,
comme pour la NVD, et une réponse trop grosse de la NVD ne l'est plus.

*Correction (novembre 2026) : ce qui est renvoyé exactement.* « Pendant la lecture » ne valait que pour
les réponses lues d'un bloc (`Do`), tenues dans `Retry`. Une page de `/v1/query`, lue avis par avis
après `Open`, n'était reprise qu'en cas d'échec à l'ouverture : une coupure au milieu de la page perdait
l'actif, sous un message trompeur. Lors d'un essai réel, le noyau Ubuntu 22.04 (8 212 avis, 63 pages,
4,5 Go, 25 minutes de lecture) a été perdu ainsi après 21 minutes, sur un `GOAWAY` HTTP/2 d'OSV
(`server_shutting_down`), affiché « réponse illisible ». Désormais :
- `Open` rend une erreur de lecture du corps comme une panne du réseau (`Temporary`), sauf la fin du
  corps et le dépassement de la borne : connexion coupée ou fermée, corps plus court qu'annoncé, délai
  atteint pendant la lecture. Un corps terminé proprement mais incomplet reste une réponse illisible ;
- une réponse lue d'un bloc (`Do`) est demandée à nouveau, comme avant ;
- une page de `/v1/query` coupée est demandée à nouveau, avec le même jeton, et relue depuis son
  début ; ses avis déjà rendus sont sautés, d'après leur identifiant. Les nouvelles tentatives sont
  aussi nombreuses que pour une requête, avec les mêmes attentes (5 puis 15 secondes, aucune pour un
  serveur de test). Une page relue ne compte pas dans la borne des 200 pages ;
- passé ces essais, l'erreur dit « lecture interrompue », et plus « réponse illisible », réservé
  aux réponses mal formées, trop grosses ou à un délimiteur inattendu, qui ne sont pas renvoyées.

*Écarté* : relire toute la requête depuis la première page, soit 25 minutes pour ce noyau ; garder une
page en mémoire pour la relire, alors qu'elle peut dépasser 64 Mo (A55).

*Correction (revue de la 0.5.0) : les quatre sources sont renvoyées.* KEV et EPSS ne passaient pas par
`Retry` : un seul 503 sur l'un des lots d'EPSS faisait échouer l'enrichissement de toute la base. Les deux
y passent désormais (`sources.Get` : requête, lecture, nouvelles tentatives), et la règle des attentes,
écrite deux fois (OSV, NVD), n'est plus qu'une (`sources.Delays`) : 5 puis 15 secondes, 10 puis 30 pour
la NVD, aucune pour un serveur de test ou un miroir.

*Plafonds de lecture, mesurés (revue de la 0.5.0).* Chaque réponse est lue dans une borne (`limit.Reader`),
bien au-dessus des réponses réelles de la base de l'audit :
- OSV : une page de `/v1/query`, 1 Gio, pour 72 Mo en moyenne (la plus lourde n'est pas mesurée) ; un avis,
  lu seul (`/v1/vulns`) ou dans une page, et une réponse de `querybatch`, 32 Mio, pour 708 Ko au plus ;
- NVD : une page de 2 000 CVE, 64 Mio, pour 12 Mo ; le dictionnaire des CPE, 48 Mio ;
- KEV : 32 Mio ; EPSS : 4 Mio par lot de 100 CVE ;
- la raison d'un refus : 64 Kio.

Au-delà, la lecture échoue (« réponse supérieure à … octets »), n'est pas renvoyée, et l'actif reste « non
vérifié ». Dans une page, la borne d'un avis compte ce qui est lu pour lui (`limit.Limited.Renew`, à chaque
avis) ; le décodeur lisant d'avance, il en tient au plus le double. *Correction* : un avis lu dans une page
n'était borné que par la page, soit 1 Gio en mémoire pour un seul avis (essai : un avis de 200 Mo accepté,
1,3 Go alloués). *Écarté* : borner la page plus bas, qui n'en protège pas un seul avis et refuserait une
page réelle plus lourde que la moyenne.

**A74. Une seule lecture bornée, hors de `netsafe`, et une seule écriture CSV.** L'audit de code de
novembre 2026 (R6) relevait que le BOM UTF-8 se retirait de trois façons (SBOM, VEX, CSV), que la
lecture d'un fichier CSV déposé vivait dans `web` avec sa propre borne, et que `netsafe.ReadLimited`,
prévu pour les réponses HTTP, servait aussi aux fichiers déposés : le paquet anti-SSRF portait une
lecture qui n'a rien à voir avec les adresses, et le contrôle de capacités (capslock) lui prêtait les
capacités « fichiers » de tout lecteur appelé derrière l'interface `io.Reader`.
Le paquet neutre `limit` porte la lecture bornée : `Reader` et `Read` pour les réponses du réseau
(sources, flux CTI), qui échouent en `*TooLargeError` au-delà de la borne, et `File` pour un fichier
envoyé par un utilisateur (SBOM, VEX, CSV) : borne, BOM retiré, et un message pour l'écran qui parle
d'un fichier (« fichier supérieur à 20 Mo », au lieu de « réponse supérieure à 20971520 octets » pour
un SBOM). `netsafe` ne garde que les règles d'URL et le client anti-SSRF. La lecture d'un CSV rejoint
`inventory`, à côté de la correspondance lignes ↔ actifs (`ReadCSV` : borne, BOM, séparateur deviné).
L'écriture reste dans `web`, en une seule fonction pour l'inventaire comme pour les vulnérabilités
(`writeCSV` : BOM, point-virgule, chaque cellule neutralisée par `inventory.CSVCell`), avec une seule
gestion d'erreur, journalisée une fois à la fin. *Écarté* : laisser la lecture dans `netsafe` ou la
mettre dans `sources`, que `sbom`, `vex` et `inventory` importeraient sans rien interroger ;
neutraliser les cellules dans chaque fonction qui construit des lignes, où un nouvel export pourrait
l'oublier ; écrire le CSV dans `inventory`, qui recevrait la réponse HTTP derrière un `io.Writer` et
que capslock dirait alors capable d'écrire sur le réseau ; un paquet CSV à part, pour un seul
utilisateur. *Conséquences* : le message d'un SBOM trop gros change ; `inventory.CSVRow` rend les
valeurs telles quelles, et seule l'écriture les neutralise ; les exports restent identiques octet
pour octet (test) ; capslock voit `limit` capable de lire fichiers et réseau (son lecteur ne sait pas
ce qu'il lit), et `netsafe` ne l'est plus de lire des fichiers.
*Envoi au-delà de la borne* (revue de la 0.5.0, W7) : avant toute lecture, le corps d'une requête est
borné selon sa route (`bodyLimit` : 64 Kio pour un formulaire, 2 Mo et 64 Kio pour un CSV, 21 Mo pour
un SBOM, un VEX ou l'API). Un envoi qui dépassait cette borne laissait le formulaire vide et recevait
« Jeton CSRF invalide. » (403), qui fait croire à une attaque. `require` lit désormais le formulaire
avant d'y chercher le jeton et répond 413 en disant la borne (« Envoi trop volumineux : le fichier CSV
doit faire 2 Mo au plus. ») ; les pages ne disent plus « manquant ou trop volumineux » d'un fichier
absent. Un fichier entre sa propre borne et celle du corps garde le message de `limit.File`.

**A13. Statuts CycloneDX / VEX.** Des statuts maison auraient été plus « parlants » mais non
interopérables. Les états VEX (`in_triage`, `exploitable`, `resolved`, `not_affected` +
justification, `false_positive`) sont libellés en français dans l'interface, et l'export /
import VEX permet l'échange avec Dependency-Track, les clients ou les auditeurs. L'import
rapproche par purl ou CPE et par identifiant ou alias (CVE ↔ GHSA), à travers un index par
composant : parcourir toutes les vulnérabilités pour chaque analyse rendait l'import quadratique
(20 000 analyses contre 20 000 vulnérabilités : 2 s de rapprochement, 2 ms avec l'index). Les
analyses d'un document s'écrivent en une seule transaction : toutes, ou aucune en cas d'erreur.

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

*Garde étendue aux vulnérabilités probables (novembre 2026, avec A80).* Seule une entrée KEV passait la
période, alors que le classement (A78) et les règles d'écart (A61) traitent de même « exploitée ou
probable » (EPSS ≥ `store.LikelyEPSS`). Une CVE ancienne du noyau Ubuntu à 94 % d'EPSS, citée par la
veille, n'était visible que par un avis groupé ; A80 la retirait. La condition de période (`inPeriod`)
reprend désormais `exploitedExpr`, et un paquet lu en entier (A55, A56) relit à part ses avis d'une CVE
laissés hors période : leurs CVE sont demandées à EPSS (une requête pour 100 CVE, environ 50 pour un noyau
Ubuntu), et ceux qui sont probables sont téléchargés un à un (`/v1/vulns`) puis enregistrés. Une panne
d'EPSS est journalisée et ne laisse passer que KEV, comme avant. Sur la base de l'audit, 13 CVE anciennes
entrent ainsi, toutes urgentes : 9 pour le noyau Ubuntu (dont CVE-2026-43284, EPSS 94 %) et 4 pour le noyau
Debian, dont CVE-2004-0230 et CVE-2008-4609 (TCP), que Debian dit toujours affecter le paquet. *Limite* : la NVD n'est interrogée que
sur la période et sur KEV (`hasKev`) ; une CVE probable plus ancienne n'y est pas cherchée.

*Correction (revue de la 0.5.0) : chaque CVE demandée une fois à EPSS.* Chaque paquet lu en entier
demandait à EPSS ses CVE anciennes, puis l'enrichissement redemandait celles en base : deux noyaux qui
partagent leurs CVE (Debian et Ubuntu) les faisaient demander deux fois, et les probables trois (essai :
1 850 demandes pour 1 000 CVE, 20 requêtes au lieu de 10). L'analyse d'un seul actif, à son ajout ou à sa
modification, enrichissait toute la base : environ 77 requêtes pour les 7 629 vulnérabilités des deux
noyaux de l'audit, pour un actif qui n'en a peut-être aucune. Une mémoire des scores, le temps d'une
synchronisation (`signals.epssScores`), ne demande que les CVE pas encore demandées, à la garde comme à
l'enrichissement ; l'analyse d'un actif n'enrichit que les avis qu'il signale, la synchronisation
périodique tout le reste. *Écarté* : garder les scores d'une synchronisation à l'autre, alors qu'EPSS
change chaque jour.

**A32. État de la synchronisation visible, analyse d'un seul actif.** Sans JavaScript, une
synchronisation en arrière-plan ne donnait aucun retour. Le bouton « Synchroniser l'inventaire »
est présent sur le tableau de bord, l'inventaire et les vulnérabilités, et ramène à la page
d'origine (liste blanche de chemins, pas de redirection ouverte). L'état courant ou le dernier
résultat (nouvelles, rouvertes, corrigées, ignorées, erreur) est affiché à côté ; il est gardé
en mémoire, car il ne concerne que le processus en cours. Ajouter, modifier ou « Analyser » un
actif lance son analyse seule ; si une synchronisation est en cours, l'analyse attend qu'elle
finisse au lieu d'être perdue. Depuis la revue de la 0.5.0 (W2), la même attente vaut pour la
synchronisation d'un import (CSV, SBOM, API) et pour la synchronisation programmée de `serve`, qui
étaient abandonnées si une autre tournait : un import pendant une synchronisation affichait
« synchronisation lancée » et ses composants attendaient la suivante, et une analyse d'actif en cours
au moment du tick faisait sauter la synchronisation programmée jusqu'à l'intervalle suivant (6 h par
défaut). Une seule fonction attend et lance (`Server.Sync`, réessai toutes les 5 secondes), et une
seule attente par actif, ou pour tout l'inventaire : une demande pour ce qui attend déjà n'ajoute rien,
puisque l'attente lit l'inventaire quand elle démarre. Deux « Analyser » de suite ne font donc qu'une
analyse, et une série de demandes n'empile plus d'analyses ni de goroutines. Le bouton « Synchroniser
l'inventaire » reste refusé pendant une synchronisation (« déjà en cours »). *Écarté* : faire attendre
`Syncer.Run` lui-même, qui refuse une seconde synchronisation (`ErrRunning`) et sur lequel comptent ce
bouton et l'état « déjà en cours ».

**A58. Fréquence de collecte des flux, réglable dans l'interface.** Les actualités suivaient
`-sync-interval`, avec les vulnérabilités : 4 collectes par jour par défaut, et changer l'une changeait
l'autre, en redémarrant le service. La fréquence devient un réglage (à la demande, 1 à 24 fois par
jour), relu chaque minute, et que chaque responsable peut changer sans accès au serveur. `-sync-interval 0`
coupe toujours les deux : c'est le moyen de ne rien appeler seul. Le flux « vulnérabilités » de The
Hacker News rejoint les flux par défaut ; ses articles figurant aussi dans le flux général du site,
un article déjà présent sous la même adresse n'est pas repris par un autre flux. Une seule collecte à
la fois, comme pour la synchronisation : « Collecter maintenant » pendant une collecte le signale au
lieu d'en mettre une autre en file (chaque demande attendait la précédente, puis recollectait tout),
et la collecte planifiée tient celle en cours pour celle qui était due.

**A59. Teams : carte adaptative, et raison des refus.** Les connecteurs de Microsoft ont cédé la place
aux workflows, qui attendent une carte adaptative plutôt que le champ `text` commun à Slack et
Mattermost : Teams a donc son format. Un 401 systématique vient de leur côté : le workflow n'accepte
pas les appels anonymes (« Qui peut déclencher le flux »), or un webhook n'a que la signature de son URL ;
ou son adresse n'est plus valide (`logic.azure.com`, retirée fin 2025). Microsoft répond 401 sans
explication selon les cas : l'état du canal donne donc le code et le message de la réponse quand il y en
a, ce qu'il faut régler pour Teams, et le bouton « Envoyer un test » évite d'attendre une alerte pour
vérifier. Rien de ce qui cite une adresse n'est repris d'une réponse : elle pourrait contenir le secret.
Une carte tient en 28 Ko, moins qu'un message de discussion : un message est coupé une seule fois, au budget
de son canal (`fit`, 20 000 octets pour Teams, 30 000 pour les autres), la note « tronqué » et le lien du
digest gardés. Le digest était coupé pour les discussions puis recoupé pour Teams, qui perdait la note et le
lien dès 20 Ko (revue 0.5.0, C4).

**A15. Priorisation KEV > EPSS > sévérité, plutôt que CVSS seul.** Le CVSS mesure la gravité
théorique, pas la probabilité d'exploitation. Exploitation avérée (KEV) d'abord, puis probabilité
EPSS ≥ 10 %, puis sévérité. Le score CVSS reste affiché et filtrable. Le statut Exploitable compte
comme une entrée KEV (A78).

**A78. Un seul classement d'urgence ; le statut Exploitable au rang d'une entrée KEV.** L'audit de code
de novembre 2026 relevait deux classements qui divergeaient : la liste et le tableau de bord triaient par la
sévérité de l'avis (`digest.MoreUrgent`), le digest par la bande de sévérité avec repli sur le score CVSS
(`SortBySeverity`), si bien qu'une vulnérabilité notée par son seul CVSS ne tombait pas au même rang dans les
deux. Le seuil EPSS de 10 % était écrit six fois, l'ordre des sévérités quatre fois, et `digest.Level`
recopiait en Go la classe d'alerte calculée en SQL ; `web` triait avec ces règles du digest. Un seul
classement, `tracking.ComparePriority`, sert maintenant aux listes, au tableau de bord et au digest :
exploitée (KEV) ou jugée exploitable, puis probable (EPSS ≥ 10 %), puis bande de sévérité (`tracking.Band` :
la sévérité de l'avis, à défaut celle du score CVSS), puis score EPSS, score CVSS et détection la plus
récente. Le statut « Exploitable – à traiter » est une décision de l'équipe : il place la vulnérabilité au
rang d'une entrée KEV, dans l'ordre comme dans le niveau Urgentes, le filtre « Prioritaire », l'indicateur
« À traiter en priorité » (tous deux remplacés par le niveau Urgentes, A84) et la classe d'alerte. Le seuil n'est écrit qu'une fois, `store.LikelyEPSS`, dont
sont construites les expressions SQL (`exploitedExpr`, `urgentExpr`, `alertClassExpr`) ; le niveau
(`tracking.Level`) se lit sur la classe calculée par la requête (`Finding.Class`) ; l'ordre des sévérités
est celui de `tracking.Severities`. *Écarté* : garder le tri par sévérité dans le digest (deux ordres pour les
mêmes vulnérabilités) ; calculer la classe d'alerte en Go (lire toutes les vulnérabilités ouvertes à chaque
synchronisation pour n'en notifier que quelques-unes) ; ranger le statut Exploitable entre KEV et EPSS.
*Conséquences* : l'ordre affiché change ; dans le digest, une vulnérabilité exploitée passe devant une
critique qui ne l'est pas ; dans la liste, une vulnérabilité notée par son seul CVSS se range à sa bande, que
la colonne Priorité affiche au lieu de « Inconnue ». Alertes immédiates (A37, une fois par niveau) : passer une
vulnérabilité ouverte à « Exploitable » la porte à la classe prioritaire ; si elle n'y avait pas déjà été
notifiée, elle part à la fin de la synchronisation suivante, une seule fois, avec la raison « jugée
exploitable » (la repasser à « À analyser » ne la renvoie pas). À la première synchronisation après la mise à
jour, celles déjà marquées Exploitables et pas encore notifiées comme prioritaires partent de même, en un
message par canal. Les délais de traitement (A39) ne changent pas : seule une entrée KEV prend le délai
critique.

**A80. Une vulnérabilité trouvée par CVE ; les avis groupés deviennent des références.** Une source
signale une même faille sous plusieurs avis : l'avis de la CVE (`UBUNTU-CVE-…`, `DEBIAN-CVE-…`, `GHSA-…`) et
un avis de mise à jour qui la cite parmi des centaines (`USN-…`, `DSA-…`), ou deux bases pour la même faille
(`GHSA-…` et `GO-…`, `GHSA-…` et `PYSEC-…`). Vigil faisait une ligne par avis : sur le noyau Ubuntu 22.04 de
l'audit UX de la 0.4.1, 1 877 CVE apparaissaient deux fois, sous leur UBUNTU-CVE et sous l'un des 16 USN.
11 des 27 urgentes étaient des USN, urgents parce qu'une de leurs CVE l'était (KEV et EPSS d'un avis sont
le maximum de ses CVE). Un USN publié dans la période de suivi faisait aussi revenir 1 701 CVE plus
anciennes, que la période écarte quand elles viennent seules (A31). Hors noyau, la base réaliste comptait
des DSA sur openssl (11 CVE), des paires GHSA et GO sur `golang.org/x/net` (4 CVE) et des RHSA entre eux (69
CVE, jusqu'à 14 lignes pour l'une). Décision : ce qui identifie une vulnérabilité trouvée est le couple
(actif, CVE), lu dans les identifiants que les avis donnent eux-mêmes (identifiant, alias, avis d'origine),
sans liste de préfixes ni exception par distribution :
- un avis qui nomme une seule CVE la décrit ; un avis qui en nomme plusieurs est un avis groupé ;
- un avis groupé qui cite lui-même des avis par CVE, dont l'un au moins est signalé pour l'actif, n'est pas
  une ligne : la source décrit ses CVE une à une, et ce sont ces avis qui font foi. Il est montré, sur la
  page de chacune de ses CVE, comme référence (identifiant, lien OSV, version corrigée qu'il donne pour
  l'actif). Un RHSA ne cite que des CVE : il reste une ligne, comme avant ;
- les avis qui décrivent seuls la même CVE font une ligne : celle qui existe reste, signalée ou non, tant
  que l'un d'eux l'est ; à la première fusion, celle qu'une décision humaine a tranchée en dernier, puis
  une ouverte, puis une notée, puis la plus ancienne. Sa version corrective réunit celles de ses avis ;
- une CVE est dans la période de suivi quand tous ses avis le sont, ou qu'elle a déjà une ligne : sa date
  compte, pas celle d'un avis plus tardif.
Les lignes en trop ne sont pas supprimées mais repliées (`findings.folded_into`, migration 019) : elles
quittent les listes, compteurs, alertes, digests, exports et règles d'écart (`shownExpr`), gardent leur
statut et leur historique, et leur page reste ouverte aux liens déjà envoyés. Le repli est fait par la
synchronisation, dans la transaction de l'actif (A57) : elle seule voit les avis signalés hors période
(non stockés, A55), sans lesquels un USN ne pourrait être replié. Un avis groupé redevenu seul (ses CVE sans
avis propre) est de nouveau montré. Reprise du triage : un avis groupé replié garde sa décision, qui
n'est pas reportée sur ses CVE (une décision sur 1 902 CVE n'en est pas une sur chacune) ; la page de chaque
CVE la cite, et celle de l'avis propose de l'appliquer à ses CVE par le triage par lot (A43). Deux avis
d'une même CVE : la décision humaine la plus récente est gardée, l'autre est inscrite dans l'historique de
la ligne gardée ; celle-ci prend la première détection la plus ancienne et la classe d'alerte la plus
haute déjà notifiée, si bien qu'aucune alerte ne repart et qu'aucune ligne ne paraît nouvelle. *Écartés* :
masquer les doublons à la lecture, sans colonne (la base ignore les avis hors période, et une décision
portée par la ligne cachée disparaîtrait) ; une fiche par CVE avec des liens vers ses avis (réécriture de
`vuln_id`, fiches `CVE-…` en collision avec celles de la NVD, sans résumé ni sévérité pour une CVE que seul
un RHSA cite, et une migration non réversible) ; replier un avis groupé dès qu'une de ses CVE est décrite
seule (sur Red Hat, les RHSA d'une CVE d'autres flux auraient fait disparaître 38 CVE sur 193, dont 6
urgentes sur 7) ; exiger que toutes ses CVE le soient (trois USN restaient, avec 44 doublons, pour des CVE
dont l'avis propre dit que la 22.04 n'est pas touchée). *Conséquences* : une copie de la base de l'audit,
synchronisée, replie ses 15 USN et ne garde aucune CVE en double ; la base réaliste passe de 377 à 316
lignes (openssl-rh de 127 à 76, ses 193 CVE et ses 7 urgentes toujours visibles) ; une CVE plus ancienne que la période
que seul un avis groupé faisait voir n'est plus montrée, sauf exploitée ou probable (A31) ; un VEX importé
qui cite un USN n'est plus rapproché (il l'est par la CVE) ; Red Hat garde ses RHSA multi-CVE en lignes,
faute d'avis par CVE chez OSV, et ses doublons viennent surtout de ce que ses écosystèmes ne distinguent pas
les versions de RHEL (A55). La migration ne replie rien ; la première synchronisation après la mise à jour
le fait, au démarrage de `serve`.

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
indicateurs retenus répondent à « que faire maintenant ? » plutôt qu'à « combien ? » : urgentes
(KEV, EPSS >= 10 % ou statut Exploitable, A78 ; cliquable vers le niveau, A84), vulnérabilités ouvertes, exploitées
avec échéance CISA dépassée, en attente d'analyse depuis plus de 30 jours, délai moyen de traitement
sur 90 jours (de la détection à la clôture : corrigée, non affectée ou faux positif) et couverture de
détection (actifs vérifiés automatiquement). Graphiques : répartition par sévérité (anneau),
activité hebdomadaire nouvelles / traitées sur 12 semaines, actifs les plus exposés. Une
bibliothèque de graphiques en JavaScript aurait cassé la CSP et ajouté une dépendance npm : le
serveur calcule la géométrie et produit du SVG ; couleurs par classes CSS (thèmes clair et sombre),
info-bulle native (`<title>`) sur chaque marque, tableau des données sous chaque graphique, aucun
attribut `style`. Palettes vérifiées avec un validateur (daltonisme, contraste) : la sévérité est
une rampe ordinale d'une seule teinte (rouge), l'activité un couple bleu / vert d'eau.
*Délai moyen (novembre 2026)* : il ne compte plus que les vulnérabilités détectées après la première
synchronisation de leur actif. Celles de la première synchronisation datent d'avant l'arrivée de l'actif
dans Vigil : leur délai mesure le rattrapage d'un arriéré, pas la réaction à une vulnérabilité nouvelle, et
faussait la moyenne. Une synchronisation date de son début toutes les vulnérabilités qu'elle crée, et rien
d'autre n'en crée : celles de la première synchronisation sont donc celles qui portent la plus ancienne
date de détection de l'actif, sans colonne ni migration. *Écarté* : enregistrer la date de la première
synchronisation sur l'actif (exact, mais une migration pour une seule statistique) ; une fenêtre après la
création de l'actif (une première synchronisation peut attendre l'intervalle, ou échouer). *Conséquence* :
pour un actif sans vulnérabilité à sa première synchronisation, la première qui en trouve est aussi laissée
hors de la moyenne ; celle-ci y perd quelques valeurs, sans jamais compter un arriéré. L'activité
hebdomadaire compte toujours toutes les vulnérabilités traitées.

**A34. Plusieurs pays, secteurs et réglementations par flux, modifiables.** Un flux européen ou
un site de normalisation couvre souvent plusieurs pays ou textes : un sélecteur unique obligeait
à choisir. Les étiquettes d'un flux se modifient après coup (y compris celles des flux par
défaut) et sont réappliquées aux actualités déjà collectées, dans la même transaction que le changement
d'étiquettes du flux : un échec en cours de route laissait le flux et une partie de ses actualités réétiquetés
(revue 0.5.0, C13), et 3 000 actualités se réétiquettent en 0,24 s au lieu de 1,02 s, une validation au lieu
d'une par actualité.

**A94. Un flux se lit entrée par entrée, 2 000 au plus.** La revue de la 0.5.0 (C1) a mesuré qu'un flux de
8 Mio fait d'éléments `<item/>` vides, décodé d'un bloc avant d'en garder 500, coûtait 2,3 Gio d'allocations et
450 Mio de tas vivant à chaque collecte (onze flux tiers par défaut, quatre collectes par jour) : de quoi faire
tuer un petit serveur par manque de mémoire. `cti.parseFeed` lit désormais le document élément par élément
(`xml.Decoder.Token`, puis `DecodeElement` pour chaque `item` ou `entry`) et s'arrête à 2 000 entrées
(`maxFeedEntries`) : le même flux se lit en 3 ms, avec 2 Mio. Les 500 plus récentes des entrées lues sont
gardées, comme avant ; un flux range ses entrées de la plus récente à la plus ancienne, et ce qui suit la
2 000ᵉ n'est pas lu, même tronqué. La même boucle lit RSS 1.0 (RDF), dont les `item` sont des enfants de la
racine et non du canal : ils étaient perdus sans erreur (C12). *Écarté* : compter les `<item` dans les octets
avant de décoder, que contourne un préfixe d'espace de noms (`<a:item/>` reste un `item` pour `encoding/xml`).

**A19. Digest « depuis le précédent ».** Une fenêtre fixe (7 jours) ferait manquer ou répéter
des éléments selon la fréquence de génération. Formats : Markdown (webhooks, export) et HTML
(interface). Webhooks au format le plus simple commun à Slack et Mattermost (A59 pour Teams ; champ
`text`), plus un JSON générique pour les intégrations. Depuis la 0.5.0, un groupe d'actifs qui a un
canal de digests a son propre digest, « depuis le précédent » de ce groupe (A68).

### Sécurité

**A20. Comptes locaux, sans SSO.** Le SSO (OIDC, SAML) ajoute une dépendance lourde et une
configuration délicate ; hors périmètre tant que la demande n'existe pas. Mots de passe en
argon2id, sessions côté serveur (jeton aléatoire stocké haché), trois rôles (lecture, analyste,
administrateur) vérifiés sur chaque route. Depuis la 0.5.0, chaque compte a aussi un accès : tout
l'inventaire, ou les seuls actifs de certains groupes (A68).

**A77. Les mots de passe les plus courants sont refusés, d'après une liste embarquée.** L'audit de
code de novembre 2026 (S14, exigence ASVS V2.1.7) relevait qu'un mot de passe de 12 caractères comme
`qwerty123456` ou `1qaz2wsx3edc` était accepté : c'est l'un des premiers qu'essaie une attaque, en
ligne malgré la limitation des tentatives, ou hors ligne sur une base volée. Les 3 000 plus courants
de 12 caractères ou plus, tirés de SecLists (provenance, extraction et licence dans
[DEPENDENCIES.md](DEPENDENCIES.md)), sont embarqués dans le binaire (`//go:embed`, 42 Ko) et
refusés, casse ignorée, par `auth.HashPassword`, par où passe déjà tout mot de passe choisi :
installation, « Mon compte », `vigil user add` et `vigil user reset-password`. Les aides le disent,
d'une seule phrase (`auth.PasswordHelp` : « 12 caractères minimum, et pas l'un des plus courants ») :
à côté des champs de l'installation et de « Mon compte », avec le mot de passe provisoire de
Paramètres → Utilisateurs, et dans l'aide et l'invite de la ligne de commande. Les mots de passe
provisoires y passent aussi, sans effet : aucune entrée n'a leur forme (vérifié par test). Écarté :
- *le service Pwned Passwords* (Have I Been Pwned, par k-anonymat) : un hôte sortant de plus à
  chaque choix de mot de passe, un échec quand la machine ne l'atteint pas (réseau fermé), un
  fragment d'empreinte de chaque mot de passe envoyé au dehors ;
- *une estimation de robustesse* (zxcvbn) : une dépendance et des dictionnaires bien plus lourds,
  pour peu de gain au-delà de 12 caractères ;
- *une liste plus longue* (les 46 296 du million qui font 12 caractères ou plus) : une attaque
  commence par les plus courants, et l'ASVS cite les 1 000 ou 10 000 premiers qui respectent la
  politique ;
- *des règles de composition* (majuscule, chiffre, symbole), que l'ASVS déconseille (V2.1.9) ;
- *le contrôle à la connexion*, que l'ASVS cite aussi : il imposerait un changement forcé au milieu
  de la connexion, une page et un état de plus ; un administrateur peut déjà imposer un nouveau mot
  de passe (« Nouveau mot de passe… », `vigil user reset-password`).

*Conséquences* : un mot de passe déjà en place reste valable jusqu'à son prochain changement ; une
variante d'un mot de passe courant (un chiffre ajouté) passe ; la licence MIT de SecLists accompagne
chaque archive de release et l'image Docker (`/usr/share/doc/vigil/`, avec celle de Vigil).

**A21. TOTP implémenté en interne.** RFC 6238 en une trentaine de lignes (vecteurs de la RFC en
test) plutôt qu'une bibliothèque. Anti-rejeu atomique en base, essais limités, désactivation
soumise à un code, autres sessions fermées à chaque changement, récupération par la CLI. Les
autres sessions se ferment aussi à la demande (audit de novembre 2026, S13) : « Fermer mes autres
sessions » sur Mon compte, pour tous les rôles, après une connexion sur un poste partagé ou un doute
sur un appareil ; la session en cours reste ouverte, l'action entre au journal d'audit
(`sessions_close`). Même requête que les fermetures automatiques (`deleteOtherSessions`), qui, elles,
journalisent un échec sans faire échouer le changement déjà fait (A73). La liste
des sessions ouvertes (appareil, adresse, date) est différée : il faudrait enregistrer ces
informations à la connexion, donc une migration.

**A22. Le premier administrateur ne se crée que depuis la machine elle-même.** Sinon un serveur
fraîchement exposé peut être réclamé par n'importe qui. Derrière un reverse proxy, toutes les
requêtes semblent locales : la page est alors désactivée et la création passe par la CLI
(défaut découvert en revue de sécurité).

**A23. Refus d'écouter en clair hors de `127.0.0.1`.** Sans TLS natif ni `-behind-proxy`
explicite, le serveur refuse de démarrer sur une interface réseau. `-tls-cert` et `-tls-key` vont
ensemble : l'une sans l'autre est refusée, au lieu d'être ignorée en servant en clair (revue 0.5.0, C8).

**A24. Client HTTP anti-SSRF pour toutes les requêtes sortantes.** Flux et webhooks sont des URL
fournies par les utilisateurs : contrôle à la connexion (après résolution DNS, contre le DNS
rebinding) des adresses privées, locales et réservées ; redirections limitées et en HTTPS. Le proxy
de l'environnement, d'abord ignoré parce qu'il masquait la destination réelle, est honoré depuis A44 :
la destination est vérifiée avant de lui être confiée. Les sources fixes (OSV, NVD, KEV, EPSS)
passent par le même client (`netsafe.NewClient`) depuis la revue de la 0.5.0 (T13) : elles avaient un
client ordinaire, qui suivait une redirection en HTTPS vers une adresse interne ; `-allow-private-urls`
vaut pour elles aussi. Même règle de redirection pour tous (`netsafe.CheckRedirect` : 5 au plus, en
HTTPS, la clé NVD retirée si l'hôte change). *Conséquence* : le délai propre aux en-têtes (30 s) est
retiré, seule compte la limite de la requête (60 s, 5 min pour OSV) : une source calcule parfois
longtemps une grosse page avant de répondre, et le client ordinaire des sources n'en avait pas.
Sans `ForceAttemptHTTP2` (la connexion est composée par le contrôle), les sources passent en HTTP/1.1.

**A25. API par jeton limité à un projet.** Les pipelines CI poussent leur SBOM via
`PUT /api/v1/projects/{projet}/sbom`. Un jeton n'écrit qu'un seul projet (moindre privilège),
est stocké haché, affiché une seule fois, préfixé `vgl_` (repérable par les scanners de secrets).
*Limite assumée* : pas d'expiration, révocation manuelle. Un jeton est suspendu tant que le compte
qui l'a créé est désactivé, comme les sessions de ce compte : le départ d'un administrateur ne
laisse pas de jeton actif derrière lui, et la réactivation du compte rend ses jetons utilisables.
Le contrôle est une jointure sur `users` à chaque appel (sans migration) ; la liste des jetons de
Paramètres montre le jeton suspendu et nomme le compte, pour qu'un administrateur comprenne
pourquoi une CI échoue (l'API répond « jeton invalide », comme pour un jeton révoqué). Un jeton
sans créateur connu (colonne vide : aucun chemin de Vigil n'en crée aujourd'hui) reste valide.
Écartés : révoquer les jetons à la désactivation, ce qu'une réactivation ne pourrait pas défaire ;
une réponse distincte de l'API, qui dirait à qui détient le jeton que le compte est désactivé.

**A70. Noms de compte : uniques à la casse près, et absents du journal s'ils sont inconnus.**
Audit de novembre 2026, S16 et S17.
- *Création* : « Alice » et « alice » pouvaient coexister (contrainte `UNIQUE` sensible à la casse)
  et se confondre dans l'historique de triage et le journal d'audit ; le limiteur de connexion, lui,
  les comptait déjà ensemble. Un nom qui ne diffère d'un nom existant que par la casse est refusé, à
  un seul endroit : `Store.CreateUser`, partagé par Paramètres → Utilisateurs et `vigil user add`
  (l'installation, `CreateFirstAdmin`, ne crée un compte que sur une base vide). La comparaison se
  fait en Go (`strings.EqualFold`, qui replie aussi « É » et « é »), dans la même transaction que
  l'insertion : deux créations simultanées ne passent pas toutes les deux. Erreur `store.ErrExists`,
  réutilisée depuis pour les autres doublons et pour le même nom inséré entre-temps par un autre
  processus (contrainte `UNIQUE` traduite par `mapUnique`, A73). Écartés : `COLLATE NOCASE` sur la colonne, qui demande une
  migration, échouerait sur une base où deux comptes se chevauchent déjà, et ne replie que l'ASCII ;
  renommer les comptes existants qui se chevauchent (ils restent) ; une connexion insensible à la
  casse (le nom se tape toujours exactement).
- *Échec de connexion* : `login_failed` gardait le nom tapé ; un mot de passe saisi dans le champ du
  nom finissait dans la base et le journal du service. Le nom n'est plus gardé que s'il est celui
  d'un compte, désactivé compris (tentative d'un ancien collègue) ; sinon seule l'adresse est
  enregistrée, au même format (`ip=… user=…`). La recherche du compte a lieu à chaque échec, en une
  requête, quel que soit le nom, et la réponse ne change pas : même page, même calcul argon2 (factice
  pour un nom inconnu). Écartés : ne jamais garder le nom, qui effacerait la trace d'une force brute
  visant un compte ; une empreinte du nom, illisible pour l'administrateur et facile à retrouver.

**A67. Une portée obligatoire dans chaque requête du stockage.** Regrouper les actifs puis limiter
des comptes à des groupes (modèle retenu en novembre 2026 : groupes définis par des étiquettes et
des projets, rôle global restreint à des groupes, livré par étapes) demande un contrôle par objet,
en plus du rôle vérifié à chaque route. Il se fait dans `internal/store` : chaque méthode qui lit ou
écrit un actif, ou ce qui en dépend (vulnérabilités trouvées, historique, règles d'écart, digests,
chiffres du tableau de bord, alertes, mention « concerne l'inventaire » de la veille), reçoit une
portée (`store.Scope`) qui entre dans le `WHERE` de chaque requête. La valeur nulle ne couvre rien :
une page qui l'oublierait serait vide, sans rien montrer d'autre. `store.Everything` couvre tout, pour
la synchronisation, les notifications, la ligne de commande et les comptes sans restriction ;
`store.InGroups` couvre les groupes d'un compte limité (A68). Hors portée, un identifiant répond
« Introuvable », comme s'il n'existait pas. Écartés : le
contrôle dans chaque page (un oubli y est une fuite, et le triage par lot comme l'import VEX prennent
leurs identifiants dans le contenu de la requête) ; la base elle-même (SQLite n'a pas de sécurité par
ligne, et la connexion unique, A5, interdit des vues par utilisateur). *Vérification* : un test liste
par réflexion les méthodes du stockage et exige pour chacune un cas d'isolation (la portée nulle
n'atteint rien et ne change rien) ou une raison d'en être exemptée ; dans `internal/web`, seul
`scope.go` accorde `store.Everything`, les méthodes de la synchronisation ne sont pas appelées, et
les routes forment une table que les tests parcourent.

**A68. Groupes d'actifs définis par des étiquettes et des projets ; comptes limités à des groupes,
contrôlés dans le stockage.** Une équipe, un site ou un client devait pouvoir ne voir que son
inventaire : les trois rôles (A20) valaient pour toute la base. Un groupe est un nom, des étiquettes
et des projets ; un actif en fait partie s'il porte une de ses étiquettes ou appartient à un de ses
projets, valeurs exactes (l'étiquette « web » ne prend pas « webapp »). Rien n'est enregistré par
actif : l'appartenance est calculée à chaque requête, un actif peut être dans plusieurs groupes et un
composant de SBOM entre dans le groupe de son projet dès l'import, API comprise. Un actif isolé reçoit
une étiquette dédiée. Un compte garde son rôle global et reçoit un accès : tout l'inventaire, ou ses
seuls groupes. Un administrateur voit tout, quel que soit son accès : il gère les comptes et pourrait
s'accorder n'importe quel groupe. Le contrôle est la portée de A67 : `User.Scope` la tire du compte de
la session, relu à chaque requête, et la condition SQL (`Scope.cond`) calcule une fois par requête les
actifs des groupes (`a.id IN (SELECT …)`), plutôt qu'une condition corrélée ligne par ligne, mesurée
deux fois plus lente dans l'étude. Hors périmètre, un objet est introuvable (404), comme un objet
inexistant ; un identifiant d'un triage par lot ou d'un énoncé VEX hors périmètre est ignoré comme un
inconnu. Ce que le compte voit le suit partout : listes, pages, compteurs et graphiques du tableau de
bord, actualités « qui concernent l'inventaire », exports CSV et VEX, étiquettes, projets et groupes
proposés. L'état de la synchronisation parcourt tout l'inventaire : un compte limité y voit si elle
tourne et son avancement en pourcentage, sans nom ni compteur. *Canaux et digests* (migration 018) : un
canal de notification peut être limité à un groupe ; il en reçoit les seules alertes (les vulnérabilités
urgentes de ce groupe, `PendingAlerts` dans sa portée) et le seul digest. Un digest couvre tout
l'inventaire ou un groupe (`digests.group_id`) : les digests périodiques sont celui de tout l'inventaire
et un par groupe ayant un canal de digests actif (`digest.Run`), chacun « depuis le précédent » de son
groupe (A19) ; dans l'interface, on génère celui de tout l'inventaire ou d'un de ses groupes. Un compte
limité lit les digests de ses groupes, jamais celui de tout l'inventaire ; un compte sans restriction
les lit tous. Depuis la revue de la 0.5.0 (W6), ce que couvre le digest demandé par la page se décide dans
`scope.go` (`digestGroup` : le groupe, que le compte doit voir, ou tout l'inventaire, réservé à qui voit
tout), et `digest.Generate` reçoit la portée de l'appelant, qu'il réduit au groupe sans jamais l'élargir :
le digest du groupe zéro ne lit plus `store.Everything` pour quiconque le demande. Les canaux qui reçoivent
le digest d'un périmètre sont désignés en un seul endroit (`store.Webhook.ReceivesDigest`), pour l'envoi,
les digests périodiques et la page ; celle-ci ne dit « envoyé » que si un canal l'a reçu (`SendDigest`
rend leur nombre, W8 et C5 : un canal d'alertes seules suffisait à l'annoncer envoyé). La marque « déjà alertée » d'une vulnérabilité reste unique : un canal de groupe ajouté
plus tard ne reçoit pas les alertes déjà envoyées, comme un canal ajouté aujourd'hui. Un groupe auquel
un canal est limité ne se supprime pas (il recevrait sinon tout l'inventaire) ; ses digests partent
avec lui. *Écritures* : un compte limité ne fait entrer un actif que dans ses
groupes, ne l'en fait sortir que de ses groupes, et l'y laisse dans au moins un, sauf pour le
supprimer ; formellement, avec G avant et G après les groupes de l'actif, (G avant Δ G après) ⊆ ses
groupes et G après rencontre ses groupes. La même règle couvre la création (G avant vide), la
modification, la suppression (G après vide : un actif partagé avec un autre groupe ne se supprime pas
depuis un compte limité), l'import CSV (tout ou rien, A41) et l'import SBOM (les composants nouveaux,
sans étiquette, sont dans les groupes de leur projet : ces groupes existent et sont tous les siens ;
un composant gardé ou retiré ne change pas de groupe). Elle est vérifiée dans la transaction de
`CreateAssets`, `UpdateAsset`, `DeleteAsset` et `ReplaceProjectAssets` (`checkMove`), les groupes de
l'actif avant et après calculés par la même condition que la lecture (`ruleMatch`). Le refus
(`store.OutsideGroupsError`) dit quoi corriger, avec les seules valeurs de l'actif, que l'utilisateur a
sous les yeux : l'étiquette ou le projet qui le rattache à un groupe d'autrui, ou ceux qui le
garderaient dans les siens ; le formulaire d'un actif les rappelle à un compte limité. Les filtres de
veille, réglage commun à tous, sont réservés aux comptes sans restriction ; la synchronisation complète
reste permise (les imports la lancent déjà). À la création d'un jeton d'API, un administrateur peut
ajouter son projet à un groupe. Administration : Paramètres → Groupes (nom, étiquettes et projets
cochés parmi ceux en usage, avec leur nombre d'actifs, ou une valeur pas encore utilisée ; nombre
d'actifs hors de tout groupe) ; l'accès se choisit dans Paramètres → Utilisateurs, obligatoirement à la
création (bouton radio `required`), et en ligne de commande (`vigil user add -groups`,
`vigil user set-access`) ; la page d'un actif nomme ses groupes, « Mon compte » l'accès ; un filtre
Groupe s'ajoute à l'inventaire et aux vulnérabilités (`Scope.Only`, qui ne peut que restreindre). Le
journal d'audit garde la création, le renommage, les règles et la suppression d'un groupe, et l'accès
donné à un compte (`access=groups groups="Équipe web,Compta"`). Un nom de groupe est unique à la casse
près (comparaison en Go, comme les noms de compte, A70), sans virgule pour la ligne de commande.
*Options écartées* : un rôle par groupe (droits par objet dans chaque gabarit et matrice comptes ×
groupes, pour un besoin rare dans les équipes visées ; une colonne `role` dans `user_groups` le
permettra si la demande vient) ; les étiquettes ou les projets seuls comme groupes (droits à répéter
compte par compte, un seul projet par actif) ; des membres enregistrés par actif (un troisième
classement, et rien d'automatique sans règles) ; un filtre dans les handlers (un oubli suffit pour un
accès par identifiant) ; un compte sans groupe qui verrait tout (retirer son dernier groupe lui
ouvrirait la base) ; l'accès « tout » par défaut à la création dans l'interface. *Conséquences* :
migrations 017 et 018 ; les comptes existants reçoivent l'accès à tout, les canaux et digests
existants couvrent tout l'inventaire comme avant, et `vigil user add` sans `-groups` le
garde, pour ne pas casser les scripts ; en base, la valeur par défaut refuse ; un actif hors de tout
groupe n'est vu que des comptes sans restriction ; changer une étiquette peut changer qui voit un
actif, d'où ses groupes affichés sur sa page ; un actif partagé par deux groupes a un seul triage,
visible des deux, et son historique nomme les comptes des deux ; supprimer un groupe ne supprime aucun
actif, ses comptes voient moins, jamais plus ; l'identifiant d'un groupe n'est jamais réutilisé
(`AUTOINCREMENT`). *Vérification* : la condition SQL est comparée à la règle écrite en Go sur des jeux
aléatoires (cas limites compris), chaque route d'objet croisée avec cinq comptes et quatre actifs
(matrice : 403 pour le rôle, puis 404 pour la portée, rien de modifié), et un actif témoin d'un autre
groupe ne doit apparaître dans aucune page, aucun export ni aucune indication d'un compte limité.
*Mesure* (copie de la base des noyaux Debian et Ubuntu de A64, 7 629 vulnérabilités, pilote de Vigil) :
la portée « tout » coûte ce qu'elle coûtait (tableau de bord environ 320 ms, liste d'un noyau environ
28 ms) ; un compte limité au groupe d'un noyau voit son tableau de bord en environ 65 ms et la liste du
noyau en environ 28 ms ; limité à un groupe couvrant les deux, il retrouve les temps de « tout ».

**A71. Le stockage lit et écrit d'une seule façon.** L'audit de la 0.4.2 (D1, D3, D5, D6) comptait
environ 25 copies de la boucle de lecture SQL, trois interfaces locales équivalentes, `RowsAffected`
ignoré sept fois et une soixantaine d'erreurs sans contexte. Une liste s'écrit désormais
`collect(ctx, q, étiquette, scan, requête, args...)` : `collect` lit et ferme toutes les lignes avant
de rendre la main, ce qui la rend sûre dans une transaction (connexion unique, A5), et préfixe ses
erreurs de l'étiquette ; `querier` (`*sql.DB`, `*sql.Tx`, `*sql.Conn`) et `scanner` sont les deux
seules interfaces. Une écriture qui doit toucher une ligne passe par `expectRow` (`ErrNotFound`
sinon, l'erreur de `RowsAffected` remontée) ; toute erreur interne porte une étiquette en anglais
(`wrap`), les messages destinés à l'écran restent tels quels (A4). Noms : `ListX` pour une liste,
le nom simple pour la clé primaire (`User`, `Session`), `XByY` pour une autre clé ; un seul type
`User` pour la table des comptes (`Account` a disparu). `UserByName` garde son sens, comptes actifs
seulement, pour la connexion ; la recherche qui inclut les comptes désactivés prend un nom nouveau,
`AnyUserByName`, pour qu'un appel écrit dans une autre branche ne change pas de sens en silence à
la fusion. Toute méthode rejoint la transaction de `Store.InTx` que porte son contexte (A57).
Échéances : « hors délai » et le filtre des vulnérabilités en retard se jugent à la même heure,
`FindingFilter.Now`, que le tableau de bord et le digest passent avec celle de leurs
chiffres (l'heure courante sinon), au lieu de trois horloges (`time.Now()` à la lecture,
`date('now')` dans le filtre, celle de l'appelant au tableau de bord). Rangement : helpers
génériques dans `store.go`, réglages dans `settings.go`. Écartés : sqlx ou un ORM (une dépendance de
plus, A26, pour une boucle de vingt lignes) ; une horloge portée par le `Store`, qui resterait une
deuxième horloge à côté de celle de l'appelant ; donner à `UserByName` le sens « tous les comptes »,
piège de fusion décrit plus haut. *Conséquences* : une liste nouvelle tient en un appel et une
fonction de lecture ; une erreur du journal nomme l'opération du stockage qui a échoué.

**A72. Options, statuts et rôles : une définition chacun.** L'audit de la 0.4.2 (R3, R4, D2)
trouvait deux types d'option identiques (`inventory.Option`, `cti.Tag`), neuf tests d'appartenance
écrits `Label(options, v) != v` (justes tant qu'aucun libellé n'égale sa valeur, faux pour une
option `{"Linux", "Linux"}`), « vulnérabilité ouverte » définie en Go dans `web`, recopiée dans un
template et en SQL, et les rôles listés trois fois (`auth`, `web`, une comparaison à `"admin"`).
Le paquet feuille `choice` (`Option`, `Label`, `Has`, `Rank`, `KnownOnly`) sert toutes les listes :
il n'importe rien de Vigil, pour que `tracking`, `notify`, `digest`, `cti`, `inventory`, `auth` et
`web` l'utilisent sans dépendre d'`inventory`. L'appartenance se lit par `Has`, jamais par le
libellé ; un test vérifie qu'aucune liste n'offre deux fois la même valeur. Les statuts sont des
constantes de `store` (`StatusInTriage`…), y compris dans le classement (`tracking.Level`) et les
alertes, « ouverte » est `Finding.Open`, que les templates appellent, et `openStatuses` en SQL ; la dernière clôture d'une vulnérabilité (`lastClosings`),
la résolution automatique avec son événement (`autoResolve`) et le changement de statut avec son
historique (`setStatus`) ne sont plus écrits qu'une fois. Les rôles forment une liste ordonnée,
`auth.Roles`, du plus au moins privilégié comme le menu les montre, dont dérivent `RoleAtLeast`,
`ValidRole` et ce menu. Écartés : garder les mots-clés de la veille dans `choice` (ils ne servent
qu'à `cti`, qui les garde dans ses tables et publie des `choice.Option`) ; mettre les statuts
dans `tracking`, que `store` ne peut pas importer. *Conséquences* : une liste, un statut ou un
rôle nouveau s'ajoute à un seul endroit ; les libellés des statuts restent dans
`tracking.Statuses`.

### Notifications, délais et échanges (0.3)

Ces décisions viennent d'un comparatif avec OpenCVE, Dependency-Track, DefectDojo, CIRCL
Vulnerability-Lookup et Taranis AI (voir [BENCHMARK.md](BENCHMARK.md)) : elles comblent les
manques qui gênaient l'usage quotidien d'une petite équipe, sans viser la profondeur de ces outils.

**A37. Alertes immédiates par niveau d'urgence, une fois par niveau.** OpenCVE et
Dependency-Track préviennent dès qu'une vulnérabilité correspond ; Vigil n'avait que le digest.
Chaque vulnérabilité ouverte a une classe : prioritaire (KEV, EPSS ≥ 10 % ou statut Exploitable, A78), sévère (critique ou
haute), autre. À la fin de chaque synchronisation, celles dont la classe dépasse la classe déjà
notifiée (`findings.alerted`) partent, en un message par canal, vers les canaux qui demandent ce
niveau ; une vulnérabilité qui devient exploitée est donc signalée à nouveau. Écartés : une alerte
par vulnérabilité (avalanche au premier import d'un SBOM), un moteur de règles à la
Dependency-Track (configuration lourde pour la cible). La migration marque les vulnérabilités
existantes comme déjà notifiées : pas d'avalanche après la mise à jour. Une alerte en échec n'est
pas renvoyée : l'erreur s'affiche sur le canal et le digest suivant liste la vulnérabilité. Les classes
sont les niveaux de la liste (A60) : un canal choisit « Urgentes seulement » ou « Urgentes et À planifier »,
et l'alerte se titre et renvoie aux listes par ces niveaux (A84). Un canal limité à un groupe d'actifs ne
reçoit que les alertes de ce groupe (A68).

**A38. E-mail par SMTP direct, dans les mêmes canaux que les webhooks.** Toutes les solutions
comparées notifient par e-mail ; c'est le canal universel des petites structures. `net/smtp` de la
bibliothèque standard suffit (aucune dépendance) ; le serveur est fixé par l'exploitant (options
`-smtp-*`), les destinataires par l'administrateur, comme un webhook. STARTTLS est exigé par défaut
(pas de repli en clair si le serveur ne le propose pas), `net/smtp` refuse d'envoyer un mot de
passe sans TLS sauf vers la machine locale. Messages en texte (le Markdown du digest se lit tel
quel), en-tête `Auto-Submitted` contre les réponses automatiques. Les destinataires sont des
adresses simples : `net/mail` retire les guillemets d'une partie locale, et
`"x> NOTIFY=NEVER"@example.com` arrivait tel quel dans `RCPT TO:<…>`, où `>` et les espaces
ajoutent des paramètres SMTP. Une adresse qui contient une espace ou l'un de `<>()[],;:\"` est donc
refusée, adresse IP entre crochets comprise ; un nom affiché (`Équipe <soc@example.org>`) reste
accepté, et seule l'adresse est utilisée. L'adresse doit aussi porter exactement un `@` :
`"a@b"@example.com` devenait `a@b@example.com`, qu'un serveur peut acheminer selon le premier `@`.
L'expéditeur (`-smtp-from`) suit la même règle (`plainAddress`, commune aux deux), puisqu'il entre
dans `MAIL FROM:<…>` et l'en-tête `From` : une adresse refusée empêche Vigil de démarrer, avec la
règle dans le message. Écartée : une validation complète de la RFC 5322, inutile pour des adresses
saisies par l'exploitant et l'administrateur, et qui accepterait justement les formes ci-dessus.

**A39. Délais de traitement calculés à partir de la détection, par sévérité.** DefectDojo et les
politiques internes (NIS2 : traitement « dans des délais appropriés ») suivent des échéances.
Délais par défaut de la directive CISA BOD 19-02 (15 jours critique, 30 haute) complétés (90, 180),
réglables, 0 = aucun. Une vulnérabilité exploitée (KEV) prend le délai critique ; l'échéance CISA
reste affichée à titre d'information mais n'est pas utilisée (elle peut précéder la détection). Les
échéances sont calculées en SQL à la lecture, jamais stockées : changer un délai recalcule tout.
Différé : délais selon la criticité de l'actif ou par projet.

**A40. Actualités qui concernent l'inventaire, par identifiant CVE.** L'atout d'un outil qui fait
à la fois inventaire et veille : signaler l'avis du CERT-FR qui parle d'une vulnérabilité ouverte
chez soi. Les identifiants CVE cités dans le titre et le résumé de chaque actualité sont indexés
(`cti_mentions`, rempli pour l'existant par une étape Go de la migration) et croisés avec les
vulnérabilités ouvertes (identifiant ou alias). Écartés : rapprochement par nom de produit
(faux positifs nombreux), NLP. Limite : une actualité qui ne cite pas l'identifiant n'est pas reliée.

**A41. Échanges par tableur : CSV en entrée et en sortie.** La cible tient souvent son inventaire
dans un tableur. Export des vulnérabilités (avec les filtres affichés) et de l'inventaire ; import
de l'inventaire en virgules ou points-virgules (Excel en français), en-têtes et libellés français
acceptés. Import tout ou rien : la moindre ligne invalide refuse le fichier, avec les numéros de
ligne, et les actifs sont écrits en une transaction (`Store.CreateAssets`) : une panne au milieu de
l'écriture n'en ajoute aucun, comme le dit la page (audit de novembre 2026, R12 ; ils étaient créés un
par un). Pour un compte limité à des groupes (A68), les lignes identiques à un actif existant ne
sont cherchées que parmi ceux qu'il voit (l'import ne dit rien des autres), et une ligne qui sortirait
de ses groupes refuse le fichier entier. Les exports utilisent le point-virgule et la virgule décimale, comme Excel en français.
*Sécurité* : toute cellule commençant par `=`, `+`, `-`, `@` est préfixée d'une apostrophe
(injection de formules à l'ouverture dans un tableur), de même qu'un tel caractère placé dans une
valeur après une virgule, un point-virgule, une tabulation ou un saut de ligne, éventuellement
suivis d'espaces : un tableur qui découpe sur un autre séparateur que celui du fichier y
commencerait une cellule, et un tableur qui retire les espaces des cellules ferait une formule de
`prod, =1+1` (étiquettes jointes par une virgule et une espace). Une espace seule ne commence pas
de cellule : « 2.0 - 2.5 » ou « a = b » restent intacts. Écarté : traiter l'espace comme un
séparateur. Seul un import où l'on coche « Espace » découpe ainsi, choix manuel qui met en pièces
chaque texte ; s'en protéger aurait abîmé tous les résumés et notes exportés. Une apostrophe déjà
présente devant un tel caractère compte : l'import retire exactement ce que l'export ajoute, et
un export relu redonne les valeurs exportées.

**A42. Recherche de CPE dans le dictionnaire de la NVD, à la demande.** Écrire un CPE à la main
était le principal frein au suivi des produits. La page de recherche interroge l'API CPE de la NVD
et préremplit le formulaire (version précise, produit entier ou éditeur entier). Piège constaté
en test : l'API renvoie les entrées des plus anciennes aux plus récentes, et beaucoup de produits
ont changé de nom d'éditeur (`elasticsearch:elasticsearch`, dernière version référencée en 2015,
devenu `elastic:elasticsearch` ; `joyent:node.js` devenu `nodejs:node.js`). Une recherche par
mots-clés limitée aux premières entrées ne proposait donc que des noms abandonnés, sans aucune
vulnérabilité récente. La recherche essaie d'abord le nom exact du produit (tous ses éditeurs), puis
« éditeur produit », puis l'éditeur seul, enfin les mots-clés en ne gardant que les entrées les
plus récentes. Les résultats sont regroupés par éditeur et produit, avec le nombre de versions et la
date de la dernière entrée ; un produit sans nouvelle entrée depuis trois ans est signalé comme
« ancien nom » et placé après les noms actuels ; les versions proposées sont triées par numéro.
Écarté : copie locale du dictionnaire (plus d'un million d'entrées, mises à jour quotidiennes) —
contraire à A9. Les requêtes partagent l'espacement de la synchronisation (limite de débit de la NVD).

**A45. Suivre tous les produits d'un éditeur.** Comme les abonnements d'OpenCVE : un actif dont le
CPE n'a ni produit ni version (`cpe:2.3:*:fortinet:*:*:*:*:*:*:*:*:*`) reçoit toute vulnérabilité
publiée pour l'éditeur, quel que soit le produit. La NVD accepte ce motif dans le même mode que
« toutes les versions » : aucune logique nouvelle de synchronisation, la période de suivi et les
KEV s'appliquent pareil. Une version saisie sur l'actif est ignorée. *Limite assumée* : un grand
éditeur représente des milliers de vulnérabilités par an (Microsoft : environ 3 500 en 120 jours
en octobre 2026) ; l'interface le signale. Éditeur et produit sont affichés à part dans
l'inventaire, déduits du CPE ou du purl, sans colonne supplémentaire en base.

**A46. Étiquettes libres sur les actifs.** Équipe, environnement, site, application : chaque
organisation classe son inventaire à sa façon, au-delà du projet (réservé aux SBOM). Les étiquettes
se saisissent librement dans un champ (séparées par des virgules), sans liste à administrer ; elles
sont mises en minuscules pour qu'une même étiquette ne se dédouble pas (« Prod », « prod »).
Stockage comme les étiquettes de la veille (`,prod,web,`, migration 010). Filtres de l'inventaire et
des vulnérabilités, export et import CSV. Écarté : une table d'étiquettes avec administration
(complexité sans besoin avéré). Une étiquette compte 40 caractères au plus (`inventory.MaxTagLen`),
20 par actif (`maxTags`). Les deux filtres lisent l'étiquette demandée comme elle est stockée
(`tagParam`, par `inventory.NormalizeTags`) et ignorent une étiquette plus longue que cette borne,
qu'aucun actif ne peut porter : le filtre des vulnérabilités en acceptait 100 caractères, celui de
l'inventaire la prenait telle que tapée (« Prod » n'y trouvait rien).

**A47. Digest regroupé par éditeur.** Le digest commence par un tableau éditeur × sévérité
(critiques, hautes, moyennes, basses, inconnues, total, exploitées), puis liste les vulnérabilités
de chaque éditeur de la plus grave à la moins grave ; dans une même sévérité, les exploitées (KEV)
d'abord, puis par score CVSS. La sévérité est celle de l'avis, à défaut la tranche du score CVSS
(9 et plus, 7 à 8,9, 4 à 6,9, moins de 4). L'éditeur vient du CPE (Fortinet), de l'espace de noms du
purl (org.apache.logging.log4j) ou, sans espace de noms, de l'écosystème (Paquets npm). Les
vulnérabilités ouvertes sont limitées à 25 par éditeur dans la liste, les compteurs restant
complets : un abonnement à un grand éditeur en compte des milliers. Le tableau vient en tête pour
survivre à la troncature des messages de discussion. Depuis A87, le tableau compte aussi les urgentes et
range les éditeurs par elles d'abord (la colonne « exploitées » s'efface : elles en font partie) ; les
listes par éditeur laissent place à une liste des plus urgentes, bornée à 50 lignes, et ce sont les
urgentes et les nombres par niveau qui viennent en tête.

**A48. Audit de sécurité et d'ergonomie (octobre 2026).** Revue de l'architecture, du réseau et du
code au regard de l'OWASP ASVS, puis de chaque écran. Décisions :
- *Comptes* : désactivés plutôt que supprimés (migration 011), pour que l'historique et le journal
  d'audit gardent le nom de qui a agi ; le dernier administrateur actif est protégé dans la
  requête elle-même (pas de course) ; un mot de passe provisoire est généré plutôt que choisi par
  l'administrateur. Écarté : la suppression définitive, qui effacerait la traçabilité.
- *Connexion* : essais comptés avant la vérification, par adresse et par compte ; argon2 limité à
  4 calculs simultanés. Le verrouillage d'un compte par un tiers est le prix assumé.
- *Instance locale* : seuls `localhost`, `127.0.0.1` et `::1` (et l'hôte de `-base-url`) sont
  acceptés dans l'en-tête `Host`, contre le *DNS rebinding*. Pas de liste d'hôtes en mode serveur :
  HTTPS y empêche déjà l'attaque (le certificat ne correspond pas au domaine de l'attaquant).
- *Messageries* : le texte tiers passe par `chattext` (mentions et liens neutralisés par un espace
  invisible, chevrons remplacés). Écarté : un échappement différent par messagerie, qui obligerait à
  produire un digest par canal.
- *Traçabilité* : le journal d'audit est dupliqué dans le journal du service, pour une copie hors
  de la base ; les suppressions et désactivations de flux, canaux et jetons y entrent.
- *Suites (même mois)* : voir A49.

**A49. Suites de l'audit.** Les points différés et les recommandations d'ergonomie de A48 :
- *Composants retirés d'un SBOM* : marqués retirés (migration 012) au lieu d'être supprimés. Leurs
  vulnérabilités encore ouvertes passent « corrigées » avec un événement d'historique (le composant
  a disparu, souvent remplacé par une version corrigée) ; les décisions (non affecté, faux positif)
  restent ; le composant revient tel quel si un SBOM le liste à nouveau. Ni listé ni vérifié tant
  qu'il est retiré ; une vue de l'inventaire les montre. Écarté : un retrait sans clôture des
  vulnérabilités, qui les aurait laissées ouvertes sans actif à corriger.
- *Double authentification obligatoire* : réglage « personne / administrateurs / tous » ; un compte
  concerné sans second facteur n'atteint plus que « Mon compte ». Pas d'option de démarrage : le
  réglage se change dans l'interface et entre dans le journal d'audit.
- *Rétention* : `-audit-retention-days` pour le seul journal d'audit, sans limite par défaut.
- *Images d'outils* : Trivy, gitleaks, BuildKit et Caddy épinglés par digest.
- *Ergonomie* : nombre de vulnérabilités antérieures à la période de suivi affiché sur l'actif (pour
  les paquets ; la NVD n'est interrogée que sur la période) ; version corrigée lue dans l'avis
  stocké (OSV : intervalles ; NVD : bornes des CPE), la branche de la version de l'actif en tête ;
  page de suivi de la synchronisation qui se recharge seule, sans JavaScript (balise *refresh*) ;
  listes en cartes sur téléphone ; ajout d'actifs sur sa propre page ; mots de passe et jetons
  affichés une fois après redirection (pas de nouvel envoi du formulaire au rechargement). Chaque
  sorte de valeur (jeton d'API, mot de passe provisoire) attend dans sa propre case de la session,
  que seule sa page lit (`keepOnce` / `takeOnce` avec une sorte) : passer par une autre page, ou
  voir un formulaire refusé, ne la fait plus disparaître sans l'afficher. Écarté : une seule case
  par session, où `/settings` prenait le mot de passe créé juste avant, et la page des
  utilisateurs le jeton.

**A50. Pas de chiffrement applicatif des secrets au repos.** Les secrets que Vigil vérifie sont
stockés comme empreintes (mots de passe en argon2id, jetons de session et d'API en SHA-256). Ceux
qu'il utilise ne peuvent pas l'être : le secret de double authentification sert à calculer le code
attendu, l'URL d'un webhook est l'adresse d'envoi. Options écartées :
- *chiffrement par une clé du serveur* : une clé à créer, sauvegarder à part, faire tourner, avec
  la perte de la double authentification et des canaux si elle disparaît ; trop de complexité pour
  un outil sans infrastructure ;
- *clé tirée du mot de passe de l'utilisateur* : qui vole la base et casse le mot de passe obtient
  aussi la clé ; aucun gain ;
- *exclure ces secrets des sauvegardes* : une restauration perdrait sans bruit la double
  authentification de tous et les notifications ;
- *SQLCipher* : CGO, fin du binaire unique.

Retenu : la base et ses copies se protègent dans leur ensemble par l'infrastructure (chiffrement du
disque, sauvegardes hors machine chiffrées par restic, borg ou rclone crypt), ce qui couvre aussi
l'inventaire, la donnée la plus sensible ; et une fuite se traite par rotation :
`vigil user reset-totp -all`, régénération des URL de webhooks et des clés de flux (OPERATIONS.md).

**A43. Triage par lot et journal d'audit consultable.** Le triage par lot applique une même
décision à des vulnérabilités cochées, avec un événement d'historique pour chacune (pas de
raccourci qui perdrait la traçabilité). Le journal d'audit, déjà écrit, devient lisible par les
administrateurs (exigence fréquente des audits NIS2 ou ISO 27001). Format du détail : A73. Depuis
A85, la décision peut porter sur toute la liste filtrée, avec les garde-fous des règles d'écart.

**A73. Un seul format pour le détail du journal d'audit, un seul chemin pour lire et modifier un objet
par son identifiant.** L'audit de code de novembre 2026 (R1, R5, R7, R12) relevait quatre formes de
détail (`12`, `id=12`, `12 → resolved`, `12 texte`), sept façons de lire un identifiant dans le chemin
et des erreurs avalées ou mal nommées dans les handlers.
- *Journal d'audit* : le détail d'une entrée nouvelle est une suite de paires `clé=valeur` séparées
  par une espace, l'identifiant de l'objet d'abord (`id=12 status=resolved`,
  `id=3 name="CERT FR" url=https://cert.example/…`). Une valeur vide, ou qui contient une espace, un
  guillemet, un signe `=`, un caractère non imprimable ou de l'UTF-8 invalide, est écrite entre
  guillemets et échappée comme en Go (`text="a\nb"`) : un nom ou un texte saisi ne peut ajouter ni
  champ ni ligne, dans la base comme dans le journal du service. Les clés sont des codes en anglais,
  comme les valeurs fixes (`role=analyst`, `enabled=false`, `trigger=manual`). Une seule fonction
  l'écrit, `store.AuditDetail`, par où passent l'interface (`audit` ne prend plus que des paires ; un
  test vérifie que chaque appel en passe) et la ligne de commande (`auditCLI`, qui ajoute
  `source=cli`). Les entrées déjà en base gardent leur forme ; la page du journal montre les deux
  telles quelles. Écartés : JSON, lourd à lire sur la page ; des phrases, illisibles pour un SIEM ;
  récrire les entrées anciennes, ce qui modifierait la trace même que le journal doit garder.
- *Lire et modifier par identifiant* : `pathID` lit un identifiant du chemin (404 s'il n'est pas un
  nombre), `load` lit l'objet qu'il désigne (404 s'il n'existe pas, 500 si la base échoue ;
  `inScope` y lie la portée de la requête pour l'inventaire) et `change` applique une modification
  par identifiant, l'inscrit au journal une fois réussie, puis redirige ; `userChange` y ajoute les
  refus propres aux comptes (son propre compte, dernier administrateur actif). Ils remplacent
  `loadAsset`, `loadFinding`, `loadDigest`, `byID`, `audited`, `userAction` et les lectures en
  ligne. `redirect` ajoute son message à une adresse qui a déjà une requête : après un import SBOM,
  le message restait collé au nom du projet (`/assets?project=app?msg=…`), qui ne filtrait plus rien.
- *Doublon ou panne* : `store.mapUnique` traduit une contrainte d'unicité violée (codes SQLite
  `UNIQUE` et `PRIMARY KEY`) en `store.ErrExists` : création d'un flux (même URL) et d'un compte (le
  même nom inséré entre-temps par un autre processus, `vigil user add`, n'est plus une erreur
  interne) ; `CreateFirstAdmin` répond aussi `ErrExists` quand un compte existe déjà. Seul un vrai
  doublon affiche « Ce flux existe déjà » ; toute autre panne est une erreur interne.
- *Erreurs* : la création d'un digest lit d'abord les canaux ; si la lecture échoue, rien n'est
  généré (le digest se disait « généré » sans être envoyé à personne). La modification d'un flux et
  le test d'un canal lisent l'objet par son identifiant (`Store.Feed`, `Store.Webhook`) au lieu de
  relire toute la liste, et l'audit suit la réussite. La fermeture des autres sessions après un
  changement de mot de passe ou de double authentification suit une seule règle : le changement est
  fait, un échec est journalisé sans le faire échouer (c'était une erreur 500 pour la double
  authentification, un avertissement pour le mot de passe) ; ces sessions finissent alors à leur
  expiration, ou par « Fermer mes autres sessions », qui, lui, signale l'échec.

*Conséquence* : un outil qui lit le journal (SIEM) lit les entrées nouvelles par paires ; les
anciennes restent en texte libre.

### Construction, distribution, exploitation

**A26. Trois dépendances directes.** Chaque ajout se justifie dans
[DEPENDENCIES.md](DEPENDENCIES.md). TOTP, CVSS, parsing SBOM / VEX / RSS et clients d'API sont
écrits en interne car simples ; argon2 (cryptographie) et SQLite (moteur) ne le sont pas.

**A27. Configuration par options et variables d'environnement, sans fichier de configuration.**
Un format de fichier à part (YAML…) serait une dépendance et une source d'erreurs de plus. Chaque
option `-nom` peut venir de `VIGIL_NOM` ; la ligne de commande l'emporte. Convient au binaire,
à systemd (`EnvironmentFile`) et à Docker (`env_file`). Les options partagées sont déclarées une
seule fois, avec un seul texte d'aide (`newCommand`, audit de novembre 2026, X7) : `-db` pour toutes
les commandes, et pour `serve`, `sync` et `digest` `-base-url`, `-allow-private-urls`,
`-nvd-api-key` et les options SMTP, vérifiées avant l'ouverture de la base. La clé NVD passe par le
même mécanisme (`-nvd-api-key`, ou de préférence `VIGIL_NVD_API_KEY`, invisible des autres
utilisateurs de la machine) au lieu d'une lecture à part de la variable, et `VIGIL_DB` n'est lu
qu'à cet endroit. *Écarté* : une bibliothèque d'options (cobra…), une dépendance pour une dizaine
de commandes. *Conséquence* : `vigil digest` accepte `-base-url` (ou `VIGIL_BASE_URL`) et met alors
le lien du digest dans ses messages, comme le digest programmé de `serve`. *Amendé (revue 0.5.0, C8)* :
l'environnement ne règle plus que les options communes et celles de `serve` (`envOptions`), qui sont la
configuration du service ; les options propres aux autres commandes (`-all`, `-role`, `-groups`,
`-username`, `-o`, `-project`, `-no-webhooks`) ne viennent que de la ligne de commande. Un conteneur
transmet son environnement à `docker compose exec vigil vigil user …` : `VIGIL_ALL=true` y faisait retirer
la double authentification de tous les comptes à un `vigil user reset-totp` lancé sans option, et
`VIGIL_ROLE=admin` créer un administrateur. Aucune variable documentée n'est touchée.

**A28. Binaire d'abord, Docker en option.** Le binaire Go suffit (systemd fourni). L'image
existe pour les équipes dont l'exploitation passe par des conteneurs : distroless, non-root,
lecture seule hors `/data`. Le Compose d'exemple ajoute Caddy pour le HTTPS automatique : l'image
écoute en clair sur `0.0.0.0:8080` avec `-behind-proxy` (sa commande par défaut), et compte donc sur un
reverse proxy devant elle ; son port ne se publie que sur `127.0.0.1` (`docker run -p
127.0.0.1:8080:8080`) ou reste interne au Compose (`expose`). Elle porte les licences des archives de
release (celle de Vigil et celle de la liste SecLists embarquée, dans `/usr/share/doc/vigil/`) :
un test les rapproche de `.goreleaser.yaml`, et la CI les relit dans l'image construite.

**A29. Releases vérifiables.** GoReleaser : builds reproductibles (`-trimpath`, horodatage du
commit), six plateformes, checksums, SBOM par archive, attestation de provenance signée ; release
créée en brouillon et publiée après relecture. *Amendé (revue 0.5.0, C2, C3)* : ce qui est publié, et
quand. Les tests tournent d'abord, dans un job à part qui n'a ni jeton d'écriture ni jeton OIDC (ils
tournaient dans le job qui signe la provenance : un code exécuté par les tests, dépendances comprises,
pouvait signer en son nom), et qui refuse un tag posé hors de `main`. Puis les binaires et la release en
brouillon ; puis l'image, qui n'attendait ni les tests ni les binaires. Elle est publique dès la fin du
workflow, étiquettes `X.Y.Z` et `X.Y` : une image n'a pas de brouillon, et le Compose suit l'étiquette
`X.Y`. Aucun cache n'est restauré (`setup-go`, `cache: false`) : la release se construit sans rien de ce
qu'ont écrit d'autres exécutions. `vigil version` dit la même version dans l'image et dans les binaires
(`0.5.0`, sans le « v » du tag). La vérification d'une archive nomme le workflow qui l'a signée
(`gh attestation verify … --signer-workflow La-Cizaille-Corp/vigil/.github/workflows/release.yml`). Les
règles du dépôt (contrôles exigés pour fusionner dans `main`, tags `v*` réservés aux administrateurs)
sont des réglages GitHub, hors du code.

**A36. Mettre à jour sans jamais perdre de données.** Les données vivent hors du binaire (fichier
SQLite ou volume Docker) ; une mise à jour remplace le binaire et applique les migrations au
démarrage. Règles :
- une migration publiée ne change plus (empreintes vérifiées par `TestMigrationsFrozen`) ; une
  correction passe par une nouvelle migration ;
- une migration ajoute ou transforme, ne supprime pas de donnée utilisateur ; chaque transformation
  voulue est déclarée dans le test de mise à jour ;
- chaque migration s'exécute dans une transaction qui prend le verrou d'écriture d'emblée et
  revérifie qu'elle n'a pas déjà été appliquée (un `vigil sync` lancé pendant le démarrage du
  serveur) ;
- avant la première migration d'une base existante, une copie cohérente
  `<base>.schema-N.<date>.bak` est écrite à côté ; si elle échoue, rien n'est migré ;
- une base écrite par une version plus récente est refusée (`ErrNewerSchema`) : un ancien binaire
  pourrait l'abîmer sans le savoir ;
- `vigil backup` copie la base sans la migrer, même lancé avec le nouveau binaire.
*Vérification* : `TestUpgradeFromReleases` ouvre des bases réellement produites par chaque version
publiée (`internal/store/testdata/upgrade/vX.Y.Z.sql` : comptes, import SBOM, synchronisation
réelle, triage, flux, webhooks, digest) et vérifie que chaque valeur est intacte et lisible par le
code actuel. À chaque release, on ajoute le dump de la version publiée.

**A44. Proxy d'entreprise et adresse réelle du client.** Sortant : `HTTPS_PROXY` / `NO_PROXY`
sont honorés partout, y compris pour les URL saisies (flux, webhooks), auparavant privées de proxy
pour préserver le contrôle anti-SSRF. Le nom de destination est désormais résolu et vérifié avant
de confier la requête au proxy, qui seul peut avoir une adresse privée ; une URL qui vise le proxy
lui-même est refusée. *Risque résiduel* : le proxy résout le nom à nouveau, un rebinding DNS entre
les deux résolutions reste possible. Écarté : demander au proxy l'adresse vérifiée plutôt que le
nom, ce qui casserait les proxys d'entreprise qui filtrent par domaine. Le risque est borné : seul
HTTPS est permis et le certificat est vérifié contre le nom demandé, qu'un service interne ne peut
pas présenter ; la requête n'atteint donc jamais le service, au plus une connexion est tentée. Le
proxy devrait lui aussi refuser les destinations internes. Entrant : derrière un reverse proxy, toutes les connexions venaient de
son adresse, si bien que cinq échecs de connexion bloquaient tous les utilisateurs. Avec
`-behind-proxy`, la limitation et le journal d'audit utilisent la dernière adresse de
`X-Forwarded-For`, celle qu'ajoute le proxy (les précédentes peuvent être forgées par le client).
*Condition* : Vigil n'est joignable que par le proxy (écoute sur `127.0.0.1` ou réseau interne au
Compose), sinon l'en-tête pourrait être forgé.

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
| Assignation des vulnérabilités à une personne | Différé | Peu utile aux équipes de 1 à 3 personnes visées ; le champ Responsable de l'actif oriente déjà. |
| Tickets (Jira, GitLab) | Différé | Le webhook JSON générique (digests et alertes) permet de brancher un outil de tickets. |
| API de lecture (JSON) | Différé | Exports CSV et VEX couvrent les besoins de reporting ; à ouvrir avec des jetons en lecture seule si demande. |
| Acceptation de risque avec date d'expiration | Différé | Statuts VEX et commentaires suffisent pour l'instant ; une date de réexamen serait la prochaine étape. |
| Base européenne EUVD (ENISA) | Différé | API récente et encore mouvante ; les CVE qu'elle référence sont déjà couvertes par OSV et la NVD. |
| Service Windows natif | Différé | Planificateur de tâches ou WinSW suffisent (voir [INSTALL.md](INSTALL.md)) ; éviterait une dépendance. |
| Liste des sessions ouvertes (date, adresse) | Différé | Le bouton « Fermer mes autres sessions » de Mon compte couvre le besoin sans nouvelle colonne ; à ouvrir sur demande. |
| Jeton CSRF avant la connexion | Écarté | `Origin` et `Sec-Fetch-Site` suffisent avec les navigateurs actuels ; le cas restant est consigné au [modèle de menace](THREAT_MODEL.md), « Risques acceptés ». |
| Structures typées par page (au lieu de `map[string]any`) | Différé | Gros changement pour peu de gain ; à faire page par page, quand on y touche. |
