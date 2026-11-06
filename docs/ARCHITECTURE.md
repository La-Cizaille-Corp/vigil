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
internal/notify        Digests et alertes vers les webhooks et par e-mail (SMTP)
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
   vers OSV ; ceux qui n'ont qu'un CPE, ou qu'un nom, vont vers la NVD.
2. OSV : une requête `querybatch` pour tout l'inventaire, puis téléchargement des seuls avis
   nouveaux ou modifiés ; un paquet aux avis trop nombreux pour une réponse est relu en entier (A55).
   Certains paquets sont lus en entier d'emblée et comparés ici (A51, A56). NVD : requêtes par CPE
   limitées à la période de suivi, espacées selon la limite de débit, renvoyées après une panne
   passagère. Un actif qu'une source n'a pas pu vérifier est signalé et ne bloque pas les autres.
3. Enrichissement : CVE croisées avec CISA KEV et EPSS, avant les findings (voir A31). Une panne
   de ces sources est journalisée sans faire échouer la synchronisation.
4. `findings` : création si nouveau et dans la période de suivi de l'actif, réouverture si résolu
   automatiquement puis signalé à nouveau, résolution automatique si la source ne le signale plus
   (version mise à jour).
5. Alertes immédiates (A37) : les vulnérabilités ouvertes devenues urgentes sont envoyées aux
   canaux qui les demandent, une fois par niveau d'urgence.
6. `cti.Collector` récupère les flux ; les items reçoivent pays, secteurs et réglementations, et
   leurs identifiants CVE sont indexés (A40). Purge après 180 jours.

### Digest

Couvre la période depuis le digest précédent (7 jours pour le premier) : nouvelles
vulnérabilités et vulnérabilités ouvertes, chacune regroupée par éditeur (A47), hors délai,
actualités citant l'inventaire, synthèse par statut, veille menaces filtrée, veille
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
`aria-sort` et la feuille de style disent l'ordre courant. Le tri se fait en Go sur la liste chargée :
elle n'est pas paginée, et un tri SQL ne saurait pas comparer des versions (A53), ni l'ordre des
statuts et des criticités. Les valeurs absentes restent en fin de liste dans les deux sens. CVSS et EPSS
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
exploités (KEV) sont stockés. La date de modification ne permet pas de les écarter plus tôt : presque
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

**A60. Un seul classement, en quatre niveaux.** Les raccourcis (non traitées, prioritaires, critiques
et hautes, hors délai) se recouvraient et ne disaient pas où commencer, surtout sur les volumes d'un noyau.
Quatre niveaux exclusifs les remplacent, calculés pour tout produit : Urgentes, À planifier, À surveiller,
Écartées, avec leur nombre. Ce sont les classes des alertes (A37) : une alerte et un niveau disent la même
chose. Le CVSS seul ne trie pas : sur le noyau Debian 6.12.60-1, 90 % des CVE notées sont à 7 ou plus, plus de la
moitié ne sont pas notées, et les 4 exploitées ne sont pas à 9. *Conséquence* : le niveau À planifier reste
gros sur un vieux noyau ; c'est la mise à jour qui le réduit, pas le classement. Les délais de traitement et
le filtre « Hors délai » restent, dans les filtres.

**A61. Écarter par un texte, pas par une notion de composant.** Une version ne dit pas si un composant est
présent : sur un serveur sans ces matériels, `drm`, `wifi` ou `bluetooth` pèsent au moins un quart des CVE du
noyau, qui sont de vrais faux positifs. Une première idée les regroupait par composant, en analysant le début
des descriptions : c'était propre au noyau, et approximatif. Le mécanisme retenu vaut pour tout produit : un texte
cherché dans l'identifiant et le résumé (ce que l'analyste voit), sur un actif. On voit la liste avant d'écarter.
Elles passent en « Non affecté – code vulnérable absent », avec la règle dans leur historique, donc dans le
VEX ; la règle s'applique aux suivantes, avant les alertes. Trois garde-fous : une vulnérabilité exploitée ou
probable reste visible et revient si elle le devient, une décision prise par quelqu'un n'est jamais changée, et
supprimer la règle défait ce qu'elle a fait.

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

**A58. Fréquence de collecte des flux, réglable dans l'interface.** Les actualités suivaient
`-sync-interval`, avec les vulnérabilités : 4 collectes par jour par défaut, et changer l'une changeait
l'autre, en redémarrant le service. La fréquence devient un réglage (à la demande, 1 à 24 fois par
jour), relu chaque minute, et que chaque responsable peut changer sans accès au serveur. `-sync-interval 0`
coupe toujours les deux : c'est le moyen de ne rien appeler seul. Le flux « vulnérabilités » de The
Hacker News rejoint les flux par défaut ; ses articles figurant aussi dans le flux général du site,
un article déjà présent sous la même adresse n'est pas repris par un autre flux.

**A59. Teams : carte adaptative, et raison des refus.** Les connecteurs de Microsoft ont cédé la place
aux workflows, qui attendent une carte adaptative plutôt que le champ `text` commun à Slack et
Mattermost : Teams a donc son format. Un 401 systématique vient de leur côté : le workflow n'accepte
pas les appels anonymes (« Qui peut déclencher le flux »), or un webhook n'a que la signature de son URL ;
ou son adresse n'est plus valide (`logic.azure.com`, retirée fin 2025). Microsoft répond 401 sans
explication selon les cas : l'état du canal donne donc le code et le message de la réponse quand il y en
a, ce qu'il faut régler pour Teams, et le bouton « Envoyer un test » évite d'attendre une alerte pour
vérifier. Rien de ce qui cite une adresse n'est repris d'une réponse : elle pourrait contenir le secret.

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
(interface). Webhooks au format le plus simple commun à Slack et Mattermost (A59 pour Teams ; champ
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

### Notifications, délais et échanges (0.3)

Ces décisions viennent d'un comparatif avec OpenCVE, Dependency-Track, DefectDojo, CIRCL
Vulnerability-Lookup et Taranis AI (voir [BENCHMARK.md](BENCHMARK.md)) : elles comblent les
manques qui gênaient l'usage quotidien d'une petite équipe, sans viser la profondeur de ces outils.

**A37. Alertes immédiates par niveau d'urgence, une fois par niveau.** OpenCVE et
Dependency-Track préviennent dès qu'une vulnérabilité correspond ; Vigil n'avait que le digest.
Chaque vulnérabilité ouverte a une classe : prioritaire (KEV ou EPSS ≥ 10 %), sévère (critique ou
haute), autre. À la fin de chaque synchronisation, celles dont la classe dépasse la classe déjà
notifiée (`findings.alerted`) partent, en un message par canal, vers les canaux qui demandent ce
niveau ; une vulnérabilité qui devient exploitée est donc signalée à nouveau. Écartés : une alerte
par vulnérabilité (avalanche au premier import d'un SBOM), un moteur de règles à la
Dependency-Track (configuration lourde pour la cible). La migration marque les vulnérabilités
existantes comme déjà notifiées : pas d'avalanche après la mise à jour. Une alerte en échec n'est
pas renvoyée : l'erreur s'affiche sur le canal et le digest suivant liste la vulnérabilité.

**A38. E-mail par SMTP direct, dans les mêmes canaux que les webhooks.** Toutes les solutions
comparées notifient par e-mail ; c'est le canal universel des petites structures. `net/smtp` de la
bibliothèque standard suffit (aucune dépendance) ; le serveur est fixé par l'exploitant (options
`-smtp-*`), les destinataires par l'administrateur, comme un webhook. STARTTLS est exigé par défaut
(pas de repli en clair si le serveur ne le propose pas), `net/smtp` refuse d'envoyer un mot de
passe sans TLS sauf vers la machine locale. Messages en texte (le Markdown du digest se lit tel
quel), en-tête `Auto-Submitted` contre les réponses automatiques.

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
ligne. Les exports utilisent le point-virgule et la virgule décimale, comme Excel en français.
*Sécurité* : toute cellule commençant par `=`, `+`, `-`, `@` est préfixée d'une apostrophe
(injection de formules à l'ouverture dans un tableur), de même qu'un tel caractère placé juste
après un séparateur dans une valeur : un tableur qui découpe sur un autre séparateur que celui du
fichier y commencerait une cellule.

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
(complexité sans besoin avéré).

**A47. Digest regroupé par éditeur.** Le digest commence par un tableau éditeur × sévérité
(critiques, hautes, moyennes, basses, inconnues, total, exploitées), puis liste les vulnérabilités
de chaque éditeur de la plus grave à la moins grave ; dans une même sévérité, les exploitées (KEV)
d'abord, puis par score CVSS. La sévérité est celle de l'avis, à défaut la tranche du score CVSS
(9 et plus, 7 à 8,9, 4 à 6,9, moins de 4). L'éditeur vient du CPE (Fortinet), de l'espace de noms du
purl (org.apache.logging.log4j) ou, sans espace de noms, de l'écosystème (Paquets npm). Les
vulnérabilités ouvertes sont limitées à 25 par éditeur dans la liste, les compteurs restant
complets : un abonnement à un grand éditeur en compte des milliers. Le tableau vient en tête pour
survivre à la troncature des messages de discussion.

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
  affichés une fois après redirection (pas de nouvel envoi du formulaire au rechargement).

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
administrateurs (exigence fréquente des audits NIS2 ou ISO 27001).

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
