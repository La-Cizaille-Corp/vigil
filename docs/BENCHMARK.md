# Comparatif avec les solutions du marché

Ce comparatif a guidé le contenu de la version 0.3. Il confronte Vigil aux outils libres retenus
lors de la conception (voir [ARCHITECTURE.md](ARCHITECTURE.md), § 1) : ce qu'ils font que Vigil ne
faisait pas, ce qui a été repris, et ce qui reste volontairement hors périmètre.

État au 28 octobre 2026, d'après la documentation publique de chaque projet. Ces outils évoluent
vite : vérifiez une fonction précise avant de fonder un choix sur ce tableau.

## Les outils comparés

| Outil | Nature | Licence | Exploitation |
|---|---|---|---|
| **Vigil** | Inventaire, suivi des vulnérabilités, veille CTI et réglementaire, digest | Apache-2.0 | Un binaire (environ 20 Mo), une base SQLite, quelques dizaines de Mo de mémoire |
| [OpenCVE](https://www.opencve.io/) v2 | Abonnements à des éditeurs et produits, alertes et rapports CVE | BSL (auto-hébergé) ou service en ligne | PostgreSQL, Redis, ordonnanceur ; import initial de toute la base CVE |
| [OWASP Dependency-Track](https://dependencytrack.org/) | Analyse continue de SBOM, politiques, VEX | Apache-2.0 | Java, base de données, plusieurs Go de mémoire |
| [DefectDojo](https://www.defectdojo.org/) | Gestion des vulnérabilités issues de scanners, délais, acceptation de risque | BSD-3-Clause (version Pro payante) | Django, PostgreSQL, Redis, workers Celery |
| [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/) | Agrégation de sources de vulnérabilités, observations (« sightings »), listes de surveillance | AGPL-3.0 | Python, base clé-valeur, PostgreSQL ; instance publique |
| [Taranis AI](https://taranis.ai/) | Veille OSINT : collecte, tri assisté, rédaction de rapports | EUPL-1.2 | Plusieurs services ; 16 Go de mémoire avec le traitement automatique de la langue |

## Fonctions

« Oui » : fonction native. « Partiel » : couverte autrement ou en partie. « Non » : absente ou hors
du périmètre de l'outil. « ? » : non vérifié dans la documentation publique. Les ajouts de la 0.3
sont en gras.

| Fonction | Vigil 0.2 | Vigil 0.3 | OpenCVE | Dependency-Track | DefectDojo | Vuln.-Lookup | Taranis AI |
|---|---|---|---|---|---|---|---|
| Inventaire saisi à la main (produits sans SBOM) | Oui | Oui | Oui (éditeur, produit) | Partiel | Non | Oui (liste de surveillance) | Non |
| Aide pour identifier un produit (recherche CPE) | Non | **Oui** | Oui | ? | Non | Oui | Non |
| Suivre tous les produits d'un éditeur | Non | **Oui** | Oui | Non | Non | Oui | Non |
| Étiquettes libres sur l'inventaire | Non | **Oui** | ? | Oui | Oui | Non | Non |
| Import d'inventaire par tableur | Non | **Oui (CSV)** | Non | Non | Partiel | Non | Non |
| Import SBOM | Oui (CycloneDX, SPDX) | Oui | Non | Oui (CycloneDX) | Oui | Non | Non |
| Correspondance par version précise | Oui (OSV, NVD) | Oui | Non | Oui | Via les scanners | Partiel | Non |
| Exploitation avérée et probabilité (KEV, EPSS) | Oui | Oui | Oui | Oui | Oui | Oui | Non |
| Statuts de triage (VEX) et historique | Oui | Oui | Partiel | Oui | Oui | Non | Non |
| Triage par lot | Non | **Oui** | ? | ? | Oui | Non | Non |
| Échéances de traitement (SLA) | Non | **Oui** | Non | Non | Oui | Non | Non |
| Alertes immédiates | Non (digest seul) | **Oui** | Oui | Oui | Oui | Oui | Non |
| Notification par e-mail | Non | **Oui** | Oui | Oui | Oui | Oui | ? |
| Webhooks, Slack, Teams, Mattermost | Oui | Oui | Oui | Oui | Oui | ? | ? |
| Rapport périodique (digest) | Oui | Oui | Oui (quotidien) | Oui (résumés planifiés) | Oui | ? | Oui (rapports rédigés) |
| Veille d'actualité filtrée par pays et secteur | Oui | Oui | Non | Non | Non | Partiel (observations) | Oui |
| Actualités reliées aux vulnérabilités de l'inventaire | Non | **Oui** | Non | Non | Non | Partiel (observations par CVE) | ? |
| Veille réglementaire (NIS2, CRA, DORA…) | Oui | Oui | Non | Non | Non | Non | Partiel |
| Exports pour tableur | VEX seulement | **CSV + VEX** | API | API, VEX | Oui | API | Non |
| Authentification unique (OIDC, SAML) | Non | Non | ? | Oui | Oui | ? | ? |
| API complète en lecture et écriture | Non (SBOM seulement) | Non | Oui | Oui | Oui | Oui | Oui |
| Tickets (Jira…) | Non | Non (webhook JSON) | Non | Oui | Oui | Non | Non |

## Ce que la 0.3 reprend, et pourquoi

| Manque constaté | Référence | Réponse dans la 0.3 |
|---|---|---|
| Une vulnérabilité exploitée n'était connue qu'au digest suivant, jusqu'à 24 h plus tard | OpenCVE, Dependency-Track, Vulnerability-Lookup | Alertes immédiates à la fin de chaque synchronisation, par niveau d'urgence, une fois par niveau (A37) |
| Pas d'e-mail, canal universel des petites structures | Tous | Canal e-mail SMTP, STARTTLS exigé par défaut (A38) |
| Pas d'échéance : impossible de dire ce qui est en retard | DefectDojo, politiques NIS2 | Délais par sévérité, filtre et indicateur « hors délai », section du digest (A39) |
| Veille et inventaire côte à côte mais pas reliés | Vulnerability-Lookup (observations), Taranis AI | Actualités qui citent une CVE ouverte de l'inventaire : badge, filtre, fiche, digest (A40) |
| Inventaire tenu dans un tableur, ressaisie pénible | DefectDojo (imports), usage de la cible | Import et export CSV, compatibles Excel en français (A41) |
| Écrire un CPE à la main | OpenCVE, Vulnerability-Lookup (recherche de produit) | Recherche dans le dictionnaire CPE de la NVD, formulaire prérempli (A42) |
| Triage ligne par ligne après un import SBOM | DefectDojo | Triage par lot, historique conservé pour chaque vulnérabilité (A43) |
| Mise à jour sans filet | Pratique d'exploitation | Copie avant migration, refus d'une base plus récente, tests sur de vraies bases de chaque version (A36) |
| Flux et webhooks inaccessibles derrière un proxy obligatoire | Tous | `HTTPS_PROXY` pris en charge, contrôle anti-SSRF conservé (A44) |

## Ce qui reste hors du périmètre

Vigil vise les petites équipes qui veulent un outil qui tourne seul, sans infrastructure. Les
manques restants du tableau sont des choix, consignés dans [ARCHITECTURE.md](ARCHITECTURE.md), § 5 :

- **Authentification unique, API complète, tickets** : utiles à une organisation plus grande,
  déjà bien servie par Dependency-Track ou DefectDojo. Le webhook JSON permet un branchement
  simple ; une API de lecture viendra si elle est demandée.
- **Plateforme de renseignement sur la menace** (IOC, STIX, partage) : domaine d'OpenCTI et de MISP.
- **Analyse de code ou d'images** : Vigil consomme les SBOM produits par syft, Trivy ou cdxgen
  plutôt que de les concurrencer.
- **Copie locale de la NVD ou du dictionnaire CPE** : plusieurs Go à importer et mettre à jour,
  contraire à la légèreté recherchée.

## Positionnement

Parmi ces outils, Vigil est le seul à réunir inventaire, suivi du traitement, veille d'actualité,
veille réglementaire et digest dans un seul binaire sans infrastructure. La 0.3 comble les manques
qui gênaient l'usage quotidien (alertes, e-mail, échéances, tableur) et relie l'actualité aux
vulnérabilités ouvertes de l'inventaire, ce que les outils comparés ne proposent pas sous cette
forme. En face, Dependency-Track et DefectDojo restent plus complets pour une organisation qui a
déjà une équipe AppSec, un annuaire et un outil de tickets.

## Sources

- OpenCVE : [concepts (projets, abonnements, notifications, rapports)](https://docs.opencve.io/concepts/core/),
  [annonce de la v2](https://blog.opencve.io/posts/opencve-v2-is-coming-soon/), [API v2](https://blog.opencve.io/posts/introducing-api-v2/)
- Dependency-Track : [notifications](https://docs.dependencytrack.org/integrations/notifications/),
  [notes de version 4.12](https://docs.dependencytrack.org/2024/10/01/v4.12.0)
- DefectDojo : [délais (SLA)](https://docs.defectdojo.com/en/working_with_findings/sla_configuration),
  [acceptation de risque](https://docs.defectdojo.com/triage_findings/findings_workflows/os__risk_acceptance/)
- CIRCL Vulnerability-Lookup : [documentation](https://vulnerability.circl.lu/documentation)
- Taranis AI : [site du projet](https://taranis.ai/)
