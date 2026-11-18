# Outils

Tous sont des logiciels libres, connus et maintenus.

## Scan commun : tout dépôt

| Contrôle | Outil | Pourquoi lui | Rapide |
| --- | --- | --- | --- |
| Détection des technologies | go-enry | Le moteur de détection de langages de GitHub. |  |
| Inventaire des composants | Syft | Produit la liste complète (SBOM) dans un format standard. |  |
| Secrets | Gitleaks | Rapide. Lit aussi tout l'historique git. | Oui |
| Secrets | TruffleHog | Vérifie si le secret trouvé est encore actif. |  |
| Vulnérabilités connues | OSV-Scanner | Base publique OSV (Google). Couvre presque tous les langages. |  |
| Vulnérabilités connues | Grype | Second avis. Lit aussi les bibliothèques livrées en fichier. |  |
| Paquets douteux | Liste OSV des paquets malveillants | La liste publique de référence. |  |
| Paquets douteux | GuardDog | Repère les paquets piégés (npm, Python). |  |
| Paquets douteux | Vérification du registre | Le paquet existe-t-il vraiment ? Est-il très récent ? |  |
| Analyse du code | Opengrep | Plus de 30 langages. Règles faciles à écrire. | Oui |
| Règles IA | Opengrep + nos règles | Voir ci-dessous. | Oui |
| Configuration | Trivy | Fichiers de déploiement et de conteneurs. |  |
| Configuration | Hadolint | Spécialiste des Dockerfile. | Oui |
| Hygiène du dépôt | Nos contrôles | Fichiers `.env`, journaux, binaires, archives, licences. | Oui |

Deux outils pour les secrets et pour les vulnérabilités : ce sont les deux risques les plus graves, et aucun outil ne trouve tout.

## Scan par technologie

| Technologie | Contrôle | Outil | Pourquoi lui | Rapide |
| --- | --- | --- | --- | --- |
| Java | Analyse du code | SpotBugs + FindSecBugs | La référence libre pour la sécurité Java. |  |
| Java | Maven | Nos contrôles | Sources de paquets non sûres, bibliothèques sans origine. | Oui |
| JavaScript | Analyse du code | ESLint + règles de sécurité | Standard du monde JavaScript. | Oui |
| JavaScript | npm | lockfile-lint + nos contrôles | Paquets hors registre officiel, scripts d'installation. | Oui |

## Les contrôles rapides

Les contrôles marqués « Rapide » prennent quelques secondes. Le projet peut les lancer lui-même, avant un commit.

- CI scan publie **une seule entrée**, qui lance ses contrôles rapides avec ses règles.
- Le projet l'ajoute à son fichier `.pre-commit-config.yaml`, le standard pour ce qui tourne avant un commit.
- Ce fichier ne bloque rien. Une personne ou une IA lance les contrôles à la demande.
- L'IA qui écrit le code trouve alors la faute elle-même, avant CI scan.
- Si l'entrée manque, le rapport conseille de l'ajouter. Voir [Rapport](04-rapport.html).
- CI scan refait tous les contrôles dans tous les cas.

## Les risques propres au code écrit par IA

Une IA cherche à « faire marcher ». Elle peut retirer une protection pour y arriver. Nos règles cherchent :

- une vérification de certificat désactivée ;
- un contrôle d'accès retiré ;
- une authentification de test ou des données fictives livrées en production ;
- des tests désactivés ou vidés ;
- un paquet qui n'existe pas, inventé par l'IA ;
- des traces de travail laissées dans le dépôt (journaux, invites, clés).

## Outils écartés

| Outil | Motif |
| --- | --- |
| CodeQL | Licence : interdit sur du code privé sans contrat. |
| SonarQube | La version libre ne couvre pas l'analyse de sécurité avancée. |
| Semgrep (édition libre) | Des fonctions ont été retirées de la version libre. Opengrep en est la suite libre. |

## Plus tard

- Test de l'application en marche (ZAP).
- Suivi des résultats dans le temps (DefectDojo).
- Scan des images de conteneurs livrées.
