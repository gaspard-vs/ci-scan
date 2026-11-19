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
| Paquets douteux | Liste OSV des paquets malveillants, lue par OSV-Scanner | La liste publique de référence. |  |
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

## Les règles d'Opengrep

| Règles | Origine | Mise à jour |
| --- | --- | --- |
| Règles générales | La partie libre des règles de GitLab (MIT et LGPL). Environ 480 règles, maintenues par GitLab. | Chaque mois, CI scan signale la nouvelle version. Une personne la copie, la teste et propose le changement. Le responsable de CI scan l'accepte. |
| Nos règles | Seulement ce que GitLab ne couvre pas, pour un cas réel. | Chaque règle a son test. Une règle sans test est refusée. |

- Le responsable de CI scan accepte chaque changement. Aujourd'hui : Anna. Plus tard : le responsable de la sécurité.
- CI scan peut relever la gravité d'une règle de GitLab. Exemple : un contrôle de certificat désactivé est « moyen » chez GitLab, et bloquant chez nous.

## L'inventaire des composants (Syft)

Syft liste tous les composants du projet : la liste complète, ou SBOM.

| Lu | Exemple |
| --- | --- |
| Fichiers de verrouillage | `package-lock.json`, `yarn.lock`, `poetry.lock` |
| Fichiers de projet | `pom.xml` |
| Bibliothèques livrées en fichier | un `.jar` posé dans le dépôt |

- Le SBOM est au format standard CycloneDX : `sbom.cdx.json`, à côté du rapport.
- Il liste aussi les paquets de développement : une faille y bloque comme ailleurs.
- Sur GitHub, il reste avec le résultat du scan, 90 jours au plus.
- Il ne bloque jamais. Si Syft échoue, l'inventaire manque : le scan bloque.
- Pour Maven, la version vient souvent d'un parent. Syft passe par le même relais qu'OSV-Scanner : seulement des fichiers POM, seulement Maven Central, jamais les paquets internes. Aucun autre réseau.
- Les réglages du projet (`.syft.yaml`) sont ignorés.
- Le rapport donne le nombre de composants.

**Pourquoi :** une faille grave est publiée demain. Le SBOM dit quels projets ont le composant touché, sans relire leur code.

**Limite :** pour Maven, seules les dépendances écrites dans `pom.xml` sont listées, avec leur version. Les dépendances des dépendances manquent : plus de 10 minutes pour `bpesvc`. OSV-Scanner, lui, les vérifie.

**Plus tard :** un dépôt central des SBOM, un par projet, pour chercher une faille dans tous les projets d'un coup.

## Les vulnérabilités connues (OSV-Scanner)

OSV-Scanner compare la liste des paquets du projet avec la base publique OSV. Cette base contient aussi la liste des paquets malveillants.

| Fichiers | Comment | Réseau |
| --- | --- | --- |
| Fichiers de verrouillage (`package-lock.json`, `yarn.lock`, `poetry.lock`, etc.) | Les versions y sont toutes écrites. | Aucun. |
| `pom.xml` (Maven) | Les versions viennent souvent d'un parent ou d'une nomenclature (BOM) publiée sur Maven Central. Un relais va chercher ces fichiers POM. | Seulement par le relais, seulement des fichiers POM, seulement Maven Central. |

- La base est téléchargée avant le scan, seulement pour les écosystèmes du projet (Maven : 11 Mo, npm : 222 Mo). Chaque fichier est vérifié par son empreinte.
- Le rapport donne la date de chaque base.
- Un paquet malveillant est critique. Une faille sans score est élevée.
- Une faille d'un paquet de développement bloque comme les autres.
- Les réglages du projet (`osv-scanner.toml`, `.gitignore`) sont ignorés.
- Un fichier de verrouillage sans base connue fait échouer l'étape : le scan bloque.

**Les paquets internes (`ch.vs.*`)** ne sont jamais demandés à Maven Central. Le relais répond à leur place, sans rien envoyer. Ils sont listés dans le rapport, « pour information » : ils sont scannés dans leur propre dépôt.

**Limite :** les dépendances d'un profil Maven ne sont pas résolues. Les paquets internes d'un profil sont quand même listés.

## Le second avis (Grype)

Grype lit l'inventaire des composants (SBOM) fait par Syft, et le compare avec sa propre base de failles.

| | OSV-Scanner | Grype |
| --- | --- | --- |
| Lit | Les fichiers de verrouillage, `pom.xml` | Le SBOM de Syft |
| Bibliothèque livrée en fichier (`.jar`) | Non | Oui |
| Dépendances des dépendances Maven | Oui | Non |
| Base | OSV | Grype (Anchore) |

- Les deux outils nomment une faille de la même façon : le paquet, sa version, et la CVE si elle existe.
- Chacun donne ses résultats. Une faille trouvée par les deux apparaît deux fois.
- Critique et élevé bloquent. Une faille sans gravité est élevée.
- Grype ne lit jamais le dépôt : seulement le SBOM. Les réglages du projet (`.grype.yaml`) sont sans effet.
- Aucun réseau.

**La base :** une seule base pour tous les langages (204 Mo). Elle est téléchargée et vérifiée par son empreinte. Elle est ensuite préparée une fois par jour (environ 1 minute). Un scan prend alors quelques secondes.

**Sur GitHub :** chaque scan part d'une machine neuve. Il télécharge et prépare la base : environ 1 minute de plus.

**Si Syft échoue**, Grype n'a pas d'inventaire : il ne tourne pas, et le scan bloque.

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
