# Décisions

## Ce qui est retenu

| Sujet | Décision | Motif |
| --- | --- | --- |
| Nom et portée | CI scan, universel. Testé d'abord sur un premier projet. | Un seul contrôle pour tous les projets. |
| Organisation | Un dossier `common`, un dossier par technologie. | Ajouter une technologie ne touche à rien d'autre. |
| Plateforme | GitHub d'abord. GitLab éventuellement. Le git du Valais ensuite. | Avancer sans attendre le git du Valais. |
| Moteur | Le même sur toutes les plateformes. | Changer de plateforme sans tout refaire. |
| Lancement des outils | Une seule tâche lance le moteur. Le moteur lance chaque outil dans son conteneur. | Pareil sur un poste et sur GitHub. La plateforme ne connaît aucun outil. |
| Contrôles rapides | CI scan publie une entrée pour `.pre-commit-config.yaml`. Si le projet ne l'a pas, le rapport le conseille. Un conseil ne bloque pas. | Un standard, souple, avec les mêmes règles que CI scan. L'IA corrige sa faute avant CI scan. |
| Projet existant | Mêmes règles pour le code ancien et le nouveau, dès le premier scan. Aucun délai. | Une IA corrige vite le code ancien. Un administrateur peut passer outre un blocage. |
| Technologies | Détectées par CI scan, jamais déclarées par le projet. | Rien à oublier, rien à contourner. |
| Technologie inconnue | Le scan bloque. | Aucun code sans contrôle. |
| Seuil de blocage | Critique et élevé. Le reste est signalé. | Bloque l'essentiel, sans noyer les équipes. |
| Quand scanner | À chaque modification, et chaque nuit. | Une faille publiée demain est vue sans attendre un changement. |
| Outils | Logiciels libres, en conteneurs, à version figée. | Même résultat partout. Aucun changement invisible. |
| Double contrôle | Deux outils pour les secrets et les vulnérabilités. | Les deux risques les plus graves. Aucun outil ne trouve tout. |
| Emplacement | Un dépôt à part, sur GitHub, géré par la sécurité. | Les projets et leurs IA ne peuvent pas le modifier. |
| Règles d'analyse du code | Les règles libres de GitLab, mises à jour chaque mois. Nos règles seulement pour les manques, chacune avec son test. | Des règles écrites seules sont fragiles. GitLab les maintient pour tous ses clients. |
| Réseau des outils | Aucun outil qui lit le code n'a de réseau. Une exception encadrée : la résolution Maven (OSV-Scanner et Syft) passe par un relais qui ne laisse sortir que des demandes de fichiers POM vers Maven Central. | Un outil, même piégé ou trop bavard, ne peut rien envoyer. |
| Base des vulnérabilités | Téléchargée avant le scan, seulement pour les écosystèmes du projet. Chaque fichier est vérifié par son empreinte (MD5) donnée par OSV, même s'il vient du cache. | Un cache peut être empoisonné par un workflow du projet scanné. |
| Paquets de développement | Une faille bloque comme toute autre faille. | Un outil de développement tourne sur le poste et dans la chaîne de construction. |
| Paquets internes (`ch.vs.*`) | Jamais demandés à Maven Central. Listés dans le rapport, pour information. | Ils sont scannés dans leur propre dépôt. Leur nom ne sort pas. |
| Inventaire des composants (SBOM) | Écrit à chaque scan par Syft, au format CycloneDX, à côté du rapport. Gardé hors du projet. Ne bloque jamais. | Savoir vite quels projets touche une faille publiée plus tard. Écrire dans le projet demanderait un droit d'écriture, que CI scan n'a pas. |
| Nos programmes dans les étapes | En Python, avec sa seule bibliothèque standard. | Un langage connu à l'État. Rien à installer. |

## Ce qui est écarté

Pour lancer les outils sur GitHub :

| Idée | Motif |
| --- | --- |
| Un conteneur par pas de la tâche | La plateforme devrait connaître chaque outil. |
| Une tâche par outil | Plus rapide. Mais chaque tâche récupère le code à nouveau, et les résultats doivent être transmis entre tâches. |
| Les conteneurs de service de GitHub | Prévus pour une base de données à côté, pas pour des outils de scan. |

Pour les règles d'analyse du code :

| Idée | Motif |
| --- | --- |
| Les règles d'Opengrep | Archivées, plus maintenues. |
| Les règles de Semgrep | Pas un logiciel libre. |
| Les autres règles de GitLab | Une partie demande un abonnement payant. Une autre interdit la revente : pas un logiciel libre. |
| Écrire toutes nos règles | Fragile. Trop de travail pour une seule équipe. |

Pour les vulnérabilités connues :

| Idée | Motif |
| --- | --- |
| Donner le réseau à OSV-Scanner | Il enverrait la liste de nos paquets à Google, et les noms internes à Maven Central. |
| Lire seulement les versions écrites dans `pom.xml` | Un projet Quarkus ou Spring n'écrit presque aucune version : `bpesvc` n'était vérifié que pour 9 paquets sur 30, sans les dépendances des dépendances. |
| Écrire notre propre résolveur Maven | Les règles de Maven sont nombreuses. Une petite erreur donne une liste fausse qui a l'air juste. |
| Le cache GitHub de CI scan | GitHub ne le permet pas : le scan tourne au nom du projet scanné. |
| Les paquets de développement un niveau plus bas | Refusé : ils tournent aussi, sur le poste et dans la construction. |

## À vérifier

| Sujet | Question | Si la réponse est non |
| --- | --- | --- |
| GitLab et le git du Valais | Une tâche peut-elle lancer des conteneurs ? | Une tâche par outil, sur GitLab seulement. GitHub n'est pas touché. |

## Remis à plus tard

| Sujet | Quand | D'ici là |
| --- | --- | --- |
| Exceptions : qui les accepte, comment | Au premier cas réel. | Aucune exception. Un blocage se lève par une correction, ou par l'administrateur de la plateforme. |
| Les dépendances des dépendances Maven dans le SBOM : la liste qu'OSV-Scanner a déjà résolue | Avec le dépôt central des SBOM. | Le SBOM liste les dépendances écrites dans `pom.xml`. |
| Dépôt central des SBOM, un par projet (par exemple OWASP Dependency-Track) | Après les autres contrôles du scan commun. | Le SBOM de chaque scan reste avec son résultat, 90 jours au plus. |

## Ce qu'il reste à choisir

### 1. Technologies suivantes

Après Java et JavaScript : Mendix, Python, autre ? L'ordre dépend des projets à venir.

### 2. Le code du premier projet, pour le scan sur GitHub

Le premier projet est sur le git du Valais. CI scan, sur GitHub, doit pouvoir lire ce code.

| Option | Effet |
| --- | --- |
| **Une copie privée du projet sur GitHub** | Simple. Du code du canton sort du git du Valais : il faut une autorisation. |
| GitHub lit le git du Valais | Pas de copie. Il faut ouvrir un accès depuis l'extérieur. |
| D'abord un autre projet, déjà sur GitHub | Aucune autorisation. Le premier projet attend. |

Recommandé : la première, si le canton l'autorise.
