# Rapport

## Ce que reçoit le responsable

Une page, en français :

- **La décision** : conforme ou bloqué.
- **Les technologies détectées**, et celles non couvertes.
- **Le nombre de résultats** par gravité et par contrôle.
- **Les points bloquants**, chacun avec le fichier et la correction attendue.
- **Un conseil**, si le projet ne lance pas lui-même les contrôles rapides.

Sont joints, pour les développeurs et pour d'autres outils :

- le détail technique (`ci-scan.sarif`) ;
- l'inventaire des composants (`sbom.cdx.json`, le SBOM).

Sur GitHub, ces deux fichiers restent avec le résultat du scan, 90 jours au plus.

## Où le lire

| Ordre | Où | Statut |
| --- | --- | --- |
| 1 | Sur GitHub, avec le résultat de chaque scan | La cible. |
| 2 | Sur GitLab | Éventuel. |
| 3 | Sur le git du Valais, près des projets | Ensuite. |

## La décision

| Situation | Décision |
| --- | --- |
| Un secret | **Bloqué** |
| Une faille critique ou élevée | **Bloqué** |
| Un paquet malveillant ou inexistant | **Bloqué** |
| Une technologie non couverte | **Bloqué** |
| Une étape qui n'a pas pu tourner | **Bloqué** |
| Une faille moyenne ou faible | Signalé |

Le code ancien et le code nouveau suivent les mêmes règles, dès le premier scan. Aucun délai pour l'ancien.

Un administrateur de la plateforme peut passer outre un blocage. Le rapport reste « bloqué ».

## Les conseils

Un conseil n'est pas un résultat. **Il ne change jamais la décision.**

CI scan regarde un seul fichier du projet, `.pre-commit-config.yaml` : la liste de ce que le projet lance avant un commit.

| Situation | Dans le rapport |
| --- | --- |
| Le fichier contient l'entrée de CI scan | Rien |
| Le fichier existe, sans l'entrée de CI scan | Conseil : l'ajouter |
| Le projet n'a pas ce fichier | Conseil : le créer, avec l'entrée |

Le conseil rappelle aussi d'écrire une phrase dans `AGENTS.md`, les consignes de l'IA : lancer ces contrôles et les tests avant un commit. CI scan ne lit pas `AGENTS.md`.

## Les exceptions

Aucune exception n'existe aujourd'hui. La règle sera fixée au premier cas réel.

D'ici là, un blocage se lève de deux façons : corriger, ou l'administrateur de la plateforme passe outre.
