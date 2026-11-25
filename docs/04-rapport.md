# Rapport

## Ce que reçoit le responsable

Une page, en français : `rapport.md`.

| Partie | Contenu | État |
| --- | --- | --- |
| La décision | Conforme ou bloqué. | Construit |
| Les technologies | Couvertes, couvertes par les contrôles communs seulement, non couvertes. | Construit |
| Les résultats | Leur nombre, par contrôle et par gravité. | Construit |
| Les points bloquants | Le fichier, la ligne, le contrôle, la gravité. | Construit |
| La correction attendue | Pour chaque point bloquant. | À construire |
| Signalé, pour information | Les autres résultats, même tableau. | Construit |
| Les étapes | Le nombre de résultats, la date des données, les requêtes vers l'extérieur. | Construit |
| Un conseil | Si le projet ne lance pas lui-même les contrôles rapides. | À construire |

Un tableau montre 200 lignes au plus. Le reste est compté, avec un renvoi au détail technique.

Sont joints, pour les développeurs, les agents et d'autres outils :

- le détail technique (`ci-scan.sarif`, au format standard SARIF) ;
- l'inventaire des composants (`sbom.cdx.json`, le SBOM).

Sur GitHub, ces trois fichiers restent avec le résultat du scan, 90 jours au plus.

## Où le lire

| Ordre | Où | Statut |
| --- | --- | --- |
| 1 | Sur GitHub, la page du scan montre `rapport.md`. Voir ci-dessous. | Construit. |
| – | Sur le poste : `node runner/cli.mjs <dépôt> --out <dossier>` écrit `rapport.md` dans le dossier. | Construit. |
| 2 | Sur GitLab | Éventuel. |
| 3 | Sur le git du Valais, près des projets | Ensuite. |

### Sur GitHub, depuis la demande de fusion

1. Dans le cadre des contrôles, cliquer le nom du contrôle : `ci-scan / ci-scan / scan (pull_request_target)`.
2. Le journal du scan s'ouvre. À gauche, en haut, cliquer **Summary**.
3. Descendre sous le cadre des artefacts. Le rapport commence par « CI scan : » et le nom du dépôt.

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
