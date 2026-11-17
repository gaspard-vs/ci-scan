# Mise en place sur un dépôt

Le but : aucun code n'arrive sur `main` sans une demande de fusion (pull request) que CI scan a déclarée conforme.

Exemple : le dépôt `gaspard-vs/ci-scan-test`.

## Le principe

| Élément | Où | Rôle |
| --- | --- | --- |
| Le scan | `ci-scan` | Contrôle le code. Rend conforme ou bloqué. |
| L'appel | `ci-scan-test`, un petit fichier | Lance le scan à chaque demande de fusion. |
| La règle | `ci-scan-test`, réglages GitHub | Refuse toute arrivée sur `main` sans scan conforme. |

Le scan lit le code, sans jamais l'exécuter ni le modifier. L'outil tourne dans un conteneur qui ne peut écrire nulle part et qui n'a pas de réseau.

L'appel utilise toujours la version du fichier qui est sur `main`. Une demande de fusion ne peut donc pas modifier son propre contrôle.

## Avant de commencer

| Point | État |
| --- | --- |
| `ci-scan` et `ci-scan-test` sont sur GitHub, même compte | Fait |
| `ci-scan` lance une image d'outil sur GitHub | Fait (test `image-test`) |
| `ci-scan` offre un scan que d'autres dépôts peuvent appeler (`scan.yml`) | **À construire** |
| Le compte permet les règles sur un dépôt privé | **À vérifier** (voir « Limites ») |

## 1. Ouvrir CI scan aux autres dépôts

Dans `ci-scan` : **Settings › Actions › General › Access**.

Choisir : **Accessible from repositories owned by the user 'gaspard-vs'**.

## 2. Ajouter l'appel dans le dépôt

Dans `ci-scan-test`, créer le fichier `.github/workflows/ci-scan.yml` :

```yaml
name: ci-scan

on:
  pull_request_target:
    branches: [main]

permissions:
  contents: read

jobs:
  ci-scan:
    uses: gaspard-vs/ci-scan/.github/workflows/scan.yml@main
```

Ce fichier arrive sur `main` par un envoi direct. C'est le dernier : l'étape 4 les interdit.

## 3. Lancer le scan une première fois

Ouvrir une demande de fusion, avec une modification quelconque.

Le scan tourne. GitHub connaît maintenant le nom du contrôle : `ci-scan / scan`. Sans ce premier passage, l'étape 4 ne le propose pas.

## 4. Créer la règle sur `main`

Dans `ci-scan-test` : **Settings › Rules › Rulesets › New ruleset › New branch ruleset**.

| Réglage | Valeur |
| --- | --- |
| Ruleset name | `main passe par CI scan` |
| Enforcement status | **Active** |
| Bypass list | Vide |
| Target branches | **Include default branch** |

Cocher ces règles :

| Règle | Détail | Effet |
| --- | --- | --- |
| Restrict deletions | | `main` ne peut pas être supprimée. |
| Block force pushes | | L'historique de `main` ne peut pas être réécrit. |
| Require a pull request before merging | Approbations : 0 | Plus aucun envoi direct sur `main`. |
| Require status checks to pass | Ajouter `ci-scan / scan`, source **GitHub Actions** | Fusion refusée tant que le scan n'est pas conforme. |
| | Cocher **Require branches to be up to date before merging** | Le scan porte sur le code tel qu'il sera sur `main`. |

Enregistrer avec **Create**.

## 5. Vérifier

| Essai | Résultat attendu |
| --- | --- |
| Envoi direct sur `main` | Refusé par GitHub. |
| Demande de fusion avec un faux secret | Scan bloqué. Bouton de fusion inactif. |
| Demande de fusion propre | Scan conforme. Fusion possible. |
| Demande de fusion qui supprime l'appel | Le scan tourne quand même, avec la version de `main`. |

## Limites

| Limite | Conséquence | Réponse |
| --- | --- | --- |
| Sur un compte personnel gratuit, GitHub peut ne pas appliquer les règles d'un dépôt privé. | La règle existe, mais elle ne bloque rien. | Faire l'essai « envoi direct » de l'étape 5. S'il passe : compte GitHub Pro, ou dépôt public. |
| L'administrateur du dépôt peut désactiver la règle. | Il peut passer outre un blocage. | Voulu : c'est la seule voie hors correction. |
| Une demande de fusion peut modifier le fichier d'appel. Elle est scannée, puis le fichier modifié arrive sur `main`. | Les demandes suivantes peuvent échapper au scan. | Relire toute modification de `.github/`. Voir ci-dessous. |

**Pour fermer la dernière limite :** placer les dépôts dans une organisation GitHub. L'organisation impose alors le scan elle-même, et le fichier d'appel dans le dépôt disparaît. Le plan GitHub nécessaire est à vérifier.
