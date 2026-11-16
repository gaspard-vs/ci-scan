# Architecture

## Le déroulement

1. **Recensement.** CI scan liste les fichiers et détecte les technologies.
2. **Scan commun.** Les contrôles valables pour tout dépôt.
3. **Scan par technologie.** Les contrôles propres à chaque technologie détectée.
4. **Rapport.** Tous les résultats réunis, puis la décision : conforme ou bloqué.

## Où tourne CI scan

| Ordre | Plateforme | Statut |
| --- | --- | --- |
| 1 | GitHub | La cible. |
| 2 | GitLab | Éventuel. |
| 3 | Le git du Valais | Ensuite. |

Le moteur est le même partout. Seul le lancement change d'une plateforme à l'autre.

## Comment les outils sont lancés sur GitHub

GitHub fournit une machine avec Docker. Une seule tâche peut donc lancer autant de conteneurs qu'il faut.

1. La tâche récupère le code.
2. Elle lance le moteur de CI scan.
3. Le moteur lance chaque outil dans son conteneur, l'un après l'autre.
4. Le moteur réunit les résultats.

C'est exactement ce qui se passe sur un poste.

**À vérifier pour GitLab et le git du Valais :** lancer des conteneurs depuis une tâche y demande un droit particulier. S'il est refusé, chaque outil devient une tâche séparée. Cela ne bloque pas GitHub.

## Les dossiers

```
ci-scan/
  docs/          cette documentation
  runner/        le moteur : lance les étapes, réunit les résultats
  common/        le scan de tout dépôt
  tech/
    java/        détection + scan Java
    javascript/  détection + scan JavaScript, TypeScript, Angular
    ...          un dossier par technologie (Mendix, Python, etc.)
  policy/        seuils, types sans risque
  fixtures/      petits dépôts avec des fautes connues, pour tester CI scan
```

## Une étape

Chaque dossier contient une suite d'étapes. Une étape, c'est un outil.

Toutes les étapes suivent **le même contrat** :

- elle reçoit un dépôt ;
- elle rend ses résultats dans un format standard (SARIF).

Le moteur ne connaît aucun outil. Il lance les étapes et réunit les résultats.

## Ajouter

| Pour ajouter | Il faut |
| --- | --- |
| Un outil | Un dossier d'étape. Rien d'autre ne change. |
| Une technologie | Un dossier dans `tech/` : comment la reconnaître, et ses étapes. |
| Un outil externe (suivi, tableau de bord) | Une étape après le rapport. Le format standard est lu par la plupart des outils. |

## Les outils tournent en conteneurs

- Chaque outil est une image de conteneur, à une version figée.
- Même résultat sur un poste, dans GitHub et dans GitLab.
- Un outil ne change pas sans une modification visible et relue.

## CI scan se teste lui-même

Chaque étape a un petit dépôt avec une faute connue. L'étape doit la trouver. Un dépôt propre doit passer.
