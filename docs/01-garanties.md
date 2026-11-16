# Garanties

Aucun projet n'échappe au scan. Aucune technologie non plus.

## Le principe

**Le scanner décide. Le projet n'a pas de voix.**

## Deux idées écartées

| Idée | Défaut |
| --- | --- |
| Le projet déclare ses technologies (étiquettes) | Une étiquette oubliée, et le code n'est pas scanné. |
| Une liste fixe de technologies | Un nouveau langage arrive, et personne ne le scanne. |

## Les six garanties

1. **CI scan détecte les technologies lui-même.** Il reconnaît Java, JavaScript, etc. par les fichiers présents. Le projet commence à utiliser Java : Java est scanné.
2. **Chaque fichier a un propriétaire.** Soit une technologie connue, soit un type sans risque (texte, image). Cette liste appartient à CI scan.
3. **Une technologie inconnue bloque.** Un projet ajoute du Python et CI scan ne connaît pas Python : le scan échoue avec « technologie non couverte ». Quelqu'un ajoute alors Python à CI scan.
4. **CI scan ne lit aucun réglage dans le projet.** Le projet ne peut pas s'accorder une exception.
5. **Les commentaires qui font taire un outil sont sans effet.** Ils sont signalés dans le rapport.
6. **CI scan va chercher le code.** Il lit la liste des dépôts et les scanne, depuis GitHub d'abord. Le projet ne peut pas retirer le scan de sa propre chaîne.

## En plus

- Une archive ou un binaire d'origine inconnue est signalé : on ne cache pas du code dans un zip.
- Une IA qui travaille dans un projet n'a aucun accès en écriture à CI scan.
- CI scan lit un seul fichier du projet, et seulement pour donner un conseil : la liste de ce que le projet lance avant un commit. Cela ne change ni ce qui est scanné, ni la décision.
