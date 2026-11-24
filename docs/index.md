# CI scan

Un scanner de sécurité unique pour tous les projets, en particulier ceux écrits, migrés ou mis à jour par une IA.

## Où en est-on

| Partie | État |
| --- | --- |
| Le moteur : une commande, un verdict | Construit |
| La détection : chaque fichier a un propriétaire | Construit |
| La porte fermée : ce qui n'est pas contrôlé bloque | Construit |
| Secrets (Gitleaks) | Construit |
| Analyse du code (Opengrep) | Construit |
| Vulnérabilités connues (OSV-Scanner) | Construit |
| Inventaire des composants (Syft) | Construit |
| Le scan obligatoire sur GitHub ([mise en place](setup.html)) | Construit, sur un dépôt d'essai |
| Les autres contrôles | À construire |
| Java, JavaScript, Shell, Docker, Python, SQL | Couverts par les contrôles communs seulement. Leurs contrôles propres : à construire. |
| Le rapport d'une page pour le responsable | À construire. D'ici là, un rapport en texte. |

## Le besoin

- Une IA produit beaucoup de code, vite. Personne ne relit tout.
- Il faut un contrôle automatique, identique pour tous les projets.
- Le projet contrôlé ne doit pas pouvoir éviter le contrôle.

## La réponse

- **Un seul outil**, CI scan, dans son propre dépôt, sur GitHub.
- **Une commande** scanne un dépôt et donne **un rapport** : conforme ou bloqué.
- **Logiciels libres uniquement.**
- **Sur GitHub d'abord.** GitLab éventuellement. Le git du Valais ensuite.
- **Extensible** : une nouvelle technologie ou un nouvel outil s'ajoute comme un dossier.

## Ce qui est contrôlé

| Question | Contrôle |
| --- | --- |
| Y a-t-il des mots de passe ou des clés dans le code ? | Secrets |
| Utilisons-nous des composants avec des failles connues ? | Vulnérabilités connues |
| Un composant est-il piégé, ou inventé par l'IA ? | Paquets douteux |
| Le code contient-il des failles ? | Analyse du code |
| L'IA a-t-elle désactivé une protection ? | Règles IA |
| Les fichiers de déploiement sont-ils sûrs ? | Configuration |
| Le dépôt contient-il ce qu'il ne devrait pas ? | Hygiène du dépôt |

## Premiers projets

Un service Java et une interface Angular. Ensuite, tous les autres.

## Les pages

1. [Garanties](01-garanties.html) : pourquoi aucun projet n'échappe au scan.
2. [Architecture](02-architecture.html) : comment c'est organisé.
3. [Outils](03-outils.html) : les outils choisis, et pourquoi.
4. [Rapport](04-rapport.html) : ce que reçoit le responsable.
5. [Décisions](05-choix.html) : ce qui est retenu, et deux choix qui restent.
