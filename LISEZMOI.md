# Site du mariage de Louise & Adrien

## Modifier le site
1. Modifier les textes dans `src/index.html` et `src/rsvp.html`, les liens et infos pratiques dans `src/config.js`.
2. Lancer `python build.py`.
3. Ouvrir le lien « Tester en local » affiché pour vérifier.
4. Publier : `git add docs && git commit -m "Mise à jour" && git push`.

## Mot de passe
- Il est dans `motdepasse.txt` (première ligne). Majuscules et espaces autour ne comptent pas.
- Après un changement de mot de passe, relancer `python build.py` puis réimprimer le QR code (dossier `qr/`).
- Un changement de mot de passe oblige tout le monde à le ressaisir, même ceux qui étaient déjà entrés.

## Ce qui part sur GitHub
Seul `docs/` contient le site public, et tout son contenu est chiffré.
`src/`, `motdepasse.txt` et `qr/` restent sur cet ordinateur (voir `.gitignore`) : pensez à les sauvegarder (OneDrive, clé USB…).

## Le QR code
Le QR code ouvre le site sans mot de passe (le mot de passe est dans le lien, après `#cle=`).
Ne le publiez pas sur les réseaux sociaux : n'importe qui pourrait entrer.
