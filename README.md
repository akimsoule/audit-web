# audit_web.sh — Guide d'utilisation

## Prérequis
- Docker installé et démarré (`sudo systemctl start docker`)
- Accès internet depuis le conteneur (pour `apt-get`)
- **Autorisation écrite du propriétaire de la cible**

## Utilisation

```bash
chmod +x audit_web.sh
./audit_web.sh https://www.votre-cible-autorisee.com
```

## Ce que le script fait
| Module | Outil | Nature |
|--------|-------|--------|
| Fichiers sensibles exposés | `curl` (HEAD/GET, code HTTP uniquement) | Passif |
| Ports backend ouverts | `nmap -sT` ports ciblés uniquement | Passif |
| Divulgation d'infos serveur | `curl -I` + `nikto -Tuning b` | Passif |

## Ce que le script ne fait PAS (par conception)
- ❌ Brute-force d'authentification
- ❌ Injection SQL / XSS / commandes
- ❌ Fuzzing de chemins
- ❌ Téléchargement du contenu des fichiers détectés
- ❌ Connexion aux bases de données ou services détectés

## Idempotence
Peut être lancé 10 fois de suite sans effets de bord :
- Le conteneur Docker `kali_audit_web` n'est créé qu'une seule fois
- Les outils ne sont réinstallés que s'ils sont absents

## Avertissement légal
L'utilisation de cet outil sans autorisation écrite explicite du propriétaire
de la cible est **illégale** dans la plupart des juridictions.
