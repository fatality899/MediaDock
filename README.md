# MediaDock

Déploiement automatisé d'un media server complet en une seule commande.

MediaDock installe, sécurise et configure automatiquement un écosystème complet de services Docker sur un serveur Debian — téléchargement protégé par VPN, gestion de médias via la stack *arr*, streaming, et monitoring centralisé.

## Fonctionnalités

- **Déploiement one-command** — D'un serveur Debian vierge à un media server opérationnel en moins de 15 minutes
- **Auto-configuration complète** — API keys, interconnexions inter-services, permissions, profils qualité
- **Privacy-first** — Zéro cloud, zéro télémétrie. Trafic torrent isolé derrière VPN avec kill-switch
- **Multi-VPN** — Support de 60+ fournisseurs VPN via Gluetun
- **Idempotent** — Le script vérifie l'état avant d'agir, relançable sans risque

## Prérequis

### Côté client (votre machine)

- `bash` (4.0+)
- `ssh`
- `curl`

### Côté serveur

- Debian 13 (installation fraîche)
- Accès SSH root

## Installation

```bash
git clone https://github.com/votre-user/mediadock.git
cd mediadock
```

## Usage

### Première installation

```bash
# Mode interactif — le script pose les questions
./mediadock install

# Mode non-interactif — configuration via fichier .env
cp .env.example .env
# Éditez .env avec vos valeurs
./mediadock install
```

### Commandes disponibles

```
mediadock install      Déploiement complet (interactif ou via .env)
mediadock update       Mise à jour contrôlée des services
mediadock backup       Sauvegarde des configs et bases de données
mediadock restore      Restauration depuis un backup
```

### Options globales

```
-v          Mode verbose (affiche tous les niveaux de log)
--help      Affiche l'aide
--version   Affiche la version
```

## Configuration

Copiez `.env.example` vers `.env` et renseignez vos valeurs. Voir `.env.example` pour la documentation complète des variables.

## Services déployés

| Service | Description |
|---|---|
| Gluetun | Client VPN avec kill-switch |
| qBittorrent | Client torrent (protégé par VPN) |
| Prowlarr | Gestionnaire d'indexeurs (protégé par VPN) |
| Radarr | Gestion automatisée de films |
| Sonarr | Gestion automatisée de séries TV |
| Jellyseerr | Interface de demandes de médias |
| FlareSolverr | Résolution de captchas Cloudflare |
| Recyclarr | Profils qualité TRaSH Guides |
| Homarr | Dashboard centralisé |
| Emby/Jellyfin/Plex | Media player (au choix) |

## Contribution

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les conventions et le processus de contribution.

## Licence

[MIT](LICENSE)
