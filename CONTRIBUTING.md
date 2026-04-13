# Contribuer à MediaDock

Merci de votre intérêt pour MediaDock ! Ce guide décrit les conventions et le processus pour contribuer au projet.

## Prérequis

- **bash** (4.0+)
- **ShellCheck** — analyse statique bash
- **bats-core** — framework de tests bash

## Conventions de code

### Nommage

- **Fonctions :** `snake_case` avec préfixe module — `hardening_configure_ssh`, `radarr_get_api_key`
- **Variables locales :** `snake_case` minuscules, déclarées avec `local`
- **Variables globales/constantes :** `UPPER_SNAKE_CASE` — `MEDIADOCK_DIR`, `LOG_FILE`
- **Fichiers scripts :** `snake_case.sh`

### Bonnes pratiques bash

- Shebang `#!/usr/bin/env bash` en tête de chaque fichier
- `set -euo pipefail` dans le point d'entrée
- Variables toujours quotées : `"${VAR}"` — jamais `$VAR` nu
- `[[ ]]` pour les tests — jamais `[ ]`
- `local` pour les variables de fonction
- Pas de `eval`, pas de `ssh` direct (utiliser `ssh_exec`)

### Structure des modules

Chaque module (`lib/modules/*.sh`) suit ce pattern :

```bash
#!/usr/bin/env bash
# Module: <nom> — <description>
# Dépendances: <liste>

<module>_run() {
  # Point d'entrée du module
}
```

### Structure des services

Chaque service (`lib/services/*.sh`) expose une interface uniforme :

```bash
<service>_get_api_key()   # Récupère l'API key
<service>_wait_ready()    # Attend que le service soit prêt
<service>_configure()     # Applique la configuration
```

## Qualité

- **ShellCheck** doit passer sans warning sur tous les fichiers
- **bats-core** — les tests existants doivent passer avant toute PR
- Ajoutez des tests pour toute nouvelle fonctionnalité

## Processus de contribution

1. Forkez le repo
2. Créez une branche descriptive (`fix/vpn-killswitch`, `feat/mullvad-support`)
3. Implémentez vos changements en suivant les conventions ci-dessus
4. Vérifiez que ShellCheck et bats-core passent
5. Ouvrez une Pull Request avec une description claire du changement
6. Attendez la revue du mainteneur

## Messages CLI

- Les messages destinés à l'utilisateur sont en **français**
- Pas d'emoji dans les messages CLI
- Les erreurs sont accompagnées d'une suggestion de résolution
