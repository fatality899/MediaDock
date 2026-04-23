#!/usr/bin/env bash
# Module: hardening - Durcissement SSH (cle only) + fail2ban (jail sshd) + UFW (firewall) + unattended-upgrades (security-only)
# Dependances: logging.sh, errors.sh, ssh.sh, utils.sh
#
# Point d'entree : hardening_run (appele par install_run via _install_run_step).
#
# Helpers publics :
#   hardening_configure_ssh
#     - Desactive PasswordAuthentication, KbdInteractiveAuthentication et
#       passe PermitRootLogin en prohibit-password via un drop-in dedie
#       /etc/ssh/sshd_config.d/50-mediadock-hardening.conf.
#     - Idempotent : source de verite = config effective `sshd -T`
#       (respecte un admin qui aurait pose les memes directives ailleurs).
#     - Valide avec `sshd -t` AVANT `systemctl reload ssh` ; rollback
#       (suppression du drop-in) + `die 1` en cas d'echec de validation,
#       afin de ne jamais recharger sshd avec une config invalide.
#
#   hardening_configure_fail2ban
#     - Installe le paquet fail2ban via apt (apt-get update puis install -y
#       avec -o Dpkg::Options::=--force-conf{def,old} pour un run totalement
#       non-interactif).
#     - Ecrit un drop-in /etc/fail2ban/jail.d/50-mediadock.local :
#         [DEFAULT] backend=systemd, ignoreip=loopback + LAN RFC1918
#         [sshd]    maxretry=5, findtime=10m, bantime=-1 (ban permanent)
#       Valeurs maxretry/findtime/bantime posees dans [sshd] (surcharge
#       ciblee, isolee d'autres drop-ins qui poseraient leur propre
#       [DEFAULT]).
#     - Valide la config avec `fail2ban-client -t` AVANT `reload` (symetrique
#       a `sshd -t` de la 2.2). Echec de -t : die 1 avec chemin du drop-in
#       dans le message (drop-in garde sur place cf. §5).
#     - Active le service (systemctl enable --now fail2ban) puis applique le
#       diff via `fail2ban-client reload` (preserve les bans actifs).
#     - Idempotent : source de verite = etat EFFECTIF du serveur (paquet
#       installe, service actif+enable, jail sshd active, valeurs effectives
#       conformes via `fail2ban-client get`). Respecte un admin qui aurait
#       configure une jail equivalente ailleurs (/etc/fail2ban/jail.local).
#     - Pas de rollback sur echec de reload/test (divergence volontaire vs
#       SSH) : fail2ban ne touche pas a sshd, garder le drop-in en place
#       aide au diagnostic (journalctl -u fail2ban). Cf. story 2.3 §5.
#
#   hardening_configure_ufw
#     - Installe le paquet ufw via apt (apt-get update puis install -y avec
#       -o Dpkg::Options::=--force-conf{def,old} pour un run non-interactif,
#       coherent 2.3).
#     - Pose les politiques par defaut : default deny incoming, default
#       allow outgoing, default deny routed (defense en profondeur pour
#       les futurs containers Docker de la 2.8).
#     - INVARIANT CRITIQUE : `ufw allow 22/tcp` EST pose AVANT
#       `ufw --force enable` pour ne jamais couper la session SSH courante
#       (y compris ControlMaster). Le test unitaire `SSH_EXEC_UFW_ALLOW_SSH_RC`
#       assertionne explicitement l'absence de `ufw --force enable` en cas
#       d'echec de l'allow SSH - c'est l'anti-lockout le plus important de
#       cette story.
#     - Ajoute les regles services MediaDock restreintes au LAN RFC1918
#       (10/8, 172.16/12, 192.168/16) via `ufw allow from <CIDR> to any
#       port <PORT> proto tcp` pour chaque combinaison (3 CIDRs x 10 ports
#       = 30 regles). Genere cote client avec boucle bash, envoye en un
#       seul ssh_exec avec `set -e` cote remote pour arreter la sequence
#       a la premiere regle en echec.
#     - Active UFW en non-interactif (`ufw --force enable` : sans --force,
#       ufw prompte 'Command may disrupt existing ssh connections...' et
#       bloque sur stdin ferme) puis persiste au boot (`systemctl enable
#       ufw`).
#     - Pas de drop-in MediaDock : UFW n'a pas de repertoire *.d/*.rules
#       officiel (tout passe par CLI ufw qui est naturellement idempotent).
#       Source de verite = etat EFFECTIF via `ufw status verbose` + `dpkg`
#       + `systemctl` (pas un fichier). Respecte un admin qui aurait pose
#       des regles equivalentes via ses propres `ufw allow`.
#     - Pas de rollback destructif sur echec (coherent 2.3 §5) : aucune
#       etape pre-enable (1-4) ne modifie le filtrage actif, donc pas de
#       risque de lockout avant `ufw --force enable`. Apres enable, SSH
#       est deja autorise. UFW garde son etat intermediaire pour aider au
#       diagnostic via `ufw status verbose`.
#
#   hardening_configure_auto_updates
#     - Installe le paquet unattended-upgrades via apt (apt-get update
#       sans -qq puis install -y avec -o Dpkg::Options::=--force-conf{def,
#       old} pour un run totalement non-interactif, coherent 2.3/2.4).
#     - Ecrit un drop-in /etc/apt/apt.conf.d/52mediadock-unattended-upgrades
#       qui override les defauts du paquet (/etc/apt/apt.conf.d/50unattended-
#       upgrades) en chargement alphabetique apt.conf.d : prefixe 52 > 50
#       garantit que nos valeurs gagnent. Scope STRICTEMENT Debian-Security
#       (2 origines : codename + codename-security, toutes deux avec
#       label=Debian-Security). Active le scheduling quotidien
#       (APT::Periodic::Update-Package-Lists=1, Unattended-Upgrade=1) et
#       desactive explicitement l'autoremove kernel/deps durant un run
#       unattended (defense en profondeur contre un update security qui
#       tirerait un autoremove casseur de deps Docker/media).
#     - Valide la config avec `unattended-upgrade --dry-run --debug` AVANT
#       l'activation des timers (symetrique `sshd -t` 2.2 / `fail2ban-client
#       -t` 2.3). Echec de --dry-run : die 1 avec chemin du drop-in dans
#       le message (drop-in garde sur place cf. §5).
#     - Active les timers systemd apt-daily.timer et apt-daily-upgrade.timer
#       en UN SEUL `systemctl enable --now` (atomique + idempotent). Les
#       deux timers sont installes par le paquet `apt` lui-meme, pas par
#       `unattended-upgrades`, donc toujours presents sur Debian 13 standard.
#     - Idempotent : source de verite = etat EFFECTIF du serveur (paquet
#       installe + 2 timers actifs+enable + 3 valeurs apt-config dump
#       conformes dont label=Debian-Security present dans Origins-Pattern),
#       PAS la presence du drop-in MediaDock. Respecte un admin qui aurait
#       configure l'equivalent ailleurs (ex: /etc/apt/apt.conf.d/20auto-
#       upgrades via debconf, ou un autre drop-in admin).
#     - Pas de rollback destructif sur echec (coherent 2.3 §5 / 2.4 §5) :
#       le drop-in garde son etat intermediaire pour aider au diagnostic
#       (cat /etc/apt/apt.conf.d/52mediadock-unattended-upgrades + journalctl
#       -u unattended-upgrades). Aucune manipulation de sshd, fail2ban,
#       UFW : 0 risque de lockout/coupure SSH par cette story.
#     - Pas d'Automatic-Reboot (defaut paquet = false, non override) :
#       une seedbox qui reboote au milieu d'un download torrent = download
#       corrompu. L'admin qui veut activer peut poser un drop-in
#       /etc/apt/apt.conf.d/53admin-reboot-window.conf dedie.
#
# Helpers prives :
#   _hardening_check_ssh_hardened, _hardening_write_ssh_drop_in,
#   _hardening_check_fail2ban_active, _hardening_install_and_configure_fail2ban,
#   _hardening_check_ufw_active, _hardening_install_and_configure_ufw,
#   _hardening_check_unattended_active, _hardening_install_and_configure_unattended.
#
# Story 2.2 : voir _bmad-output/implementation-artifacts/2-2-hardening-*.md.
# Story 2.3 : voir _bmad-output/implementation-artifacts/2-3-protection-*.md.
# Story 2.4 : voir _bmad-output/implementation-artifacts/2-4-firewall-*.md.
# Story 2.5 : voir _bmad-output/implementation-artifacts/2-5-mises-*.md.

# Variables privees au module. Pas de `readonly` : casserait un second
# sourcing dans le meme process (cf. deferred-work.md, defer 2-1).
_HARDENING_SSHD_DROP_IN="/etc/ssh/sshd_config.d/50-mediadock-hardening.conf"
_HARDENING_F2B_JAIL_DROP_IN="/etc/fail2ban/jail.d/50-mediadock.local"

# Contenu du drop-in (libelles sans accents : lisible cote serveur via SSH).
_HARDENING_SSHD_CONFIG='# MediaDock hardening - genere par mediadock install (Story 2.2)
# Ne pas editer manuellement : ce fichier est gere par MediaDock.
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no'

# Drop-in fail2ban. backend=systemd : Debian 13 utilise systemd-journald par
# defaut (pas de /var/log/auth.log), l'autodetection tomberait sur pyinotify
# et echouerait. Forcer explicitement le backend evite ce piege.
# ignoreip : loopback + plages LAN RFC1918 (10/8, 172.16/12, 192.168/16)
# pour eviter un self-lockout de l'admin depuis le reseau local - critique
# avec bantime=-1 (ban permanent jusqu'au prochain restart du service).
# maxretry/findtime/bantime poses dans [sshd] (pas [DEFAULT]) : surcharge
# ciblee, isolee d'autres drop-ins qui poseraient leur propre [DEFAULT].
# bantime=-1 : ban permanent, dissuasion maximale pour un hote Internet-facing.
_HARDENING_F2B_CONFIG='# MediaDock fail2ban - genere par mediadock install (Story 2.3)
# Ne pas editer manuellement : ce fichier est gere par MediaDock.
# backend=systemd : Debian 13 utilise systemd-journald par defaut (pas rsyslog).
[DEFAULT]
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = -1'

# Story 2.4 : UFW firewall.
# Plages LAN RFC1918 symetriques a l'ignoreip fail2ban ci-dessus : couvre
# les 3 sous-reseaux prives standards (home 192.168/16, corporate 10/8,
# rares 172.16/12). Les 30 regles (3 CIDRs x 10 ports) sont enforce a
# chaque `mediadock install` : toute suppression admin via `ufw delete`
# est ré-écrite par `_hardening_check_ufw_active`. Pour restreindre,
# modifier cette constante au niveau du module (story future `.env
# LAN_SUBNETS`).
_HARDENING_UFW_LAN_CIDRS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

# Ports services MediaDock exposes au LAN. Union complete (MEDIA_PLAYER
# non discrimine) : l'admin peut basculer entre Emby/Jellyfin/Plex sans
# rejouer hardening_configure_ufw. Les ports dont aucun service n'ecoute
# ne posent pas de probleme (trafic simplement non consomme).
#   7878 Radarr            | 8989 Sonarr          | 9696 Prowlarr (via Gluetun)
#   8080 qBittorrent (Glu) | 5055 Jellyseerr      | 8191 Flaresolverr
#   7575 Homarr            | 8888 Gluetun control | 8096 Emby/Jellyfin
#   32400 Plex
_HARDENING_UFW_SERVICE_PORTS=(7878 8989 9696 8080 5055 8191 7575 8888 8096 32400)

# Story 2.5 : drop-in unattended-upgrades. Numerote 52 > 50 pour override
# le /etc/apt/apt.conf.d/50unattended-upgrades du paquet upstream en
# chargement alphabetique. Un admin qui voudrait customiser peut poser
# un drop-in 53admin-*.conf - le notre ne verrouille pas la customisation.
_HARDENING_UNATTENDED_DROP_IN="/etc/apt/apt.conf.d/52mediadock-unattended-upgrades"

# Contenu du drop-in. Single quote bash AUTOUR de la constante : empeche
# l'expansion de ${distro_codename} cote client (qui serait vide/absent).
# Cette chaine est transmise TELLE QUELLE au serveur via stdin de `cat > tmp`
# - ssh_exec ne voit pas ${distro_codename} comme variable bash. Cote serveur,
# python-apt / unattended-upgrade substitue ${distro_codename} au runtime
# via /etc/os-release (Debian 13 -> trixie). Le test AC1 verifie bien que
# le littéral ${distro_codename} apparait dans le drop-in, PAS sa valeur.
#
# Les 2 lignes Origins-Pattern couvrent les deux suites security Debian :
#   codename=trixie,label=Debian-Security          (main repo label security)
#   codename=trixie-security,label=Debian-Security (suite dediee)
# Defaut 50unattended-upgrades fait aussi ces 2 lignes - on les reproduit
# pour etre explicites et autonomes.
#
# Remove-Unused-{Kernel-Packages,Dependencies} "false" : defense en profondeur
# contre un autoremove silencieux qui pourrait casser des deps Docker/media
# pendant un run unattended. Defaut paquet pour Kernel = true, on override.
# shellcheck disable=SC2016 # ${distro_codename} est intentionnellement littéral (expanse cote serveur par python-apt).
_HARDENING_UNATTENDED_CONFIG='// MediaDock unattended-upgrades - genere par mediadock install (Story 2.5)
// Ne pas editer manuellement : ce fichier est gere par MediaDock.
// Charge apres 50unattended-upgrades (ordre alphabetique apt.conf.d) donc
// override les defauts du paquet. Scope security-only strict.

// Scheduling : refresh index quotidien + run unattended quotidien.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";

// Origins strictement security - override du defaut 50unattended-upgrades.
// Note : ${distro_codename} est expanse par unattended-upgrade au runtime
// (via python-apt + /etc/os-release). Sur Debian 13 : trixie.
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};

// Defense en profondeur : aucun autoremove silencieux durant un run
// unattended. Bloque tout autoremove declenche par une update security
// qui supprimerait une dep Docker/media inopinement.
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";'

# Commande de check : la source de verite est `sshd -T` (configuration
# effective), PAS la presence du drop-in (AC3). Accepte PermitRootLogin
# `no` ou `prohibit-password` - les deux satisfont le critere "pas de
# root login par mot de passe". Retour 0 = deja conforme, 1 = a faire.
# Un seul appel a sshd -T (stocke dans $out) pour eliminer la course
# theorique entre plusieurs invocations et diviser par 3 le cout reseau.
_hardening_check_ssh_hardened() {
  # shellcheck disable=SC2016 # $out est expanse cote serveur, pas cote client.
  ssh_exec 'out=$(sshd -T 2>/dev/null) && printf "%s\n" "$out" | grep -qxE "passwordauthentication no" && printf "%s\n" "$out" | grep -qxE "permitrootlogin (prohibit-password|no)" && printf "%s\n" "$out" | grep -qxE "kbdinteractiveauthentication no"'
}

# Ecriture atomique du drop-in + validation + reload gracieux.
#   1. printf | ssh_exec "cat > tmp && chmod 644 && mv -f" : creation puis
#      rename atomique sur /etc (meme filesystem) ; chmod AVANT mv evite
#      une fenetre courte avec des permissions laxistes. Detection
#      explicite de l'echec du pipeline (ne depend pas de pipefail).
#   2. `sshd -t` valide la syntaxe complete incluant le nouveau drop-in.
#      En cas d'echec : rollback (rm -f du drop-in) AVANT tout reload,
#      puis `die 1`. Le sshd en cours d'execution n'a pas encore
#      charge le drop-in (reload non effectue) : la config EFFECTIVE
#      du sshd tourne toujours sur l'etat pre-operation, donc la
#      connexion SSH courante reste saine.
#   3. `systemctl reload ssh` (pas restart) recharge via SIGHUP sans couper
#      les connexions existantes. Echec de reload = die 1 (sinon
#      ensure_state remonterait succes sans que la nouvelle config soit
#      appliquee).
_hardening_write_ssh_drop_in() {
  local tmp_path="${_HARDENING_SSHD_DROP_IN}.tmp-$$"
  if ! printf '%s\n' "${_HARDENING_SSHD_CONFIG}" \
      | ssh_exec "cat > ${tmp_path} && chmod 644 ${tmp_path} && mv -f ${tmp_path} ${_HARDENING_SSHD_DROP_IN}"; then
    ssh_exec "rm -f ${tmp_path}" \
      || log_warn "Nettoyage du tmp drop-in echoue sur ${SERVER_IP:-serveur}"
    die 1 "Ecriture du drop-in hardening SSH echouee" \
      "Verifiez les permissions ou la connectivite SSH vers ${SERVER_IP:-serveur}"
  fi
  if ! ssh_exec "sshd -t"; then
    ssh_exec "rm -f ${_HARDENING_SSHD_DROP_IN}" \
      || log_warn "Rollback rm echoue : drop-in potentiellement encore en place sur ${SERVER_IP:-serveur}"
    die 1 "Validation sshd -t echouee apres ecriture du drop-in" \
      "Verifiez manuellement /etc/ssh/sshd_config.d/ sur ${SERVER_IP:-serveur}"
  fi
  if ! ssh_exec "systemctl reload ssh"; then
    die 1 "systemctl reload ssh a echoue apres validation" \
      "Verifiez 'systemctl status ssh' sur ${SERVER_IP:-serveur}"
  fi
}

# Configure le durcissement SSH (PasswordAuthentication no, PermitRootLogin
# prohibit-password, KbdInteractiveAuthentication no). Idempotent via
# ensure_state qui controle la config effective avec `sshd -T`.
hardening_configure_ssh() {
  ensure_state \
    '_hardening_check_ssh_hardened' \
    '_hardening_write_ssh_drop_in' \
    'Hardening SSH'
}

# Commande de check fail2ban : la source de verite est l'ETAT EFFECTIF du
# serveur (AC3), pas la presence du drop-in. Chainage `&&` pour court-
# circuiter des qu'un sous-check echoue. Un seul appel ssh_exec (session
# ControlMaster mutualisee) pour minimiser la latence.
#
# Les 4 dimensions verifiees + 3 valeurs effectives :
#   1. dpkg -s fail2ban              : paquet installe
#   2. systemctl is-active fail2ban  : service tourne
#   3. systemctl is-enabled fail2ban : service enable au boot
#   4. fail2ban-client status sshd   : jail sshd active
#   5/6/7. fail2ban-client get sshd <param> : valeurs effectives conformes
#
# Valeurs retournees par fail2ban-client en secondes (findtime 10m -> 600)
# sauf bantime=-1 qui reste litteral -1 (ban permanent, pas de normalisation).
_hardening_check_fail2ban_active() {
  # shellcheck disable=SC2016 # $() est expanse cote serveur, pas cote client.
  ssh_exec 'dpkg -s fail2ban >/dev/null 2>&1 && systemctl is-active --quiet fail2ban && systemctl is-enabled --quiet fail2ban && fail2ban-client status sshd >/dev/null 2>&1 && [ "$(fail2ban-client get sshd maxretry)" = "5" ] && [ "$(fail2ban-client get sshd bantime)" = "-1" ] && [ "$(fail2ban-client get sshd findtime)" = "600" ]'
}

# Action fail2ban : 6 etapes chacune gardee par `if ! ssh_exec ; then die 1`
# (pas de dependance a pipefail). Pattern d'ecriture atomique du drop-in
# identique a la 2.2 (tmp + chmod 644 + mv -f). Pas de rollback destructif
# sur echec de test/reload (cf. story 2.3 §5).
_hardening_install_and_configure_fail2ban() {
  local tmp_path="${_HARDENING_F2B_JAIL_DROP_IN}.tmp-$$"

  # 1. Mise a jour index apt. Pas de -qq : conserver les warnings utiles
  #    (depot signe expire, miroir down, NO_PUBKEY) qui sont des signaux
  #    de securite non negligeables pour l'install d'un paquet reseau.
  if ! ssh_exec "apt-get update"; then
    die 1 "apt-get update a echoue avant installation fail2ban" \
      "Verifiez la connectivite reseau du serveur ${SERVER_IP:-serveur}"
  fi

  # 2. Installation idempotente (apt court-circuite si deja installe).
  #    DEBIAN_FRONTEND=noninteractive + --force-conf{def,old} : couvre
  #    tout mainteneur du paquet qui deciderait a l'avenir d'introduire
  #    un prompt debconf ou un conflit sur fichier de conf existant.
  if ! ssh_exec "DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold fail2ban"; then
    die 1 "Installation fail2ban echouee" \
      "Verifiez 'apt-cache policy fail2ban' et 'journalctl -xe' sur ${SERVER_IP:-serveur}"
  fi

  # 3. Ecriture atomique du drop-in (chmod AVANT mv : pas de fenetre avec
  #    permissions laxistes). Nettoyage best-effort du tmp sur echec.
  if ! printf '%s\n' "${_HARDENING_F2B_CONFIG}" \
      | ssh_exec "cat > ${tmp_path} && chmod 644 ${tmp_path} && mv -f ${tmp_path} ${_HARDENING_F2B_JAIL_DROP_IN}"; then
    ssh_exec "rm -f ${tmp_path}" \
      || log_warn "Nettoyage du tmp jail drop-in echoue sur ${SERVER_IP:-serveur}"
    die 1 "Ecriture du drop-in fail2ban echouee" \
      "Verifiez les permissions ou la connectivite SSH vers ${SERVER_IP:-serveur}"
  fi

  # 4. Activation + demarrage en un appel (idempotent si deja actif).
  if ! ssh_exec "systemctl enable --now fail2ban"; then
    die 1 "Activation fail2ban echouee (enable --now)" \
      "Verifiez 'systemctl status fail2ban' et 'journalctl -u fail2ban' sur ${SERVER_IP:-serveur}"
  fi

  # 5. Validation syntaxique AVANT reload (symetrique a `sshd -t` de la 2.2).
  #    `fail2ban-client -t` parse tous les fichiers de config sans solliciter
  #    le socket. Echec = drop-in garde sur place (coherent avec §5) + die 1
  #    avec chemin explicite pour que l'admin sache ou regarder.
  if ! ssh_exec "fail2ban-client -t"; then
    die 1 "fail2ban-client -t a detecte une config invalide (drop-in : ${_HARDENING_F2B_JAIL_DROP_IN})" \
      "Verifiez '${_HARDENING_F2B_JAIL_DROP_IN}' et 'journalctl -u fail2ban' sur ${SERVER_IP:-serveur}"
  fi

  # 6. Reload gracieux : applique le diff de config sans perdre les bans.
  #    PAS de rollback du drop-in sur echec (divergence volontaire vs SSH
  #    hardening) : fail2ban ne touche pas a sshd, garder le fichier aide
  #    au diagnostic (cf. story 2.3 §5). Le chemin du drop-in est explicite
  #    dans le message pour guider le diagnostic.
  if ! ssh_exec "fail2ban-client reload"; then
    die 1 "fail2ban-client reload a echoue (drop-in : ${_HARDENING_F2B_JAIL_DROP_IN})" \
      "Verifiez '${_HARDENING_F2B_JAIL_DROP_IN}', 'fail2ban-client status' et 'journalctl -u fail2ban' sur ${SERVER_IP:-serveur}"
  fi
}

# Configure fail2ban : jail sshd avec seuils stricts (maxretry=5, findtime=10m,
# bantime=-1 ban permanent) et ignoreip loopback+LAN RFC1918. Idempotent via
# ensure_state qui verifie l'etat effectif (paquet + service + jail + valeurs)
# avant toute action.
hardening_configure_fail2ban() {
  ensure_state \
    '_hardening_check_fail2ban_active' \
    '_hardening_install_and_configure_fail2ban' \
    'Hardening fail2ban'
}

# Story 2.4 : commande de check UFW. Source de verite = etat EFFECTIF du
# serveur (AC3), PAS la presence d'un fichier (UFW n'a pas de repertoire
# *.d/*.rules officiel - tout passe par CLI ufw). 7 dimensions + 30 regles
# LAN verifiees en UN SEUL ssh_exec (session ControlMaster mutualisee) :
#
#   1. Paquet installe             : dpkg -s ufw
#   2. Service actif               : systemctl is-active --quiet ufw
#   3. Service enable au boot      : systemctl is-enabled --quiet ufw
#   4. Statut actif                : ufw status verbose | grep "^Status: active"
#   5. Default incoming = deny     : ufw status verbose | grep "Default: deny (incoming)"
#   6. Default routed = deny       : ufw status verbose | grep "deny (routed)"
#   7. Regle SSH globale           : ufw status | grep "^22/tcp ALLOW"
#   8-N. Regles LAN par port/CIDR  : ufw status | grep "^<PORT>/tcp ALLOW <CIDR>"
#                                    (30 regles : 3 CIDRs RFC1918 x 10 ports)
#
# Notes regex :
#   - [[:space:]]+ (POSIX) plutot que \s+ (GNU) : portable busybox/ERE strict.
#   - Dots des CIDRs echappes : `10\.0\.0\.0/8` pour matcher literal (sinon
#     `.` matcherait n'importe quel caractere).
#   - `Default: deny \(incoming\)` : parentheses echappees pour ERE (grep
#     recoit `\(` literal apres traitement bash double-quote cote serveur).
#   - LC_ALL=C devant `ufw status` : UFW localise sa sortie via gettext
#     (ex: fr_FR -> "Etat : actif", "Defaut : refuser (entrant)"). Forcer
#     la locale C garantit la sortie anglaise stable sur laquelle nos
#     regex sont ancrees, independamment de la locale du serveur.
#
# `ufw status verbose` et `ufw status` captures UNE SEULE FOIS cote serveur
# dans $status/$rules pour ne pas lancer ufw 30+ fois (fan-out 150-300 ms
# vs 50-200 ms total). Optimisation marginale mais gratuite.
_hardening_check_ufw_active() {
  # Base du check : 9 sous-verifications cote serveur. $status/$rules sont
  # expanses cote serveur (simple quote cote client).
  # shellcheck disable=SC2016  # $status/$rules sont expanses cote serveur.
  local check_cmd='dpkg -s ufw >/dev/null 2>&1 && systemctl is-active --quiet ufw && systemctl is-enabled --quiet ufw && status=$(LC_ALL=C ufw status verbose 2>/dev/null) && printf "%s\n" "$status" | grep -qE "^Status: active" && printf "%s\n" "$status" | grep -qE "Default: deny \\(incoming\\)" && printf "%s\n" "$status" | grep -qE "deny \\(routed\\)" && rules=$(LC_ALL=C ufw status 2>/dev/null) && printf "%s\n" "$rules" | grep -qE "^22/tcp[[:space:]]+ALLOW"'
  local port cidr escaped_cidr
  for port in "${_HARDENING_UFW_SERVICE_PORTS[@]}"; do
    for cidr in "${_HARDENING_UFW_LAN_CIDRS[@]}"; do
      # Echappe les dots du CIDR : 10.0.0.0/8 -> 10\.0\.0\.0/8 (literal match).
      escaped_cidr="${cidr//./\\.}"
      check_cmd+=" && printf \"%s\\n\" \"\$rules\" | grep -qE \"^${port}/tcp[[:space:]]+ALLOW[[:space:]]+${escaped_cidr}\""
    done
  done
  ssh_exec "${check_cmd}"
}

# Story 2.4 : action UFW. 7 etapes gardees chacune par `if ! ssh_exec ;
# then die 1` (pas de dependance a pipefail, coherent 2.2/2.3). Pas de
# rollback destructif sur echec (coherent 2.3 §5).
#
# Ordre critique (anti-lockout) :
#   etape 4 (allow 22/tcp) AVANT etape 6 (--force enable). Si etape 4
#   echoue, etape 6 n'est JAMAIS atteinte (die 1 stoppe la chaine).
#   Aucun scenario ne peut donc couper SSH par `ufw enable` sans allow
#   SSH prealable - c'est l'invariant anti-lockout de la story 2.4.
_hardening_install_and_configure_ufw() {
  # 1. Mise a jour index apt. Pas de -qq (coherent 2.3 §4 : conserver
  #    les warnings de depot signe expire / miroir down / NO_PUBKEY).
  if ! ssh_exec "apt-get update"; then
    die 1 "apt-get update a echoue avant installation ufw" \
      "Verifiez la connectivite reseau du serveur ${SERVER_IP:-serveur}"
  fi

  # 2. Installation idempotente (apt court-circuite si deja installe).
  #    DEBIAN_FRONTEND=noninteractive + --force-conf{def,old} : couvre
  #    tout prompt debconf futur ou conflit sur fichier de conf existant.
  if ! ssh_exec "DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ufw"; then
    die 1 "Installation ufw echouee" \
      "Verifiez 'apt-cache policy ufw' et 'journalctl -xe' sur ${SERVER_IP:-serveur}"
  fi

  # 3. Politiques par defaut. Chainees && : chacune idempotente cote ufw,
  #    la premiere qui echoue arrete la chaine. Les politiques ne sont
  #    appliquees au filtrage qu'a l'etape 6 (`ufw --force enable`) donc
  #    aucun risque de lockout a ce stade meme si SSH n'est pas encore
  #    autorise (etape 4).
  if ! ssh_exec "ufw default deny incoming && ufw default allow outgoing && ufw default deny routed"; then
    die 1 "Configuration des politiques par defaut UFW echouee" \
      "Verifiez 'ufw status verbose' et 'journalctl -u ufw' sur ${SERVER_IP:-serveur}"
  fi

  # 4. ANTI-LOCKOUT : autoriser SSH AVANT d'activer UFW. Sans cette ligne,
  #    `ufw --force enable` couperait la session SSH courante (y compris
  #    ControlMaster) puisque `default deny incoming` rejetterait tous
  #    les paquets entrants, SSH compris. Si cette etape echoue, `die 1`
  #    stoppe la chaine : l'etape 6 n'est JAMAIS atteinte - UFW reste
  #    inactif, aucun risque de coupure (test unitaire AC5
  #    SSH_EXEC_UFW_ALLOW_SSH_RC=1 assertionne l'absence de --force enable).
  if ! ssh_exec "ufw allow 22/tcp"; then
    die 1 "Autorisation SSH via UFW echouee (ufw allow 22/tcp)" \
      "Verifiez 'ufw status' et 'journalctl -u ufw' sur ${SERVER_IP:-serveur}"
  fi

  # 5. Regles services LAN : 3 CIDRs RFC1918 x 10 ports = 30 regles.
  #    Genere cote client via boucle, envoye en UN SEUL ssh_exec avec
  #    `set -e` cote remote : une regle en echec arrete immediatement la
  #    sequence (meilleur diagnostic qu'un partial-apply silencieux).
  #    `ufw allow from X to any port Y proto tcp` est naturellement
  #    idempotent (posee deux fois : "Skipping adding existing rule",
  #    exit 0).
  local lan_rules_cmd='set -e'
  local cidr port
  for port in "${_HARDENING_UFW_SERVICE_PORTS[@]}"; do
    for cidr in "${_HARDENING_UFW_LAN_CIDRS[@]}"; do
      lan_rules_cmd+="; ufw allow from ${cidr} to any port ${port} proto tcp"
    done
  done
  if ! ssh_exec "${lan_rules_cmd}"; then
    die 1 "Ajout des regles UFW LAN echoue" \
      "Verifiez 'ufw status' et 'journalctl -u ufw' sur ${SERVER_IP:-serveur}"
  fi

  # 6. Activation UFW non-interactif. --force : sinon prompt y/n bloquant
  #    ("Command may disrupt existing ssh connections. Proceed with
  #    operation (y|n)?"). SSH est deja autorise (etape 4) : la session
  #    ControlMaster reste saine apres activation du filtrage.
  if ! ssh_exec "ufw --force enable"; then
    die 1 "ufw --force enable a echoue" \
      "Verifiez 'ufw status verbose', 'journalctl -u ufw' et 'iptables -L -n -v | head' sur ${SERVER_IP:-serveur}"
  fi

  # 7. Persistance au boot. `ufw enable` active normalement le service
  #    systemd aussi, mais `systemctl enable ufw` explicite garantit le
  #    contrat meme si une version future d'ufw change ce comportement.
  #    Idempotent (systemctl n'erre pas si deja enable).
  if ! ssh_exec "systemctl enable ufw"; then
    die 1 "Activation persistance UFW au boot echouee (systemctl enable)" \
      "Verifiez 'systemctl status ufw' sur ${SERVER_IP:-serveur}"
  fi
}

# Configure UFW : default deny incoming/routed + allow outgoing, SSH ouvert
# globalement (fail2ban 2.3 gatekeepe le brute-force), services MediaDock
# accessibles uniquement depuis LAN RFC1918 (3 CIDRs x 10 ports = 30 regles).
# Idempotent via ensure_state (source de verite : ufw status verbose + dpkg
# + systemctl). Ordre anti-lockout : `ufw allow 22/tcp` AVANT `ufw --force
# enable` - invariant absolu de la story 2.4.
hardening_configure_ufw() {
  ensure_state \
    '_hardening_check_ufw_active' \
    '_hardening_install_and_configure_ufw' \
    'Hardening UFW'
}

# Story 2.5 : commande de check unattended-upgrades. Source de verite =
# etat EFFECTIF du serveur (AC3), PAS la presence du drop-in MediaDock.
# 10 dimensions verifiees en UN SEUL ssh_exec chaine (session ControlMaster
# mutualisee, latence ~50ms total) :
#
#   1. Paquet installe                   : dpkg -s unattended-upgrades
#   2. Timer apt-daily actif             : systemctl is-active apt-daily.timer
#   3. Timer apt-daily enable au boot    : systemctl is-enabled apt-daily.timer
#   4. Timer apt-daily-upgrade actif     : systemctl is-active apt-daily-upgrade.timer
#   5. Timer apt-daily-upgrade enable    : systemctl is-enabled apt-daily-upgrade.timer
#   6. APT::Periodic::Unattended-Upgrade = "1"            : apt-config dump --format %v%n
#   7. APT::Periodic::Update-Package-Lists = "1"          : apt-config dump --format %v%n
#   8. Origins-Pattern inclut Debian-Security             : apt-config dump | grep -q
#   9. Remove-Unused-Kernel-Packages = "false"            : apt-config dump --format %v%n
#  10. Remove-Unused-Dependencies = "false"               : apt-config dump --format %v%n
#
# Ordre court-circuit : dpkg -s d'abord (le moins couteux, evite de poursuivre
# si paquet absent) ; apt-config dump en dernier (plus lourd, parse toute la
# config apt.conf.d). apt-config dump est insensible a la locale (format
# machine-readable) donc pas de LC_ALL=C contrairement a UFW.
#
# Check 8 (label=Debian-Security) : condition LACHE intentionnelle. Un admin
# qui aurait pose au moins une ligne label=Debian-Security via un autre
# drop-in est considere conforme. Le test strict security-only (AC2) s'appuie
# sur l'effet runtime via unattended-upgrade --dry-run --debug, pas sur ce
# check d'idempotence.
#
# Checks 9-10 (Remove-Unused-* = "false") : symetrie check/action - l'action
# ecrit ces 2 directives dans le drop-in (defense en profondeur anti-autoremove
# pendant un run unattended), le check les verifie. Sans ces 2 sous-checks, un
# admin ou un drop-in concurrent qui flip l'une a "true" resterait invisible :
# ensure_state reporterait conforme au prochain run et la defense en profondeur
# serait silencieusement perdue. Decision revue post code review (2026-04-23)
# au prix d'une legere deviation spec §3 qui n'enumerait que 3 apt-config dumps.
_hardening_check_unattended_active() {
  # shellcheck disable=SC2016 # $() est expanse cote serveur, pas cote client.
  ssh_exec 'dpkg -s unattended-upgrades >/dev/null 2>&1 && systemctl is-active --quiet apt-daily.timer && systemctl is-enabled --quiet apt-daily.timer && systemctl is-active --quiet apt-daily-upgrade.timer && systemctl is-enabled --quiet apt-daily-upgrade.timer && [ "$(apt-config dump APT::Periodic::Unattended-Upgrade --format %v%n 2>/dev/null)" = "1" ] && [ "$(apt-config dump APT::Periodic::Update-Package-Lists --format %v%n 2>/dev/null)" = "1" ] && apt-config dump Unattended-Upgrade::Origins-Pattern 2>/dev/null | grep -q "label=Debian-Security" && [ "$(apt-config dump Unattended-Upgrade::Remove-Unused-Kernel-Packages --format %v%n 2>/dev/null)" = "false" ] && [ "$(apt-config dump Unattended-Upgrade::Remove-Unused-Dependencies --format %v%n 2>/dev/null)" = "false" ]'
}

# Story 2.5 : action unattended-upgrades. 5 etapes gardees chacune par
# `if ! ssh_exec ; then die 1` (pas de dependance a pipefail, coherent
# 2.2/2.3/2.4). Pattern d'ecriture atomique du drop-in identique 2.2/2.3
# (tmp + chmod 644 + mv -f). Pas de rollback destructif sur echec
# (coherent 2.3 §5 / 2.4 §5) : drop-in conserve pour diagnostic.
#
# Ordre etape 4 (dry-run) AVANT etape 5 (enable --now timers) : symetrique
# sshd -t avant reload (2.2) et fail2ban-client -t avant reload (2.3).
# Echec de --dry-run = timers jamais actives, comportement seedbox intact.
_hardening_install_and_configure_unattended() {
  local tmp_path="${_HARDENING_UNATTENDED_DROP_IN}.tmp-$$"

  # 1. Mise a jour index apt. Pas de -qq (coherent 2.3 §4 / 2.4 §4 :
  #    conserver les warnings depot signe expire / miroir down / NO_PUBKEY
  #    comme signaux de securite).
  if ! ssh_exec "apt-get update"; then
    die 1 "apt-get update a echoue avant installation unattended-upgrades" \
      "Verifiez la connectivite reseau du serveur ${SERVER_IP:-serveur}"
  fi

  # 2. Installation idempotente (apt court-circuite si deja installe).
  #    DEBIAN_FRONTEND=noninteractive + --force-conf{def,old} : couvre
  #    tout prompt debconf futur ou conflit sur fichier de conf existant
  #    (le paquet cree /etc/apt/apt.conf.d/50unattended-upgrades par defaut).
  if ! ssh_exec "DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold unattended-upgrades"; then
    die 1 "Installation unattended-upgrades echouee" \
      "Verifiez 'apt-cache policy unattended-upgrades' et 'journalctl -xe' sur ${SERVER_IP:-serveur}"
  fi

  # 3. Ecriture atomique du drop-in (chmod AVANT mv : pas de fenetre avec
  #    permissions laxistes). Nettoyage best-effort du tmp sur echec.
  #    Le contenu _HARDENING_UNATTENDED_CONFIG contient litteralement
  #    ${distro_codename} - expansion au runtime par unattended-upgrade
  #    (python-apt + /etc/os-release), PAS cote bash ni cote ssh_exec
  #    (stdin transmis tel quel).
  if ! printf '%s\n' "${_HARDENING_UNATTENDED_CONFIG}" \
      | ssh_exec "cat > ${tmp_path} && chmod 644 ${tmp_path} && mv -f ${tmp_path} ${_HARDENING_UNATTENDED_DROP_IN}"; then
    ssh_exec "rm -f ${tmp_path}" \
      || log_warn "Nettoyage du tmp drop-in auto-updates echoue sur ${SERVER_IP:-serveur}"
    die 1 "Ecriture du drop-in unattended-upgrades echouee" \
      "Verifiez les permissions ou la connectivite SSH vers ${SERVER_IP:-serveur}"
  fi

  # 4. Validation pre-apply : unattended-upgrade --dry-run --debug parse
  #    la config apt.conf finale (tous drop-ins agreges) ET teste la
  #    requete des origines. Symetrique sshd -t (2.2) / fail2ban-client -t
  #    (2.3). Echec = drop-in conserve sur place (coherent 2.3 §5 / 2.4 §5)
  #    + die 1 avec chemin explicite pour que l'admin sache ou regarder.
  #    Pas de reload apt : la config apt.conf est relue a chaque invocation.
  if ! ssh_exec "unattended-upgrade --dry-run --debug >/dev/null 2>&1"; then
    die 1 "unattended-upgrade --dry-run --debug a detecte une config invalide (drop-in : ${_HARDENING_UNATTENDED_DROP_IN})" \
      "Verifiez '${_HARDENING_UNATTENDED_DROP_IN}', 'unattended-upgrade --dry-run --debug' et 'journalctl -u unattended-upgrades' sur ${SERVER_IP:-serveur}"
  fi

  # 5. Activation des timers systemd apt-daily*. Les deux timers en UN
  #    SEUL appel systemctl (atomique + idempotent). enable --now : enable
  #    pour persistance au boot + start immediat. Si les timers sont deja
  #    actifs/enable (cas Debian 13 standard ou le paquet apt a deja enable
  #    les timers), systemctl no-op sans erreur.
  if ! ssh_exec "systemctl enable --now apt-daily.timer apt-daily-upgrade.timer"; then
    die 1 "Activation des timers apt-daily* echouee (systemctl enable --now)" \
      "Verifiez 'systemctl status apt-daily.timer apt-daily-upgrade.timer' et 'journalctl -u apt-daily-upgrade' sur ${SERVER_IP:-serveur}"
  fi
}

# Configure unattended-upgrades : scope strictement Debian-Security (2 origines
# codename + codename-security), timers apt-daily* actifs et enable au boot,
# Remove-Unused-{Kernel-Packages,Dependencies} a false pour defense en
# profondeur (pas d'autoremove silencieux durant un run unattended). Idempotent
# via ensure_state qui verifie l'etat effectif (paquet + 2 timers + 3 valeurs
# apt-config dump) avant toute action. Pas d'Automatic-Reboot (laisser le
# defaut paquet false : seedbox ne reboote PAS au milieu d'un download torrent).
hardening_configure_auto_updates() {
  ensure_state \
    '_hardening_check_unattended_active' \
    '_hardening_install_and_configure_unattended' \
    'Hardening auto-updates'
}

# Orchestre le hardening : SSH d'abord (story 2.2), puis fail2ban (story
# 2.3), puis UFW (story 2.4), puis auto-updates (story 2.5 - clot l'epic
# hardening). L'ordre compte : sshd doit etre en mode cle-only AVANT que
# fail2ban ne protege la nouvelle config ; fail2ban doit etre actif AVANT
# que UFW --force enable n'active le filtrage (pour que le gatekeeper
# brute-force soit deja en place quand le firewall restrictif entre en
# vigueur) ; auto-updates arrive en dernier car aucun autre helper n'en
# depend et il n'a aucun impact sur SSH/f2b/UFW en cours.
# `_install_run_step` attend un return 0 explicite : aucun traitement
# d'erreur supplementaire necessaire ici, `die` depuis les helpers fait
# exit avec code propage.
hardening_run() {
  hardening_configure_ssh
  hardening_configure_fail2ban
  hardening_configure_ufw
  hardening_configure_auto_updates
  return 0
}
