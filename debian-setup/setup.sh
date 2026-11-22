#!/usr/bin/env bash

#  1) Запрет входа root по паролю через SSH (ключи остаются)
#  2) Создание пользователя с sudo (имя/пароль — в настройках ниже)
#  3) UFW закрыть всё входящее, открыть порты из конфига; нет UFW — спросит
#  4) Установка и настройка fail2ban для защиты SSH
#  5) Обновление системы + проверки + автоматический откат при ошибке
#
# Запуск: bash setup.sh (от root)

set -Eeuo pipefail

# ------------------------------- НАСТРОЙКИ -----------------------------------
NEW_USER="ops"                 # Имя создаваемого пользователя
NEW_USER_PASSWORD=""           # Пароль. Пусто = спросит интерактивно (безопаснее)
SSH_PORT=22                    # порт SSH — откроется в фаерволе автоматически
TCP_PORTS=(22 80 443)          # Разрешённые TCP-порты
UDP_PORTS=()                   # Разрешённые UDP-порты
DO_SYSTEM_UPGRADE=true         # Выполнять apt-get upgrade
CONFIGURE_FIREWALL=true        # Настраивать UFW
CONFIGURE_FAIL2BAN=true        # Устанавливать и настраивать fail2ban
ASSUME_YES=false               # true = не спрашивать подтверждение установки UFW
MIN_PASSWORD_LEN=6
# -----------------------------------------------------------------------------

SCRIPT_VERSION=1
BACKUP_DIR=""
LOG_FILE=""
STEP="инициализация"
SUCCESS=false
IN_CONTAINER=false
UFW_WAS_ACTIVE=false
USER_EXISTED=false
ROLLBACK_STEPS=()
INSTALLED_PKGS=()

log()  { printf '[ OK ] %s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err()  { printf '[FAIL] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

push_rollback() { ROLLBACK_STEPS+=("$1"); }

run_rollback() {
    local i
    if (( ${#ROLLBACK_STEPS[@]} == 0 )); then
        info "Откатывать нечего."
        return 0
    fi
    warn "Откат: ${#ROLLBACK_STEPS[@]} шаг(ов) в обратном порядке..."
    for (( i=${#ROLLBACK_STEPS[@]}-1; i>=0; i-- )); do
        info "  <- ${ROLLBACK_STEPS[$i]}"
        eval "${ROLLBACK_STEPS[$i]}" || warn "Шаг отката завершился с ошибкой (продолжаю)."
    done
}

on_exit() {
    local code=$?
    trap - EXIT
    if [[ "$SUCCESS" == true ]]; then
        log "Готово. Бэкапы: $BACKUP_DIR | лог: $LOG_FILE"
        exit 0
    fi
    if (( code == 0 )); then code=1; fi
    err "Сбой на этапе <<$STEP>> (код $code). Откатываю изменения..."
    if [[ "$IN_CONTAINER" == true && "$STEP" == *фаервол* ]]; then
        err "Подсказка: контейнеру нужны --cap-add=NET_ADMIN --cap-add=NET_RAW."
    fi
    run_rollback
    if (( ${#INSTALLED_PKGS[@]} > 0 )); then
        info "Удаляю пакеты, установленные скриптом: ${INSTALLED_PKGS[*]}"
        apt-get purge -y "${INSTALLED_PKGS[@]}" >/dev/null 2>&1 || true
        apt-get autoremove -y >/dev/null 2>&1 || true
    fi
    err "Откат завершён (обновления пакетов не откатываются)."
    exit "$code"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ask_yes() {
    [[ "$ASSUME_YES" == true ]] && return 0
    local a=""
    printf '%s [y/N]: ' "$1"
    read -r a </dev/tty || return 1
    [[ "$a" =~ ^[YyДд]$ ]]
}

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

ensure_pkg() {
    if pkg_installed "$1"; then
        info "Пакет $1 уже установлен - пропускаю."
    else
        info "Устанавливаю $1..."
        apt-get install -y "$1"
        INSTALLED_PKGS+=("$1")
    fi
}

restart_ssh() {
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart ssh
    elif [[ -x /etc/init.d/ssh ]]; then
        /etc/init.d/ssh restart >/dev/null
    else
        # контейнер без init-системы
        mkdir -p /run/sshd
        if [[ -r /run/sshd.pid ]] && kill -0 "$(cat /run/sshd.pid)" 2>/dev/null; then
        kill -HUP "$(cat /run/sshd.pid)"
        else
        /usr/sbin/sshd
        fi
    fi
}

restore_ufw() {
    ufw --force disable >/dev/null 2>&1 || true
    if [[ -d "$BACKUP_DIR/etc-ufw" ]]; then
        rm -rf /etc/ufw
        cp -a "$BACKUP_DIR/etc-ufw" /etc/ufw
    fi
    if [[ "$UFW_WAS_ACTIVE" == true ]]; then
        ufw --force enable >/dev/null 2>&1 || warn "Не удалось вернуть UFW в активное состояние."
    fi
}

restore_fail2ban() {
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop fail2ban >/dev/null 2>&1 || true
    fi
    if [[ -d "$BACKUP_DIR/etc-fail2ban" ]]; then
        rm -rf /etc/fail2ban
        cp -a "$BACKUP_DIR/etc-fail2ban" /etc/fail2ban
    fi
}

# ПРОВЕРКИ ---------------------------------------------------------------------------------------------------------------
STEP="проверки окружения"
[[ $EUID -eq 0 ]] || die "Запустите от root: bash $0"
command -v apt-get >/dev/null 2>&1 || die "apt-get не найден."
if [[ -r /etc/os-release ]]; then
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID_LIKE:-}" == *debian* ]] || die "Скрипт только для Debian."
fi

LOG_FILE="/var/log/debian-hardening-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
info "setup.sh v$SCRIPT_VERSION | лог: $LOG_FILE"

[[ "$NEW_USER" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || die "Некорректное имя NEW_USER: $NEW_USER"
[[ "$NEW_USER" != "root" ]] || die "NEW_USER не может быть root."
for p in "$SSH_PORT" "${TCP_PORTS[@]}" "${UDP_PORTS[@]}"; do
[[ "$p" =~ ^[0-9]+$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 )) || die "Некорректный порт: $p"
done

if [[ -z "$NEW_USER_PASSWORD" ]]; then
    read -r -s -p "Пароль для $NEW_USER: " NEW_USER_PASSWORD </dev/tty || die "Нет TTY - задайте пароль в скрипте."
    echo
    read -r -s -p "Повторите пароль: " _p2 </dev/tty || die "Нет TTY."
    echo
    [[ "$NEW_USER_PASSWORD" == "$_p2" ]] || die "Пароли не совпадают."
    unset _p2
fi
(( ${#NEW_USER_PASSWORD} >= MIN_PASSWORD_LEN )) || die "Пароль короче $MIN_PASSWORD_LEN символов."

if [[ -f /.dockerenv || -f /run/.containerenv ]] || grep -qaE 'docker|containerd|kubepods|lxc' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER=true
    warn "Контейнер: UFW требует --cap-add=NET_ADMIN; systemd может отсутствовать."
fi

BACKUP_DIR=$(mktemp -d /root/hardening-backup.XXXXXX)
chmod 700 "$BACKUP_DIR"

# 1) ОБНОВЛЕНИЕ ---------------------------------------------------------------------------------------------------------------
STEP="обновление системы"
export DEBIAN_FRONTEND=noninteractive
apt-get update
if [[ "$DO_SYSTEM_UPGRADE" == true ]]; then
    apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
    log "Система обновлена (это действие не откатывается)."
fi

# 2) ПОЛЬЗОВАТЕЛЬ + SUDO ---------------------------------------------------------------------------------------------------------------
STEP="пользователь и sudo"
ensure_pkg sudo
if id "$NEW_USER" >/dev/null 2>&1; then
    USER_EXISTED=true
    warn "Пользователь $NEW_USER уже существует — пароль не меняю."
else
    useradd -m -s /bin/bash "$NEW_USER"
    push_rollback "userdel -r '$NEW_USER' 2>/dev/null || true"
    printf '%s:%s\n' "$NEW_USER" "$NEW_USER_PASSWORD" | chpasswd
    log "Пользователь $NEW_USER создан."
fi
if id -nG "$NEW_USER" | grep -qw sudo; then
    info "$NEW_USER уже в группе sudo."
else
    usermod -aG sudo "$NEW_USER"
    push_rollback "gpasswd -d '$NEW_USER' sudo >/dev/null 2>&1 || true"
    log "$NEW_USER добавлен в группу sudo."
fi
# Проверяем sudo до того, как трогаем SSH чтобы не потерять доступ
if [[ "$USER_EXISTED" == false ]]; then
    printf '%s\n' "$NEW_USER_PASSWORD" | runuser -u "$NEW_USER" -- sudo -S -k -p '' true \
        || die "sudo для $NEW_USER не работает — прерываю до изменения SSH."
    log "Проверка sudo пройдена."
fi

# 3) SSH: ЗАПРЕТ ВХОДА ПО ROOT ПО ПАРОЛЮ ---------------------------------------------------------------------------------------------------------------
STEP="SSH: запрет root по паролю"
ensure_pkg openssh-server
mkdir -p /run/sshd /etc/ssh/sshd_config.d
ssh-keygen -A >/dev/null 2>&1 || true

SSHD_CONF=/etc/ssh/sshd_config
# sshd берёт первое значение параметра; *.conf читаются по алфавиту.
# 00- ставит файл в начало списка.
DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
DROPIN_EXISTED=false
if [[ -f "$DROPIN" ]]; then
cp -a "$DROPIN" "$BACKUP_DIR/00-hardening.conf"
DROPIN_EXISTED=true
fi

if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONF"; then
cp -a "$SSHD_CONF" "$BACKUP_DIR/sshd_config"
sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_CONF"
push_rollback "cp -a '$BACKUP_DIR/sshd_config' '$SSHD_CONF'; restart_ssh >/dev/null 2>&1 || true"
fi

cat > "$DROPIN" <<EOF
# setup.sh, $(date -Is)
# root: вход только по ключу, пароль запрещён
PermitRootLogin prohibit-password
EOF
chmod 644 "$DROPIN"
if [[ "$DROPIN_EXISTED" == true ]]; then
push_rollback "cp -a '$BACKUP_DIR/00-hardening.conf' '$DROPIN'; restart_ssh >/dev/null 2>&1 || true"
else
push_rollback "rm -f '$DROPIN'; restart_ssh >/dev/null 2>&1 || true"
fi

/usr/sbin/sshd -t || die "sshd -t: конфигурация невалидна."

# Проверка эффективного конфига до рестарта. Ошибки не прячем.
# sshd -T печатает легаси-алиас without-password == prohibit-password.
SSHD_T_OUT=$(/usr/sbin/sshd -T 2>"$BACKUP_DIR/sshd-T.err") || {
cat "$BACKUP_DIR/sshd-T.err" >&2
die "sshd -T завершился с ошибкой — причина выше."
}
root_login=$(printf '%s\n' "$SSHD_T_OUT" | awk '$1=="permitrootlogin"{print $2}')
info "Эффективный PermitRootLogin: ${root_login:-не определён}"
if [[ "$root_login" != "prohibit-password" && "$root_login" != "without-password" && "$root_login" != "no" ]]; then
warn "PermitRootLogin переопределён чем-то ещё. Активные строки:"
grep -Rni '^[[:space:]]*PermitRootLogin' "$SSHD_CONF" /etc/ssh/sshd_config.d/ >&2 || true
die "Пароль root по SSH не запрещён — см. источники выше."
fi

restart_ssh
log "SSH: вход root по паролю запрещён."

# 4) ФАЕРВОЛ ---------------------------------------------------------------------------------------------------------------
STEP="настройка фаервола (UFW)"
if [[ "$CONFIGURE_FIREWALL" != true ]]; then
info "Фаервол пропущен (CONFIGURE_FIREWALL=false)."
elif ! command -v ufw >/dev/null 2>&1 && ! ask_yes "UFW не установлен. Установить?"; then
warn "Установка UFW отклонена — фаервол пропущен."
else
ensure_pkg ufw
iptables -L -n >/dev/null 2>&1 \
    || die "iptables недоступен. В контейнере: --cap-add=NET_ADMIN --cap-add=NET_RAW."

cp -a /etc/ufw "$BACKUP_DIR/etc-ufw"
ufw status | grep -q 'Status: active' && UFW_WAS_ACTIVE=true
push_rollback "restore_ufw"

# IPv6 в контейнерах часто выключен — иначе ufw enable упадёт
if [[ ! -e /proc/net/if_inet6 ]]; then
    sed -i 's/^IPV6=.*/IPV6=no/' /etc/ufw/ufw.conf
fi
if [[ "$UFW_WAS_ACTIVE" == true ]]; then
    warn "UFW был активен: reset на мгновение снимет фильтрацию."
fi

ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing

# SSH открываем первым, до включения — чтобы не отрезать себя
ufw allow "$SSH_PORT/tcp" comment 'SSH'
# Если подключены по SSH на другой порт — тоже открываем
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    cur_port="${SSH_CONNECTION##* }"
    if [[ "$cur_port" =~ ^[0-9]+$ && "$cur_port" != "$SSH_PORT" ]]; then
    ufw allow "$cur_port/tcp" comment 'current SSH session'
    fi
fi
for p in "${TCP_PORTS[@]}"; do
    [[ "$p" == "$SSH_PORT" ]] || ufw allow "$p/tcp"
done
for p in "${UDP_PORTS[@]}"; do ufw allow "$p/udp"; done

ufw --force enable
ufw status | grep -q 'Status: active' || die "UFW не активировался."
log "UFW активен: deny incoming; TCP: ${TCP_PORTS[*]}; UDP: ${UDP_PORTS[*]:-нет}."
fi

# 5) FAIL2BAN ---------------------------------------------------------------------------------------------------------------
STEP="настройка fail2ban"
if [[ "$CONFIGURE_FAIL2BAN" != true ]]; then
    info "Fail2ban пропущен (CONFIGURE_FAIL2BAN=false)."
elif ! command -v fail2ban-client >/dev/null 2>&1 && ! ask_yes "Fail2ban не установлен. Установить?"; then
    warn "Установка fail2ban отклонена — пропущено."
else
    ensure_pkg fail2ban
    
    if [[ -d /etc/fail2ban ]]; then
        cp -a /etc/fail2ban "$BACKUP_DIR/etc-fail2ban"
    fi
    push_rollback "restore_fail2ban"
    
    # Создаём локальную конфигурацию для SSH
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/ssh.conf <<EOF
# setup.sh, $(date -Is)
# Защита SSH от brute-force атак
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
backend = systemd
EOF
    chmod 644 /etc/fail2ban/jail.d/ssh.conf
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cat > /etc/fail2ban/jail.local <<EOF
# setup.sh, $(date -Is)
# Базовые настройки fail2ban
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
EOF
        chmod 644 /etc/fail2ban/jail.local
    fi
    
    # Запуск и включение fail2ban
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
        systemctl enable fail2ban >/dev/null 2>&1
        systemctl restart fail2ban >/dev/null 2>&1
        sleep 2
        if systemctl is-active --quiet fail2ban; then
            log "Fail2ban запущен и активен."
            if fail2ban-client status sshd >/dev/null 2>&1; then
                info "SSH jail активен."
                fail2ban-client status sshd | grep -E 'Currently|Total' || true
            else
                warn "SSH jail не активен — проверьте конфигурацию."
            fi
        else
            die "Fail2ban не запустился. Проверьте логи: journalctl -u fail2ban"
        fi
    else
        warn "systemd недоступен — fail2ban установлен, но не запущен."
        info "Запустите вручную: fail2ban-client start"
    fi
fi

# ИТОГ ---------------------------------------------------------------------------------------------------------------
STEP="завершение"
SUCCESS=true
log "Все шаги выполнены."
info "Юзер: $NEW_USER (sudo) | SSH-порт: $SSH_PORT | root по паролю SSH: запрещён | fail2ban: $([ "$CONFIGURE_FAIL2BAN" == true ] && echo 'настроен' || echo 'пропущен')."