#!/usr/bin/env bash
#
# =============================================================================
# Loghound installer — bare box to working panel, in one command.
# =============================================================================
#
#   sudo ./install/install.sh                     full install
#   sudo ./install/install.sh --dry-run           print every action, change nothing
#   sudo ./install/install.sh --upgrade           refresh code, keep config and data
#   sudo ./install/install.sh --uninstall         reverse everything, with prompts
#   sudo ./install/install.sh --non-interactive   answer every prompt from LOGHOUND_* env
#
# End state: a running ingest daemon, an authenticated panel served over HTTPS by
# whichever web server is already on the box, timers enabled, and documents landing in
# Solr. No "now edit this file by hand" left over.
#
# =============================================================================
# THE ONE RULE: NEVER BREAK THE HOST.
# =============================================================================
# The first deployment target for this script is a busy production box already serving
# real sites. Every design decision below follows from that:
#
#   * Pre-install state (the vhost directory, the FPM pool directory, the unit
#     directory) is RECORDED to a file before anything changes, so a rollback is exact
#     rather than a guess.
#   * A file that already exists is NEVER overwritten. The install aborts and names the
#     conflict. There is no "helpfully back up and replace".
#   * Configuration is VALIDATED before it is enabled — `apache2ctl configtest`,
#     `nginx -t`, `php-fpm -t` — and if validation fails the files this run created are
#     removed, the site is disabled, and validation is re-run to prove the host is back
#     where it started.
#   * `systemctl reload`, never `restart`, for the web server and PHP-FPM. A restart
#     drops in-flight requests on every other site on the machine.
#   * The vhost filename sorts LAST on purpose. On the first target box,
#     `001-block-direct-ip.conf` is the `_default_` vhost: Apache treats the first
#     matching vhost for an address:port as the default for unmatched requests, so a
#     file sorting ahead of it would have silently hijacked every unmatched request on
#     the entire machine.
#   * Source log files are read-only, always. Loghound never writes, truncates, rotates
#     or deletes a log file it reads.
#
# Everything is logged to /var/log/loghound-install.log.
# =============================================================================

set -euo pipefail

# =============================================================================
# Defaults, all overridable by flag or by environment
# =============================================================================

PREFIX="${LOGHOUND_PREFIX:-/opt/loghound}"
RUN_USER="${LOGHOUND_USER:-loghound}"
LOG_GROUP="adm"

MODE="install"                       # install | upgrade | uninstall
PREFIX_EXPLICIT=0                    # set when --prefix was passed, so discovery defers
DRY_RUN=0
NONINTERACTIVE="${LOGHOUND_NONINTERACTIVE:-0}"
SKIP_TESTS=0
ASSUME_YES=0

HOSTNAME_FQDN="${LOGHOUND_HOSTNAME:-}"
WEBSERVER="${LOGHOUND_WEBSERVER:-}"          # apache | nginx | none
TLS_MODE="${LOGHOUND_TLS_MODE:-}"            # existing | certbot | selfsigned | none
TLS_CERT="${LOGHOUND_TLS_CERT:-}"
TLS_KEY="${LOGHOUND_TLS_KEY:-}"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SYSTEMD_DIR="/etc/systemd/system"
INSTALL_LOG="/var/log/loghound-install.log"

# The vhost filename. 'zzz-' so it sorts after every numeric- and letter-prefixed file
# already in the directory, and can therefore never become the default vhost. See the
# header comment — this one has already caused a real outage elsewhere.
VHOST_NAME="zzz-loghound.conf"

# PHP floor. 8.1 because the code uses 8.1+ syntax throughout and there is no polyfill
# layer to paper over an older runtime: it fails at parse time, not gracefully.
PHP_MIN="8.1"

# Extensions the application genuinely needs. Nothing aspirational:
#   curl     Solr HTTP, the Opensolr API, geo/ASN lookups
#   json     every wire format in the project
#   pcre     the compiled log-format parsers
#   sqlite3  var/state.db: tail offsets, open sessions, beacon staging, caches
#   mbstring safe truncation of attacker-supplied UTF-8 in the panel
REQUIRED_EXTS=(curl json pcre sqlite3 mbstring)

# How long to wait for the first document to reach Solr before reporting honestly that
# it has not.
FIRST_DOC_TIMEOUT=60

# =============================================================================
# Detected at runtime — never hardcoded
# =============================================================================

OS_FAMILY="unknown"; OS_PRETTY="unknown"
HAVE_SYSTEMD=0
PHP_BIN=""; PHP_VERSION=""
FPM_BIN=""; FPM_SERVICE=""; FPM_POOL_DIR=""; FPM_SOCK_DIR=""; FPM_SOCK=""
WEB_USER=""
APACHE_BIN=""; APACHE_SERVICE=""; APACHE_SITES_AVAIL=""; APACHE_SITES_ENABLED=""; APACHE_FLAVOUR=""
NGINX_SITES_AVAIL=""; NGINX_SITES_ENABLED=""

# =============================================================================
# Rollback bookkeeping
# =============================================================================

# Every path this run created, so a failure can undo exactly what it did and nothing
# more. Populated by track_created().
declare -a CREATED_PATHS=()
declare -a ENABLED_UNITS=()
APACHE_SITE_ENABLED_BY_US=0
ROLLBACK_ARMED=0
STATE_SNAPSHOT=""

# =============================================================================
# Output
# =============================================================================

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_DIM=$'\033[90m'
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_DIM=''
fi

# Append a plain (uncoloured) line to the install log. Escape codes in a log file make it
# unreadable in an editor and unsearchable with grep, so colour never goes in there.
logfile() {
    if [[ -w "$(dirname "$INSTALL_LOG")" ]] || [[ -w "$INSTALL_LOG" ]]; then
        printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "$INSTALL_LOG" 2>/dev/null || true
    fi
}

step()  { printf '\n%s==>%s %s%s%s\n' "$C_BOLD" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; logfile "== $1"; }
say()   { printf '    %s\n' "$1"; logfile "   $1"; }
ok()    { printf '    %sPASS%s  %s\n' "$C_GREEN" "$C_RESET" "$1"; logfile "PASS $1"; }
fail()  { printf '    %sFAIL%s  %s\n' "$C_RED" "$C_RESET" "$1" >&2; logfile "FAIL $1"; }
warn()  { printf '    %sWARN%s  %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; logfile "WARN $1"; }
skip()  { printf '    %sskip  %s%s\n' "$C_DIM" "$1" "$C_RESET"; logfile "skip $1"; }
info()  { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_RESET"; logfile "     $1"; }

die() {
    printf '\n%sERROR%s %s\n\n' "$C_RED" "$C_RESET" "$1" >&2
    logfile "ERROR $1"
    exit 1
}

# Execute a command, or describe it under --dry-run.
run() {
    logfile "RUN  $*"
    if (( DRY_RUN )); then
        printf '    %sDRY-RUN%s %s\n' "$C_DIM" "$C_RESET" "$*"
        return 0
    fi
    "$@"
}

# Write a file, or describe it under --dry-run. Content on stdin.
# ALWAYS refuses to clobber: callers must have checked for existence first, and this is
# the second lock on that door.
write_file() {
    local path="$1" mode="${2:-0644}"
    if [[ -e "$path" ]]; then
        die "Refusing to overwrite an existing file: $path"
    fi
    logfile "WRITE $path (mode $mode)"
    if (( DRY_RUN )); then
        printf '    %sDRY-RUN%s write %s (mode %s)\n' "$C_DIM" "$C_RESET" "$path" "$mode"
        cat > /dev/null
        return 0
    fi
    cat > "$path"
    chmod "$mode" "$path"
    track_created "$path"
}

# Record a path this run created, so rollback and --uninstall know about it.
track_created() {
    CREATED_PATHS+=("$1")
    logfile "CREATED $1"
    if [[ -n "$STATE_SNAPSHOT" ]] && (( ! DRY_RUN )); then
        printf 'created %s\n' "$1" >> "$STATE_SNAPSHOT" 2>/dev/null || true
    fi
}

# Ask a yes/no question. Honours --non-interactive and --yes.
confirm() {
    local q="$1" default="${2:-n}"
    if (( ASSUME_YES )); then say "$q -> yes (--yes)"; return 0; fi
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        say "$q -> $default (non-interactive default)"
        [[ "$default" == "y" ]]
        return
    fi
    local hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
    local answer
    read -r -p "    $q $hint " answer </dev/tty || answer=""
    answer="${answer,,}"
    [[ -z "$answer" ]] && answer="$default"
    [[ "$answer" == "y" || "$answer" == "yes" ]]
}

# Ask for a value. Honours --non-interactive (returns the default).
ask() {
    local q="$1" default="${2:-}"
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        printf '%s' "$default"
        return
    fi
    local answer
    read -r -p "    $q${default:+ [$default]}: " answer </dev/tty || answer=""
    printf '%s' "${answer:-$default}"
}

usage() {
    cat <<'USAGE'

Loghound installer — bare box to working install, in one command.

  sudo ./install/install.sh [options]

Modes
  (default)             full install
  --upgrade             refresh code in place; config/loghound.php and var/ untouched
  --uninstall           reverse everything, prompting before deleting any data

Options
  --dry-run             print every action and change nothing. Do this first.
  --non-interactive     answer every prompt from LOGHOUND_* env vars or defaults
  --yes                 assume yes for confirmations (still refuses to overwrite files)
  --prefix DIR          install root (default /opt/loghound; also --prefix=DIR,
                        also the LOGHOUND_PREFIX environment variable).
                        Anywhere is fine — /srv/loghound, /var/www/loghound —
                        and every generated artefact follows it: the vhost
                        DocumentRoot, the FPM pool's open_basedir and session
                        path, the systemd units, and the deny rules.
                        If the prefix is a git working copy of this repo,
                        --upgrade does a fast-forward pull in place instead of
                        copying files.
  --user NAME           system user to run as (default loghound)
  --hostname FQDN       the panel's hostname, e.g. loghound.example.com
  --webserver apache|nginx|none
  --tls-mode existing|certbot|selfsigned|none
  --tls-cert PATH       with --tls-mode existing
  --tls-key PATH        with --tls-mode existing
  --skip-tests          do not run the test suite
  -h, --help

Environment overrides (for --non-interactive / Ansible / CI)
  LOGHOUND_PREFIX LOGHOUND_USER LOGHOUND_HOSTNAME LOGHOUND_WEBSERVER
  LOGHOUND_TLS_MODE LOGHOUND_TLS_CERT LOGHOUND_TLS_KEY
  plus every LOGHOUND_* variable bin/loghound-setup understands — run
  `bin/loghound-setup --help` or read the header of that file for the full list
  (panel credentials, Solr mode, Opensolr email/API key/region, privacy mode,
  retention). The API key is never echoed and never written to the install log.

What it never does
  - modify an existing vhost, FPM pool, cron entry, service or any file it did not create
  - restart (as opposed to reload) your web server or PHP-FPM
  - write to, truncate, rotate or delete any log file it reads
  - deploy a TLS certificate it has not verified as trusted and key-matched

USAGE
}

# =============================================================================
# Arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)          DRY_RUN=1; shift ;;
        --upgrade)          MODE="upgrade"; shift ;;
        --uninstall)        MODE="uninstall"; shift ;;
        --non-interactive)  NONINTERACTIVE=1; shift ;;
        --yes|-y)           ASSUME_YES=1; shift ;;
        --skip-tests)       SKIP_TESTS=1; shift ;;
        # Both spellings are accepted for every value flag: "--prefix /srv/loghound"
        # and "--prefix=/srv/loghound". People type both, and an installer that
        # rejects one of them for no reason is an installer people stop trusting.
        --prefix)           PREFIX="${2:?--prefix needs a directory}"; PREFIX_EXPLICIT=1; shift 2 ;;
        --prefix=*)         PREFIX="${1#*=}"; PREFIX_EXPLICIT=1; shift ;;
        --user)             RUN_USER="${2:?--user needs a name}"; shift 2 ;;
        --user=*)           RUN_USER="${1#*=}"; shift ;;
        --hostname)         HOSTNAME_FQDN="${2:?--hostname needs an FQDN}"; shift 2 ;;
        --hostname=*)       HOSTNAME_FQDN="${1#*=}"; shift ;;
        --webserver)        WEBSERVER="${2:?--webserver needs apache|nginx|none}"; shift 2 ;;
        --webserver=*)      WEBSERVER="${1#*=}"; shift ;;
        --tls-mode)         TLS_MODE="${2:?--tls-mode needs a value}"; shift 2 ;;
        --tls-mode=*)       TLS_MODE="${1#*=}"; shift ;;
        --tls-cert)         TLS_CERT="${2:?--tls-cert needs a path}"; shift 2 ;;
        --tls-cert=*)       TLS_CERT="${1#*=}"; shift ;;
        --tls-key)          TLS_KEY="${2:?--tls-key needs a path}"; shift 2 ;;
        --tls-key=*)        TLS_KEY="${1#*=}"; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  usage; die "Unknown option: $1" ;;
    esac
done

# Normalise the prefix: absolute, no trailing slash. Everything downstream — the vhost
# DocumentRoot, the FPM open_basedir, the systemd ReadWritePaths, the deny rules — is
# built by string concatenation from this, and "/srv/loghound/" would produce "//".
PREFIX="${PREFIX%/}"
[[ "$PREFIX" = /* ]] || PREFIX="$(cd "$(dirname "$PREFIX")" 2>/dev/null && pwd)/$(basename "$PREFIX")"
[[ -z "$PREFIX" || "$PREFIX" == "/" ]] && { echo "Refusing to install to '/'." >&2; exit 1; }

# stdin is not a terminal (piped install, CI): prompting would hang forever.
if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
    NONINTERACTIVE=1
fi

printf '%sLoghound installer%s  (%s)\n' "$C_BOLD" "$C_RESET" "$MODE"
(( DRY_RUN )) && printf '%sDRY RUN — nothing will be changed.%s\n' "$C_YELLOW" "$C_RESET"

if (( EUID == 0 )) && (( ! DRY_RUN )); then
    : > /dev/null
    touch "$INSTALL_LOG" 2>/dev/null || true
    chmod 0640 "$INSTALL_LOG" 2>/dev/null || true
fi
logfile "===== loghound installer start: mode=$MODE prefix=$PREFIX dry_run=$DRY_RUN ====="

# =============================================================================
# Rollback
# =============================================================================

# Undo exactly what this run created, and nothing else. Armed only once we start making
# changes, so a preflight failure cannot trigger it.
rollback() {
    local rc=$?
    if (( ! ROLLBACK_ARMED )) || (( DRY_RUN )); then
        exit $rc
    fi
    printf '\n%sRolling back the changes this run made.%s\n' "$C_YELLOW" "$C_RESET" >&2
    logfile "ROLLBACK start"

    # Disable the site first, so the web server stops referring to files we remove.
    if (( APACHE_SITE_ENABLED_BY_US )) && [[ -n "$APACHE_SITES_ENABLED" ]]; then
        rm -f "$APACHE_SITES_ENABLED/$VHOST_NAME" 2>/dev/null || true
    fi

    local p
    for (( idx=${#CREATED_PATHS[@]}-1 ; idx>=0 ; idx-- )); do
        p="${CREATED_PATHS[idx]}"
        # Only ever remove files, never directory trees: a directory we "created" might
        # already have had something in it.
        if [[ -f "$p" || -L "$p" ]]; then
            rm -f "$p" 2>/dev/null || true
            logfile "ROLLBACK removed $p"
        fi
    done

    local u
    for u in "${ENABLED_UNITS[@]:-}"; do
        [[ -z "$u" ]] && continue
        systemctl disable --now "$u" >/dev/null 2>&1 || true
    done
    systemctl daemon-reload >/dev/null 2>&1 || true

    # Prove the host is back where it started rather than asserting it.
    if [[ -n "$APACHE_BIN" ]]; then
        if "$APACHE_BIN" -t >/dev/null 2>&1; then
            printf '    %sPASS%s  web server configuration is valid again\n' "$C_GREEN" "$C_RESET" >&2
        else
            printf '    %sFAIL%s  web server configuration is STILL invalid — look at it now\n' "$C_RED" "$C_RESET" >&2
        fi
    elif command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            printf '    %sPASS%s  web server configuration is valid again\n' "$C_GREEN" "$C_RESET" >&2
        else
            printf '    %sFAIL%s  web server configuration is STILL invalid — look at it now\n' "$C_RED" "$C_RESET" >&2
        fi
    fi

    printf '    Full log: %s\n\n' "$INSTALL_LOG" >&2
    logfile "ROLLBACK done"
    exit $rc
}
trap rollback ERR INT TERM

# =============================================================================
# Platform detection — nothing below this line is hardcoded
# =============================================================================

detect_platform() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_PRETTY="${PRETTY_NAME:-${NAME:-unknown}}"
        case "${ID:-}${ID_LIKE:-}" in
            *debian*|*ubuntu*) OS_FAMILY="debian" ;;
            *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) OS_FAMILY="rhel" ;;
        esac
    fi

    command -v systemctl >/dev/null 2>&1 && HAVE_SYSTEMD=1

    PHP_BIN="$(command -v php || true)"
    if [[ -n "$PHP_BIN" ]]; then
        PHP_VERSION="$("$PHP_BIN" -r 'echo PHP_VERSION;' 2>/dev/null || echo '')"
    fi

    # ---- PHP-FPM: binary, service, pool directory, socket directory -------
    # Never assume php8.5-fpm vs php-fpm: find whatever is actually installed.
    local c
    for c in php-fpm "php-fpm${PHP_VERSION%%.*}" $(compgen -c 'php-fpm' 2>/dev/null | sort -u); do
        if command -v "$c" >/dev/null 2>&1; then FPM_BIN="$(command -v "$c")"; break; fi
    done
    if [[ -z "$FPM_BIN" ]]; then
        for c in /usr/sbin/php-fpm* /usr/bin/php-fpm*; do
            [[ -x "$c" ]] && { FPM_BIN="$c"; break; }
        done
    fi

    if (( HAVE_SYSTEMD )); then
        FPM_SERVICE="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
            | awk '{print $1}' | grep -E '^php[0-9.]*-fpm\.service$' | sort | tail -1 || true)"
    fi

    for c in /etc/php/*/fpm/pool.d /etc/php-fpm.d /usr/local/etc/php-fpm.d; do
        [[ -d "$c" ]] && FPM_POOL_DIR="$c"
    done

    for c in /run/php /run/php-fpm /var/run/php /var/run/php-fpm; do
        [[ -d "$c" ]] && { FPM_SOCK_DIR="$c"; break; }
    done
    [[ -z "$FPM_SOCK_DIR" ]] && FPM_SOCK_DIR="/run/php"
    FPM_SOCK="$FPM_SOCK_DIR/loghound-fpm.sock"

    # ---- Apache: Debian-style vs RHEL-style -------------------------------
    if command -v apache2ctl >/dev/null 2>&1; then
        APACHE_BIN="$(command -v apache2ctl)"; APACHE_SERVICE="apache2"; APACHE_FLAVOUR="debian"
        APACHE_SITES_AVAIL="/etc/apache2/sites-available"
        APACHE_SITES_ENABLED="/etc/apache2/sites-enabled"
    elif command -v apachectl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        APACHE_BIN="$(command -v apachectl || command -v httpd)"
        APACHE_SERVICE="httpd"; APACHE_FLAVOUR="rhel"
        # RHEL has no sites-available/a2ensite: a file in conf.d is live immediately.
        APACHE_SITES_AVAIL="/etc/httpd/conf.d"
        APACHE_SITES_ENABLED="/etc/httpd/conf.d"
    fi

    # ---- nginx ------------------------------------------------------------
    if command -v nginx >/dev/null 2>&1; then
        if [[ -d /etc/nginx/sites-available ]]; then
            NGINX_SITES_AVAIL="/etc/nginx/sites-available"
            NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
        elif [[ -d /etc/nginx/conf.d ]]; then
            NGINX_SITES_AVAIL="/etc/nginx/conf.d"
            NGINX_SITES_ENABLED="/etc/nginx/conf.d"
        fi
    fi

    # ---- Which web server are we installing for? --------------------------
    if [[ -z "$WEBSERVER" ]]; then
        if [[ -n "$APACHE_BIN" ]] && [[ -n "$NGINX_SITES_AVAIL" ]]; then
            say "Both Apache and nginx are installed on this machine."
            WEBSERVER="$(ask 'Serve the Loghound panel with which? (apache/nginx/none)' 'apache')"
        elif [[ -n "$APACHE_BIN" ]]; then
            WEBSERVER="apache"
        elif [[ -n "$NGINX_SITES_AVAIL" ]]; then
            WEBSERVER="nginx"
        else
            WEBSERVER="none"
        fi
    fi

    # ---- The web server's runtime user ------------------------------------
    # Detected, never assumed: this is the identity that has to traverse $PREFIX to
    # reach public/, and getting it wrong produces Apache's famously opaque
    # "AH00035: access denied because search permissions are missing on a component
    # of the path".
    case "$WEBSERVER" in
        apache)
            if [[ -r /etc/apache2/envvars ]]; then
                WEB_USER="$(awk -F= '/^export APACHE_RUN_USER/{gsub(/[ \t]/,"",$2); print $2}' /etc/apache2/envvars | tail -1)"
            fi
            if [[ -z "$WEB_USER" ]] && [[ -n "$APACHE_BIN" ]]; then
                WEB_USER="$("$APACHE_BIN" -S 2>/dev/null | awk -F'"' '/User:/{print $2}' | head -1)"
            fi
            if [[ -z "$WEB_USER" ]] && [[ -r /etc/httpd/conf/httpd.conf ]]; then
                WEB_USER="$(awk '/^[[:space:]]*User[[:space:]]/{print $2}' /etc/httpd/conf/httpd.conf | tail -1)"
            fi
            ;;
        nginx)
            if [[ -r /etc/nginx/nginx.conf ]]; then
                WEB_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(/;/,"",$2); print $2}' /etc/nginx/nginx.conf | head -1)"
            fi
            ;;
    esac

    # Last resort: the first of the usual suspects that actually exists.
    if [[ -z "$WEB_USER" ]] && [[ "$WEBSERVER" != "none" ]]; then
        local u
        for u in www-data apache nginx http; do
            if getent passwd "$u" >/dev/null 2>&1; then WEB_USER="$u"; break; fi
        done
    fi
}

# =============================================================================
# PREFLIGHT — everything is checked BEFORE the first change
# =============================================================================

PREFLIGHT_FAILED=0

# Record a pass/fail row in the preflight table.
check() {
    local state="$1" label="$2" remedy="${3:-}"
    if [[ "$state" == "pass" ]]; then
        ok "$label"
    else
        fail "$label"
        [[ -n "$remedy" ]] && info "      $remedy"
        PREFLIGHT_FAILED=1
    fi
}

preflight() {
    step "Preflight"

    # ---- root ---------------------------------------------------------
    if (( EUID == 0 )); then
        check pass "running as root"
    elif (( DRY_RUN )); then
        check pass "not root, but --dry-run changes nothing"
    else
        check fail "must run as root" "re-run with sudo, or use --dry-run first"
    fi

    # ---- OS -----------------------------------------------------------
    case "$OS_FAMILY" in
        debian) check pass "$OS_PRETTY (Debian family)" ;;
        rhel)   check pass "$OS_PRETTY (RHEL family)" ;;
        *)      warn "unrecognised distribution: $OS_PRETTY — continuing, but package"
                info "      names and paths may need doing by hand" ;;
    esac

    # ---- PHP ----------------------------------------------------------
    if [[ -z "$PHP_BIN" ]]; then
        local pkg="php-cli php-curl php-sqlite3 php-mbstring"
        [[ "$OS_FAMILY" == "rhel" ]] && pkg="php-cli php-curl php-pdo php-mbstring"
        check fail "php-cli not found" "install it: $( [[ "$OS_FAMILY" == "rhel" ]] && echo dnf || echo apt-get ) install -y $pkg"
    elif "$PHP_BIN" -r 'exit(version_compare(PHP_VERSION, "'"$PHP_MIN"'", ">=") ? 0 : 1);'; then
        check pass "PHP $PHP_VERSION >= $PHP_MIN  ($PHP_BIN)"
    else
        check fail "PHP $PHP_VERSION is older than $PHP_MIN" \
            "Loghound has no polyfill layer; an older PHP fails at parse time"
    fi

    # ---- extensions ---------------------------------------------------
    if [[ -n "$PHP_BIN" ]]; then
        local ext pkgname
        for ext in "${REQUIRED_EXTS[@]}"; do
            if "$PHP_BIN" -r 'exit(extension_loaded("'"$ext"'") ? 0 : 1);'; then
                check pass "ext-$ext"
            else
                case "$OS_FAMILY:$ext" in
                    rhel:sqlite3) pkgname="php-pdo" ;;
                    *:pcre)       pkgname="php-cli (pcre is built in; a missing one means a broken build)" ;;
                    *)            pkgname="php-$ext" ;;
                esac
                check fail "ext-$ext missing" "install: $( [[ "$OS_FAMILY" == "rhel" ]] && echo dnf || echo apt-get ) install -y $pkgname"
            fi
        done
    fi

    # ---- scheduler ----------------------------------------------------
    if (( HAVE_SYSTEMD )); then
        check pass "systemd present"
    elif command -v crontab >/dev/null 2>&1; then
        warn "no systemd; cron fallbacks will be installed for score and retention"
        info "      the ingest daemon will need your own supervisor — see docs/INSTALL.md"
    else
        check fail "neither systemd nor cron is available" "Loghound needs one of them"
    fi

    # ---- log-read group -----------------------------------------------
    if getent group "$LOG_GROUP" >/dev/null 2>&1; then
        check pass "group '$LOG_GROUP' exists (grants read access to /var/log)"
    else
        warn "group '$LOG_GROUP' does not exist"
        info "      Loghound will not be able to read /var/log until you grant access"
        LOG_GROUP=""
    fi

    # ---- source tree --------------------------------------------------
    local missing=0 required
    for required in bin/loghound-tail bin/loghound-setup src/autoload.php tests/run.php; do
        [[ -e "$SRC_DIR/$required" ]] || { fail "missing from the checkout: $required"; missing=1; }
    done
    if (( missing )); then
        PREFLIGHT_FAILED=1
    else
        check pass "source tree complete ($SRC_DIR)"
    fi

    # ---- writability --------------------------------------------------
    local parent; parent="$(dirname "$PREFIX")"
    if [[ -w "$parent" ]] || (( DRY_RUN )); then
        check pass "can write to $parent"
    else
        check fail "cannot write to $parent" "run as root"
    fi

    # ---- web server ---------------------------------------------------
    case "$WEBSERVER" in
        apache) check pass "Apache detected ($APACHE_FLAVOUR style, service '$APACHE_SERVICE', runs as '$WEB_USER')" ;;
        nginx)  check pass "nginx detected (runs as '$WEB_USER')" ;;
        none)   warn "no web server selected — the panel will not be served"
                info "      the ingest daemon and timers still install and run" ;;
        *)      check fail "unknown --webserver value: $WEBSERVER" "use apache, nginx or none" ;;
    esac

    # ---- PHP-FPM ------------------------------------------------------
    if [[ "$WEBSERVER" != "none" ]]; then
        if [[ -n "$FPM_POOL_DIR" ]]; then
            check pass "PHP-FPM pool directory: $FPM_POOL_DIR"
        else
            check fail "no PHP-FPM pool directory found" \
                "install php-fpm: $( [[ "$OS_FAMILY" == "rhel" ]] && echo 'dnf install -y php-fpm' || echo 'apt-get install -y php-fpm' )"
        fi
        if (( HAVE_SYSTEMD )) && [[ -z "$FPM_SERVICE" ]]; then
            FPM_SERVICE="php-fpm.service"
            warn "could not identify the php-fpm service unit; assuming '$FPM_SERVICE'"
        fi
    fi

    # ---- Apache modules ------------------------------------------------
    if [[ "$WEBSERVER" == "apache" ]] && [[ -n "$APACHE_BIN" ]]; then
        local loaded m need_enable=()
        loaded="$("$APACHE_BIN" -M 2>/dev/null || true)"
        for m in headers rewrite proxy_fcgi ssl; do
            if grep -q "${m}_module" <<<"$loaded"; then
                check pass "apache module: $m"
            elif [[ "$APACHE_FLAVOUR" == "debian" ]] && command -v a2enmod >/dev/null 2>&1; then
                need_enable+=("$m")
                warn "apache module '$m' is not loaded — it will be enabled"
            else
                check fail "apache module '$m' is not loaded" \
                    "load it in /etc/httpd/conf.modules.d/ and re-run"
            fi
        done
        APACHE_MODULES_TO_ENABLE=("${need_enable[@]:-}")
    fi

    # ---- collisions ----------------------------------------------------
    local collisions=() unit target
    for unit in loghound-tail.service loghound-score.service loghound-score.timer \
                loghound-retention.service loghound-retention.timer; do
        target="$SYSTEMD_DIR/$unit"
        if [[ -e "$target" ]] && ! cmp -s "$SRC_DIR/install/$unit" "$target"; then
            collisions+=("$target")
        fi
    done
    [[ -n "$FPM_POOL_DIR" && -e "$FPM_POOL_DIR/loghound.conf" ]] && collisions+=("$FPM_POOL_DIR/loghound.conf")
    if [[ "$WEBSERVER" == "apache" && -n "$APACHE_SITES_AVAIL" && -e "$APACHE_SITES_AVAIL/$VHOST_NAME" ]]; then
        collisions+=("$APACHE_SITES_AVAIL/$VHOST_NAME")
    fi
    if [[ "$WEBSERVER" == "nginx" && -n "$NGINX_SITES_AVAIL" && -e "$NGINX_SITES_AVAIL/$VHOST_NAME" ]]; then
        collisions+=("$NGINX_SITES_AVAIL/$VHOST_NAME")
    fi

    if (( ${#collisions[@]} > 0 )); then
        if [[ "$MODE" == "upgrade" ]]; then
            info "existing Loghound files found — expected for --upgrade"
        else
            for target in "${collisions[@]}"; do
                fail "already exists: $target"
            done
            info "      This installer never replaces a file it did not write."
            info "      Remove them, or run --uninstall first, or use --upgrade."
            PREFLIGHT_FAILED=1
        fi
    else
        check pass "no file collisions"
    fi

    if (( PREFLIGHT_FAILED )); then
        printf '\n'
        die "Preflight failed. Nothing has been changed. Fix the items marked FAIL above."
    fi

    printf '\n'
    ok "Preflight passed — safe to proceed"
}

# =============================================================================
# Pre-install snapshot
# =============================================================================

snapshot_state() {
    STATE_SNAPSHOT="$PREFIX/var/install-state.txt"
    (( DRY_RUN )) && { STATE_SNAPSHOT=""; return 0; }

    mkdir -p "$PREFIX/var"
    {
        printf '# Loghound pre-install snapshot: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# Everything below existed BEFORE this run. Anything not listed here that\n'
        printf '# Loghound created is listed as "created" further down, and --uninstall\n'
        printf '# removes exactly those.\n'
        printf 'prefix %s\n' "$PREFIX"
        printf 'user %s\n' "$RUN_USER"
        printf 'webserver %s\n' "$WEBSERVER"
        printf 'web_user %s\n' "$WEB_USER"
        [[ -n "$APACHE_SITES_ENABLED" ]] && { printf '# apache sites-enabled before:\n'; ls -1 "$APACHE_SITES_ENABLED" 2>/dev/null | sed 's/^/#   /'; }
        [[ -n "$NGINX_SITES_ENABLED"  ]] && { printf '# nginx sites-enabled before:\n';  ls -1 "$NGINX_SITES_ENABLED" 2>/dev/null | sed 's/^/#   /'; }
        [[ -n "$FPM_POOL_DIR"         ]] && { printf '# fpm pool.d before:\n';           ls -1 "$FPM_POOL_DIR" 2>/dev/null | sed 's/^/#   /'; }
        printf '# systemd units before:\n'
        ls -1 "$SYSTEMD_DIR" 2>/dev/null | grep -i loghound | sed 's/^/#   /' || true
    } > "$STATE_SNAPSHOT"
    chmod 0640 "$STATE_SNAPSHOT"
    ok "Recorded pre-install state to $STATE_SNAPSHOT"
}

# =============================================================================
# System user
# =============================================================================

create_user() {
    step "System user"

    if id -u "$RUN_USER" >/dev/null 2>&1; then
        ok "user '$RUN_USER' already exists"
    else
        local shell=/usr/sbin/nologin
        [[ "$OS_FAMILY" == "rhel" ]] && shell=/sbin/nologin
        run useradd --system --home-dir "$PREFIX" --no-create-home \
                    --shell "$shell" --comment "Loghound" "$RUN_USER"
        ok "created system user '$RUN_USER' (no login shell, no home directory)"
    fi

    if [[ -n "$LOG_GROUP" ]]; then
        if id -nG "$RUN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$LOG_GROUP"; then
            ok "'$RUN_USER' is already in group '$LOG_GROUP'"
        else
            # usermod -aG only ADDS; it can never remove the user from anything.
            run usermod -aG "$LOG_GROUP" "$RUN_USER"
            ok "added '$RUN_USER' to group '$LOG_GROUP'"
        fi
    fi
}

# =============================================================================
# Files and permissions
# =============================================================================

install_files() {
    step "Application files"

    if [[ "$(cd "$PREFIX" 2>/dev/null && pwd || echo)" == "$SRC_DIR" ]]; then
        skip "prefix is the checkout itself; no files copied"
        return 0
    fi

    run mkdir -p "$PREFIX"

    # Copy each top-level item to a .new sibling, then swap. A half-finished cp cannot
    # leave a broken tree live, and config/loghound.php plus var/ are never in the set.
    local item
    for item in bin src public solr docs install tests SPEC.md README.md LICENSE CHANGELOG.md CONTRIBUTING.md; do
        [[ -e "$SRC_DIR/$item" ]] || continue
        run rm -rf "$PREFIX/$item.new"
        run cp -a "$SRC_DIR/$item" "$PREFIX/$item.new"
    done
    for item in bin src public solr docs install tests SPEC.md README.md LICENSE CHANGELOG.md CONTRIBUTING.md; do
        [[ -e "$PREFIX/$item.new" ]] || continue
        run rm -rf "$PREFIX/$item"
        run mv "$PREFIX/$item.new" "$PREFIX/$item"
    done

    # config/ is copied only for its example file, and only when it does not exist —
    # config/loghound.php holds the API key and the HMAC secret and is never touched.
    run mkdir -p "$PREFIX/config"
    if [[ -f "$SRC_DIR/config/loghound.example.php" ]] && [[ ! -f "$PREFIX/config/loghound.example.php" ]]; then
        run cp -a "$SRC_DIR/config/loghound.example.php" "$PREFIX/config/loghound.example.php"
    fi

    ok "installed application files into $PREFIX"
}

# -----------------------------------------------------------------------------
# Permissions.
#
# THIS IS THE BLOCK THAT DECIDES WHETHER THE PANEL WORKS AT ALL. The layout below was
# arrived at by hitting the failure in production:
#
#   $PREFIX at 0750 owned by the service user makes Apache fail with
#     "AH00035: access denied because search permissions are missing on a
#      component of the path /opt/loghound/public/index.php"
#
# because the web server user cannot traverse $PREFIX to reach public/. The obvious fix —
# adding www-data to the loghound group — is WRONG on a live box: supplementary groups are
# read once, at process start, so it requires a full Apache RESTART rather than a reload,
# and a restart drops in-flight requests on every other site on the machine.
#
# So the traversal is granted by MODE instead:
#
#   $PREFIX        0751  world may TRAVERSE, may not LIST
#   public/        0755  world-readable: it holds no secrets, and nginx/Apache serve
#                        b.js and assets/ directly as themselves, not through FPM
#   config/        0700  owner only. The web server user must NOT be able to read this.
#   var/           0750  service user only
#   src/ bin/      0750  root-owned code, readable by the service group, world nothing
# -----------------------------------------------------------------------------
fix_permissions() {
    step "Permissions"

    run mkdir -p "$PREFIX/var" "$PREFIX/config"

    # Code is root-owned and only READ by the service user: a compromise of the daemon
    # must not be able to rewrite the code that runs next time.
    run chown -R root:"$RUN_USER" "$PREFIX/bin" "$PREFIX/src" "$PREFIX/public" "$PREFIX/solr" 2>/dev/null || true
    run chown -R "$RUN_USER":"$RUN_USER" "$PREFIX/var" "$PREFIX/config"

    run chmod 0751 "$PREFIX"
    run chmod 0700 "$PREFIX/config"
    run chmod 0750 "$PREFIX/var"

    # PHP session files, when auth.mode is 'session'. 0700 because a session file IS a
    # login: anything that can read one can impersonate the operator. Kept inside var/
    # rather than the shared /var/lib/php/sessions, where any other FPM pool on the box
    # could read it.
    run mkdir -p "$PREFIX/var/sessions"
    run chown "$RUN_USER":"$RUN_USER" "$PREFIX/var/sessions"
    run chmod 0700 "$PREFIX/var/sessions"

    local d
    for d in bin src solr; do
        [[ -d "$PREFIX/$d" ]] || continue
        run find "$PREFIX/$d" -type d -exec chmod 0750 {} +
        run find "$PREFIX/$d" -type f -exec chmod 0640 {} +
    done
    local cmd
    for cmd in loghound-tail loghound-setup loghound-score loghound-retention; do
        [[ -e "$PREFIX/bin/$cmd" ]] && run chmod 0750 "$PREFIX/bin/$cmd"
    done

    if [[ -d "$PREFIX/public" ]]; then
        run find "$PREFIX/public" -type d -exec chmod 0755 {} +
        run find "$PREFIX/public" -type f -exec chmod 0644 {} +
    fi

    # docs/, tests/, install/ are not served; keep them off the world.
    for d in docs tests install; do
        [[ -d "$PREFIX/$d" ]] && run chmod -R o-rwx "$PREFIX/$d"
    done

    if [[ -f "$PREFIX/config/loghound.php" ]]; then
        run chmod 0640 "$PREFIX/config/loghound.php"
        run chown "$RUN_USER":"$RUN_USER" "$PREFIX/config/loghound.php"
    fi

    ok "$PREFIX 0751 (traverse, no listing)"
    ok "$PREFIX/public 0755 (world-readable; holds no secrets)"
    ok "$PREFIX/config 0700 and $PREFIX/var/sessions 0700 (owner only)"
    ok "$PREFIX/var 0750, and src/ bin/ solr/ 0750 (root-owned code, group-readable)"

    # ---- convenience symlinks ----
    for cmd in loghound-tail loghound-setup loghound-score loghound-retention; do
        [[ -e "$PREFIX/bin/$cmd" ]] || continue
        if [[ -e "/usr/local/bin/$cmd" ]] && [[ ! -L "/usr/local/bin/$cmd" ]]; then
            warn "/usr/local/bin/$cmd exists and is not a symlink — leaving it alone"
            continue
        fi
        run ln -sfn "$PREFIX/bin/$cmd" "/usr/local/bin/$cmd"
    done
}

# Run a test as another user, quietly. Returns the command's exit status.
as_user() {
    local u="$1"; shift
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$u" -- "$@" >/dev/null 2>&1
    elif command -v sudo >/dev/null 2>&1; then
        sudo -n -u "$u" -- "$@" >/dev/null 2>&1
    else
        return 2
    fi
}

# -----------------------------------------------------------------------------
# Verify, do not assume. Every permission claim above is now tested AS the user that
# has to satisfy it. This is the difference between an installer that works and one
# that leaves you reading Apache error logs at midnight.
# -----------------------------------------------------------------------------
verify_permissions() {
    step "Permission verification"

    if (( DRY_RUN )); then
        skip "cannot verify permissions under --dry-run"
        return 0
    fi

    local verify_failed=0

    # ---- the service user ----
    if as_user "$RUN_USER" test -r "$PREFIX/src/autoload.php"; then
        ok "$RUN_USER can read the application code"
    else
        fail "$RUN_USER cannot read $PREFIX/src/autoload.php"; verify_failed=1
    fi
    if as_user "$RUN_USER" test -w "$PREFIX/var"; then
        ok "$RUN_USER can write to var/"
    else
        fail "$RUN_USER cannot write to $PREFIX/var"; verify_failed=1
    fi

    # ---- the web server user: THE THREE CHECKS THAT MATTER ----
    #
    # These three, run as the web server user itself, are the difference between a
    # working panel and an afternoon spent reading Apache error logs:
    #
    #   test -x $PREFIX                    must PASS  (else AH00035)
    #   test -r $PREFIX/public/index.php   must PASS  (else 403 on every page)
    #   test -r $PREFIX/config             must FAIL  (else the secrets are exposed)
    #
    # All three are printed, including the inverted one, because "it did not fail" is
    # not the same evidence as "it was checked and behaved correctly".
    if [[ "$WEBSERVER" != "none" ]] && [[ -n "$WEB_USER" ]]; then
        # THE traversal check. This is the exact failure hit in production.
        if as_user "$WEB_USER" test -x "$PREFIX"; then
            ok "$WEB_USER can traverse $PREFIX (mode 0751)"
        else
            fail "$WEB_USER CANNOT traverse $PREFIX"
            info "      This is Apache's AH00035 'search permissions are missing on a"
            info "      component of the path'. Fix: chmod 0751 $PREFIX"
            verify_failed=1
        fi

        if as_user "$WEB_USER" test -x "$PREFIX/public" && as_user "$WEB_USER" test -r "$PREFIX/public"; then
            ok "$WEB_USER can read public/"
        else
            fail "$WEB_USER cannot read $PREFIX/public"; verify_failed=1
        fi

        if [[ -f "$PREFIX/public/index.php" ]]; then
            if as_user "$WEB_USER" test -r "$PREFIX/public/index.php"; then
                ok "$WEB_USER can read public/index.php"
            else
                fail "$WEB_USER cannot read $PREFIX/public/index.php"; verify_failed=1
            fi
        fi

        # INVERTED CHECK, and the most important one on this list: the web server user
        # must NOT be able to read the secrets. If this passes, the install is wrong.
        # Test the DIRECTORY, not just the file: the config may not exist yet on a
        # first install, and a readable directory is the actual hole.
        if as_user "$WEB_USER" test -r "$PREFIX/config" || as_user "$WEB_USER" test -x "$PREFIX/config"; then
            fail "$WEB_USER CAN reach $PREFIX/config — that directory holds the Opensolr"
            info "      API key and the beacon HMAC secret. Fix: chmod 0700 $PREFIX/config"
            verify_failed=1
        else
            ok "$WEB_USER cannot reach config/ (correct — it holds the secrets)"
        fi
    fi

    # ---- the log files, actually, not theoretically ----
    local tested=0 readable=0 f
    for f in /var/log/apache2/*access*.log /var/log/httpd/*access*log /var/log/nginx/*access*.log; do
        [[ -f "$f" ]] || continue
        tested=$((tested+1))
        if as_user "$RUN_USER" test -r "$f"; then
            readable=$((readable+1))
        else
            warn "$RUN_USER cannot read $f"
        fi
        (( tested >= 5 )) && break
    done
    if (( tested == 0 )); then
        info "no access log files found yet to test against — setup will look again"
    elif (( readable == tested )); then
        ok "$RUN_USER can read $readable/$tested sampled access log file(s)"
    else
        fail "$RUN_USER can read only $readable of $tested sampled access log files"
        info "      Check the group and mode of your log directory:"
        info "        ls -ld /var/log/apache2 /var/log/nginx"
        info "      Loghound needs group '$LOG_GROUP' read access. Note that group"
        info "      membership added just now applies to NEW processes, which is why"
        info "      this test starts a fresh one rather than trusting id(1)."
        verify_failed=1
    fi

    if (( verify_failed )); then
        die "Permission verification failed. The items above must be fixed or the panel
      and the ingest daemon will not work. Nothing has been enabled yet."
    fi
}

# =============================================================================
# systemd units, or cron fallback
# =============================================================================

install_units() {
    step "Scheduling"

    if (( ! HAVE_SYSTEMD )); then
        install_cron_fallback
        return 0
    fi

    local unit src dst
    for unit in loghound-tail.service loghound-score.service loghound-score.timer \
                loghound-retention.service loghound-retention.timer; do
        src="$SRC_DIR/install/$unit"
        dst="$SYSTEMD_DIR/$unit"
        [[ -f "$src" ]] || { warn "missing $src"; continue; }

        if [[ -e "$dst" ]] && cmp -s "$src" "$dst"; then
            skip "$unit already installed and identical"
            continue
        fi
        if [[ -e "$dst" ]] && [[ "$MODE" != "upgrade" ]]; then
            die "Refusing to overwrite $dst (use --upgrade, or remove it first)."
        fi

        run install -m 0644 -o root -g root "$src" "$dst"
        [[ -e "$dst" ]] && track_created "$dst"

        # The shipped units name /opt/loghound and /usr/bin/php. Rewrite them so
        # --prefix and a non-standard PHP are not quietly ignored.
        # The shipped units carry the defaults; rewrite them so --prefix, a
        # non-standard PHP and --user are honoured rather than quietly ignored.
        # WorkingDirectory, ExecStart and ReadWritePaths all come from this one
        # substitution, which is why the units use the literal default throughout.
        if [[ "$PREFIX" != "/opt/loghound" ]]; then
            run sed -i "s#/opt/loghound#${PREFIX}#g" "$dst"
        fi
        if [[ "$PHP_BIN" != "/usr/bin/php" ]]; then
            run sed -i "s#/usr/bin/php#${PHP_BIN}#g" "$dst"
        fi
        if [[ "$RUN_USER" != "loghound" ]]; then
            run sed -i "s#^User=loghound\$#User=${RUN_USER}#; s#^Group=loghound\$#Group=${RUN_USER}#" "$dst"
        fi

        ok "installed $unit"
    done

    run systemctl daemon-reload
    run systemctl enable loghound-score.timer loghound-retention.timer
    ENABLED_UNITS+=(loghound-score.timer loghound-retention.timer)
    ok "enabled loghound-score.timer (60s) and loghound-retention.timer (daily)"
}

install_cron_fallback() {
    local cronfile="/etc/cron.d/loghound"
    if [[ -e "$cronfile" ]]; then
        warn "$cronfile already exists — leaving it exactly as it is"
        return 0
    fi

    write_file "$cronfile" 0644 <<CRON
# Loghound — cron fallback for a box without systemd.
#
# The scoring and retention jobs run fine on cron. The INGEST DAEMON does not: it is a
# long-running process, and cron's one-minute floor is exactly what it exists to beat.
# Run bin/loghound-tail under your own supervisor (supervisord, runit, s6, or a screen
# session if you must) and see docs/INSTALL.md.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Close idle sessions and score them, every minute.
* * * * * $RUN_USER $PHP_BIN $PREFIX/bin/loghound-score >/dev/null 2>&1

# Enforce the retention window, daily at 03:20.
20 3 * * * $RUN_USER $PHP_BIN $PREFIX/bin/loghound-retention >/dev/null 2>&1
CRON

    ok "installed cron fallback at $cronfile"
    warn "the ingest daemon needs a supervisor on this box — see docs/INSTALL.md"
}

# =============================================================================
# PHP-FPM pool
# =============================================================================

install_fpm_pool() {
    [[ "$WEBSERVER" == "none" ]] && { skip "no web server; no FPM pool needed"; return 0; }

    step "PHP-FPM pool"

    if [[ -z "$FPM_POOL_DIR" ]]; then
        warn "no PHP-FPM pool directory found; skipping"
        return 0
    fi

    local pool="$FPM_POOL_DIR/loghound.conf"
    if [[ -e "$pool" ]]; then
        warn "$pool already exists — leaving it exactly as it is"
        info "      compare it against $PREFIX/install/php-fpm-pool.conf.example yourself"
        return 0
    fi

    run mkdir -p "$FPM_SOCK_DIR"

    # A DEDICATED pool. Never the shared www-data pool: config/loghound.php holds the
    # Opensolr API key and the beacon HMAC secret, and running the panel in a shared pool
    # would mean every other site on this machine executes as a user that can read it.
    write_file "$pool" 0644 <<POOL
; Loghound — dedicated PHP-FPM pool. Generated by install/install.sh.
; See $PREFIX/install/php-fpm-pool.conf.example for the annotated version.
[loghound]
user  = $RUN_USER
group = $RUN_USER

listen       = $FPM_SOCK
listen.owner = $WEB_USER
listen.group = $WEB_USER
listen.mode  = 0660

pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 30s
pm.max_requests = 500

php_admin_value[memory_limit]        = 128M
php_admin_value[post_max_size]       = 1M
php_admin_value[upload_max_filesize] = 1M
php_admin_value[max_execution_time]  = 60
php_admin_flag[file_uploads]         = off

php_admin_value[open_basedir]        = $PREFIX:/tmp
php_admin_value[disable_functions]   = exec,passthru,shell_exec,system,proc_open,popen,proc_nice,dl,pcntl_exec,pcntl_fork
php_admin_flag[expose_php]           = off
php_admin_flag[display_errors]       = off
php_admin_flag[display_startup_errors] = off
php_admin_flag[log_errors]           = on
php_admin_value[error_log]           = $PREFIX/var/php-error.log

php_admin_value[session.save_path]       = $PREFIX/var/sessions
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_secure]   = 1
php_admin_value[session.cookie_samesite] = Lax
php_admin_value[session.use_strict_mode] = 1

slowlog = $PREFIX/var/fpm-slow.log
request_slowlog_timeout = 10s

clear_env = yes
POOL

    ok "created $pool (socket $FPM_SOCK, runs as $RUN_USER)"

    # VALIDATE BEFORE RELOADING. A syntax error in a pool file takes php-fpm down for
    # every site on the box the moment it is reloaded.
    if [[ -n "$FPM_BIN" ]]; then
        if (( DRY_RUN )); then
            skip "would run: $FPM_BIN -t"
        elif "$FPM_BIN" -t >/dev/null 2>&1; then
            ok "php-fpm configuration is valid"
        else
            "$FPM_BIN" -t 2>&1 | sed 's/^/      /' >&2 || true
            die "php-fpm rejected the new pool. It has been left in place for you to read,
      but php-fpm has NOT been reloaded, so nothing is broken. Remove it with:
        rm $pool"
        fi
    else
        warn "could not find the php-fpm binary to validate the pool"
    fi

    # RELOAD, never restart: a restart kills in-flight requests for every other site.
    if (( HAVE_SYSTEMD )) && [[ -n "$FPM_SERVICE" ]]; then
        run systemctl reload "$FPM_SERVICE"
        ok "reloaded $FPM_SERVICE (reload, not restart — other sites undisturbed)"
    else
        warn "reload php-fpm yourself so the new pool starts serving"
    fi
}

# =============================================================================
# TLS
# =============================================================================

# Is this certificate chain trusted by the system store?
#
# A Let's Encrypt STAGING certificate looks entirely normal — it has the right hostname
# and a valid date range — but its root is not in any trust store, so every browser shows
# "unable to get local issuer certificate". Verifying against the real trust store is the
# only test that catches it. On the first production target, /root/.acme.sh/<domain>/ held
# exactly such a staging certificate, NEWER than the real one.
tls_is_trusted() {
    local cert="$1"
    openssl verify -untrusted "$cert" "$cert" >/dev/null 2>&1
}

# Does the issuer name look like a staging or test CA? Used only to produce a better
# message; tls_is_trusted() is the actual gate.
tls_issuer_looks_staging() {
    local cert="$1" issuer
    issuer="$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null || true)"
    grep -qiE 'staging|\(test\)|fake ?le|happy hacker|pretend|dastardly|durum|invalid' <<<"$issuer"
}

# Does the private key belong to this certificate?
#
# Compares the PUBLIC KEY rather than the RSA modulus, because the modulus comparison
# people usually reach for only works for RSA and silently produces two empty strings
# (which compare equal!) for an EC key. This form is algorithm-agnostic.
tls_key_matches() {
    local cert="$1" key="$2" a b
    a="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null || true)"
    b="$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl sha256 2>/dev/null || true)"
    [[ -n "$a" && "$a" == "$b" ]]
}

# Full validation of a candidate cert/key pair. Prints its findings.
tls_validate_pair() {
    local cert="$1" key="$2" host="$3" bad=0

    [[ -r "$cert" ]] || { fail "certificate not readable: $cert"; return 1; }
    [[ -r "$key"  ]] || { fail "private key not readable: $key"; return 1; }

    if openssl x509 -in "$cert" -noout >/dev/null 2>&1; then
        ok "certificate parses: $cert"
    else
        fail "not a PEM certificate: $cert"; return 1
    fi

    if tls_key_matches "$cert" "$key"; then
        ok "private key matches the certificate"
    else
        fail "private key does NOT match the certificate"
        info "      $cert"
        info "      $key"
        bad=1
    fi

    if openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null 2>&1; then
        ok "certificate is valid for at least another day ($(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2))"
    else
        fail "certificate has expired or expires within 24 hours"
        bad=1
    fi

    if openssl x509 -in "$cert" -noout -checkhost "$host" >/dev/null 2>&1; then
        ok "certificate is valid for $host"
    else
        warn "certificate does not list $host in its CN or SANs"
        info "      subject: $(openssl x509 -in "$cert" -noout -subject 2>/dev/null | cut -d= -f2-)"
    fi

    if tls_is_trusted "$cert"; then
        ok "certificate chains to a trusted root"
    else
        fail "certificate does NOT chain to a trusted root"
        if tls_issuer_looks_staging "$cert"; then
            info "      Issuer: $(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | cut -d= -f2-)"
            info "      That looks like a Let's Encrypt STAGING / test certificate."
            info "      Deploying it produces 'unable to get local issuer certificate'"
            info "      in every browser. Re-issue without --staging / --test-cert."
        else
            info "      Either an intermediate is missing from the chain file, or the"
            info "      issuing CA is not in this machine's trust store."
        fi
        bad=1
    fi

    return $bad
}

# Look for a usable certificate for $HOSTNAME_FQDN in the usual places.
tls_find_existing() {
    local host="$1" c k
    local -a candidates=(
        "/etc/letsencrypt/live/$host/fullchain.pem|/etc/letsencrypt/live/$host/privkey.pem"
        "/root/.acme.sh/$host/fullchain.cer|/root/.acme.sh/$host/$host.key"
        "/root/.acme.sh/${host}_ecc/fullchain.cer|/root/.acme.sh/${host}_ecc/$host.key"
        "/etc/ssl/certs/$host.pem|/etc/ssl/private/$host.key"
        "/etc/pki/tls/certs/$host.crt|/etc/pki/tls/private/$host.key"
    )
    local pair
    for pair in "${candidates[@]}"; do
        c="${pair%%|*}"; k="${pair##*|}"
        [[ -r "$c" && -r "$k" ]] || continue
        # Only offer a candidate that actually passes. An untrusted or mismatched pair
        # found on disk is worse than none, because it looks like success.
        if tls_key_matches "$c" "$k" && tls_is_trusted "$c" \
           && openssl x509 -in "$c" -noout -checkend 86400 >/dev/null 2>&1; then
            printf '%s|%s' "$c" "$k"
            return 0
        fi
    done
    return 1
}

resolve_tls() {
    [[ "$WEBSERVER" == "none" ]] && return 0

    step "TLS certificate"

    if [[ -z "$HOSTNAME_FQDN" ]]; then
        HOSTNAME_FQDN="$(ask 'Hostname for the Loghound panel (FQDN)' "loghound.$(hostname -d 2>/dev/null || echo 'example.com')")"
    fi
    [[ -z "$HOSTNAME_FQDN" ]] && die "A hostname is required to generate a vhost. Pass --hostname."
    ok "panel hostname: $HOSTNAME_FQDN"

    # ---- explicit paths win ----
    if [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then
        TLS_MODE="existing"
        if tls_validate_pair "$TLS_CERT" "$TLS_KEY" "$HOSTNAME_FQDN"; then
            return 0
        fi
        die "The certificate you supplied did not pass validation (see above).
      Nothing has been written. Fix the certificate, or choose another --tls-mode."
    fi

    # ---- find one ----
    if [[ -z "$TLS_MODE" || "$TLS_MODE" == "existing" ]]; then
        local found
        if found="$(tls_find_existing "$HOSTNAME_FQDN")"; then
            TLS_CERT="${found%%|*}"; TLS_KEY="${found##*|}"
            TLS_MODE="existing"
            ok "found a usable certificate for $HOSTNAME_FQDN"
            tls_validate_pair "$TLS_CERT" "$TLS_KEY" "$HOSTNAME_FQDN" || \
                die "The certificate found on disk did not pass validation. Nothing written."
            return 0
        fi
        [[ "$TLS_MODE" == "existing" ]] && \
            die "No usable certificate for $HOSTNAME_FQDN was found, and --tls-mode existing
      was requested. Pass --tls-cert and --tls-key, or choose another mode."
        info "no existing trusted certificate for $HOSTNAME_FQDN was found"
    fi

    # ---- choose ----
    if [[ -z "$TLS_MODE" ]]; then
        if command -v certbot >/dev/null 2>&1; then
            say "certbot is installed on this machine."
            if confirm "Obtain a Let's Encrypt certificate for $HOSTNAME_FQDN with certbot?" y; then
                TLS_MODE="certbot"
            fi
        fi
    fi
    if [[ -z "$TLS_MODE" ]]; then
        say "Options: 'selfsigned' (works, but every browser warns), or 'none' (plain HTTP)."
        TLS_MODE="$(ask 'TLS mode (selfsigned/none)' 'selfsigned')"
    fi

    case "$TLS_MODE" in
        certbot)
            command -v certbot >/dev/null 2>&1 || die "certbot is not installed."
            # --webroot would need the vhost to exist first; standalone needs port 80 free.
            # Use the plugin that matches the running web server, which is the least
            # disruptive option and the one certbot itself recommends.
            local plugin="--apache"
            [[ "$WEBSERVER" == "nginx" ]] && plugin="--nginx"
            run certbot certonly $plugin -n --agree-tos --keep-until-expiring \
                -d "$HOSTNAME_FQDN" --register-unsafely-without-email
            TLS_CERT="/etc/letsencrypt/live/$HOSTNAME_FQDN/fullchain.pem"
            TLS_KEY="/etc/letsencrypt/live/$HOSTNAME_FQDN/privkey.pem"
            if (( ! DRY_RUN )); then
                tls_validate_pair "$TLS_CERT" "$TLS_KEY" "$HOSTNAME_FQDN" || \
                    die "certbot ran but the resulting certificate did not validate.
      Check that you did not use --staging / --test-cert."
            fi
            ;;
        selfsigned)
            TLS_CERT="$PREFIX/config/tls-$HOSTNAME_FQDN.crt"
            TLS_KEY="$PREFIX/config/tls-$HOSTNAME_FQDN.key"
            if [[ -e "$TLS_CERT" ]]; then
                warn "reusing the existing self-signed certificate at $TLS_CERT"
            else
                run openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
                    -keyout "$TLS_KEY" -out "$TLS_CERT" \
                    -subj "/CN=$HOSTNAME_FQDN" \
                    -addext "subjectAltName=DNS:$HOSTNAME_FQDN"
                (( DRY_RUN )) || { track_created "$TLS_CERT"; track_created "$TLS_KEY"; }
                run chmod 0640 "$TLS_KEY"
                run chown root:"$RUN_USER" "$TLS_KEY" "$TLS_CERT"
            fi
            printf '\n'
            warn "############################################################"
            warn "# SELF-SIGNED CERTIFICATE."
            warn "# Every browser will show a full-page security warning, and"
            warn "# the panel's session cookie is only as safe as the operator"
            warn "# who clicks through it. Replace this with a real"
            warn "# certificate before anyone else uses the panel:"
            warn "#   certbot certonly --apache -d $HOSTNAME_FQDN"
            warn "#   then re-run this installer with --tls-mode existing"
            warn "############################################################"
            printf '\n'
            ;;
        none)
            warn "serving the panel over PLAIN HTTP."
            warn "The panel shows every visitor, path and IP address on your site, and"
            warn "its credentials cross the network in the clear. Do this only on a"
            warn "private network you control."
            ;;
        *)
            die "Unknown --tls-mode: $TLS_MODE (use existing, certbot, selfsigned or none)"
            ;;
    esac
}

# =============================================================================
# vhost generation
# =============================================================================

gen_apache_vhost() {
    local tls_block="" redirect_block="" listen="*:80"

    # Apache's config parser understands ${VAR} but NOT ${VAR:-default} — that is a
    # shell-ism, and on RHEL (where APACHE_LOG_DIR is never defined) it would make
    # `httpd -t` fail outright. Resolve the directory here, in bash, where defaults work.
    local logdir="/var/log/apache2"
    [[ "$APACHE_FLAVOUR" == "rhel" ]] && logdir="/var/log/httpd"
    [[ -d "$logdir" ]] || logdir="/var/log"

    # Somewhere for the ACME HTTP-01 challenge to be served from. Without a DocumentRoot
    # the :80 vhost cannot answer a challenge, and certificate renewal would start
    # failing silently three months after the install.
    local acme_root="/var/www/html"
    [[ -d "$acme_root" ]] || acme_root="$(ls -d /var/www/html /usr/share/httpd/noindex /var/www 2>/dev/null | head -1 || echo /var/www)"

    if [[ "$TLS_MODE" != "none" ]]; then
        listen="*:443"
        tls_block="    SSLEngine on
    SSLCertificateFile      $TLS_CERT
    SSLCertificateKeyFile   $TLS_KEY
    SSLProtocol             -all +TLSv1.2 +TLSv1.3
    SSLHonorCipherOrder     off
"
        redirect_block="<VirtualHost *:80>
    ServerName $HOSTNAME_FQDN
    # A real DocumentRoot so the ACME HTTP-01 challenge can actually be served;
    # everything else is redirected to HTTPS.
    DocumentRoot $acme_root
    <Directory \"$acme_root/.well-known/acme-challenge\">
        Options -Indexes
        Require all granted
    </Directory>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\\.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

"
    fi

    cat <<VHOST
########################################################################
# Loghound panel — GENERATED by install/install.sh. Do not hand-edit;
# re-run the installer, or copy this to a new name and edit that.
#
# Filename note: this file is deliberately named to sort LAST in the
# vhost directory. Apache treats the FIRST vhost matching an
# address:port as the default for unmatched requests, so a Loghound
# file sorting ahead of an existing catch-all would silently hijack
# every unmatched request on this machine.
########################################################################

${redirect_block}<VirtualHost $listen>
    ServerName $HOSTNAME_FQDN
    DocumentRoot $PREFIX/public

$tls_block
    # Loghound's OWN logs. Do not point Loghound at these: it would ingest
    # its own beacon traffic and inflate every number it reports.
    ErrorLog  $logdir/loghound_error.log
    CustomLog $logdir/loghound_access.log combined

    # ---- DEFAULT DENY -------------------------------------------------
    <Directory />
        AllowOverride None
        Options -Indexes -FollowSymLinks -ExecCGI -Includes
        Require all denied
    </Directory>

    # ---- The docroot: index.php, collect.php and b.js only -------------
    <Directory $PREFIX/public>
        AllowOverride None
        Options -Indexes +SymLinksIfOwnerMatch -ExecCGI -Includes
        Require all denied

        <FilesMatch "^(index|collect)\\.php\$">
            Require all granted
            # A DEDICATED pool socket. Never the shared www-data pool: every
            # other site on this box would then run as a user that can read
            # $PREFIX/config/loghound.php, which holds the API key and the
            # beacon HMAC secret.
            SetHandler "proxy:unix:$FPM_SOCK|fcgi://localhost"
        </FilesMatch>

        <FilesMatch "^b\\.js\$">
            Require all granted
        </FilesMatch>

        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/(collect\\.php|b\\.js)\$
        RewriteCond %{REQUEST_URI} !^/assets/
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteRule ^ /index.php [L]
    </Directory>

    # ---- Static assets: no PHP here, ever ------------------------------
    <Directory $PREFIX/public/assets>
        AllowOverride None
        Options -Indexes +SymLinksIfOwnerMatch -ExecCGI -Includes
        Require all granted
        RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phps
    </Directory>

    # ---- HARD DENIES, last so nothing above can re-grant them ----------
    <DirectoryMatch "$PREFIX/(config|src|var|bin|tests|solr|install|docs)(/|\$)">
        Require all denied
    </DirectoryMatch>
    <LocationMatch "^/(config|src|var|bin|tests|solr|install|docs)(/|\$)">
        Require all denied
    </LocationMatch>
    <LocationMatch "/(\\.git|\\.hg|\\.svn|\\.bzr|__pycache__|node_modules)(/|\$)">
        Require all denied
    </LocationMatch>
    <FilesMatch "^\\.">
        Require all denied
    </FilesMatch>
    <FilesMatch "(~|\\.swp|\\.swo|\\.orig|\\.rej|\\.save)\$">
        Require all denied
    </FilesMatch>

    # Dangerous extensions, denied everywhere in this vhost. Serving any one
    # of these has been the root cause of a real breach somewhere: a .sql
    # dump, a .env with credentials, a .db that IS the database, a .pem that
    # IS the private key. .json and .xml are in the list deliberately —
    # nothing Loghound ships needs to serve either.
    <FilesMatch "\\.(sh|csv|conf|lock|json|jar|gz|xml|properties|py|pyc|db|cache|hist|sql|bak|old|inc|sqlite|sqlite3|pem|key|crt|env|tar|zip|log|ini|yml|yaml)\$">
        Require all denied
    </FilesMatch>

    # ---- Cache headers -------------------------------------------------
    # b.js is versioned by query string (?v=N), so a new version is a new URL
    # and there is never a stale-beacon problem to debug.
    <Location "/b.js">
        Header always set Cache-Control "public, max-age=604800, immutable"
        Header unset Pragma
        Header unset Expires
        Header always set X-Content-Type-Options "nosniff"
        Header always set Access-Control-Allow-Origin "*"
        Header always set Timing-Allow-Origin "*"
    </Location>

    # The collector is NEVER cached. A cached 204 would silently swallow every
    # subsequent beacon from that client, and the data loss would be invisible.
    <Location "/collect.php">
        Header always set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"
        Header always set Pragma "no-cache"
        Header always set Expires "0"
        Header always set X-Content-Type-Options "nosniff"
    </Location>

    <Location "/assets/">
        Header always set Cache-Control "public, max-age=2592000"
        Header always set X-Content-Type-Options "nosniff"
    </Location>

    <Location "/">
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "DENY"
        Header always set Referrer-Policy "same-origin"$( [[ "$TLS_MODE" != "none" ]] && printf '\n        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' )
    </Location>

    Header always unset X-Powered-By
    ServerSignature Off

    # Beacon payloads are capped at 8 KB by the collector; nothing legitimate
    # is larger. A low ceiling turns a body-flood into a 413 at the edge.
    LimitRequestBody 65536
</VirtualHost>
VHOST
}

gen_nginx_vhost() {
    local listen_block redirect_block=""

    if [[ "$TLS_MODE" != "none" ]]; then
        listen_block="    listen 443 ssl;
    listen [::]:443 ssl;

    ssl_certificate     $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;"
        redirect_block="server {
    listen 80;
    listen [::]:80;
    server_name $HOSTNAME_FQDN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/html; autoindex off; }
    location / { return 301 https://\$host\$request_uri; }
}

"
    else
        listen_block="    listen 80;
    listen [::]:80;"
    fi

    cat <<VHOST
########################################################################
# Loghound panel — GENERATED by install/install.sh. Do not hand-edit;
# re-run the installer, or copy this to a new name and edit that.
#
# This server block deliberately does NOT carry default_server, so it can
# never take over requests for any other site on this machine.
########################################################################

${redirect_block}server {
$listen_block
    server_name $HOSTNAME_FQDN;

    root $PREFIX/public;
    index index.php;

    # Loghound's OWN logs. Do not point Loghound at these.
    access_log /var/log/nginx/loghound_access.log combined;
    error_log  /var/log/nginx/loghound_error.log warn;

    autoindex off;
    server_tokens off;
    client_max_body_size 64k;
    client_body_buffer_size 16k;

    # ---- HARD DENIES, first: regex locations beat the prefix location ----
    location ~ ^/(config|src|var|bin|tests|solr|install|docs)(/|\$)      { deny all; return 404; }
    location ~ /(\\.git|\\.hg|\\.svn|\\.bzr|__pycache__|node_modules)(/|\$) { deny all; return 404; }
    location ~ /\\.                                                      { deny all; return 404; }
    location ~ (~|\\.swp|\\.swo|\\.orig|\\.rej|\\.save)\$                 { deny all; return 404; }

    # Dangerous extensions. .json and .xml are in the list deliberately —
    # nothing Loghound ships needs to serve either.
    location ~* \\.(sh|csv|conf|lock|json|jar|gz|xml|properties|py|pyc|db|cache|hist|sql|bak|old|inc|sqlite|sqlite3|pem|key|crt|env|tar|zip|log|ini|yml|yaml)\$ {
        deny all; return 404;
    }

    # ---- The beacon: cacheable, versioned by ?v=N ------------------------
    location = /b.js {
        add_header Cache-Control "public, max-age=604800, immutable" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Access-Control-Allow-Origin "*" always;
        add_header Timing-Allow-Origin "*" always;
        default_type application/javascript;
        try_files /b.js =404;
    }

    # ---- The collector: NEVER cached -------------------------------------
    location = /collect.php {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        add_header X-Content-Type-Options "nosniff" always;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root/collect.php;
        fastcgi_param DOCUMENT_ROOT   \$document_root;
        fastcgi_param PATH_INFO       "";
        fastcgi_pass unix:$FPM_SOCK;
        fastcgi_read_timeout 15s;
    }

    location ^~ /assets/ {
        add_header Cache-Control "public, max-age=2592000" always;
        add_header X-Content-Type-Options "nosniff" always;
        try_files \$uri =404;
        location ~ \\.php\$ { deny all; return 404; }
    }

    location / {
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "same-origin" always;$( [[ "$TLS_MODE" != "none" ]] && printf '\n        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' )
        try_files \$uri /index.php\$is_args\$args;
    }

    # ONLY index.php is executable. Anchored to the exact filename rather than
    # the usual \\.php\$, so a file planted anywhere in the tree can never be
    # executed by requesting it.
    location = /index.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root/index.php;
        fastcgi_param DOCUMENT_ROOT   \$document_root;
        fastcgi_param PATH_INFO       "";
        fastcgi_pass unix:$FPM_SOCK;
        fastcgi_read_timeout 60s;
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
    }

    location ~ \\.php\$ { deny all; return 404; }
}
VHOST
}

install_vhost() {
    [[ "$WEBSERVER" == "none" ]] && { skip "no web server selected"; return 0; }

    step "Web server configuration"

    # ---- Apache modules, if we said we would enable them ----
    if [[ "$WEBSERVER" == "apache" && "$APACHE_FLAVOUR" == "debian" ]]; then
        local m
        for m in "${APACHE_MODULES_TO_ENABLE[@]:-}"; do
            [[ -z "$m" ]] && continue
            run a2enmod "$m"
            ok "enabled apache module: $m"
        done
    fi

    local avail enabled
    if [[ "$WEBSERVER" == "apache" ]]; then
        avail="$APACHE_SITES_AVAIL/$VHOST_NAME"; enabled="$APACHE_SITES_ENABLED/$VHOST_NAME"
        gen_apache_vhost | write_file "$avail" 0644
    else
        avail="$NGINX_SITES_AVAIL/$VHOST_NAME";  enabled="$NGINX_SITES_ENABLED/$VHOST_NAME"
        gen_nginx_vhost | write_file "$avail" 0644
    fi
    ok "wrote $avail"

    # ---- enable ----
    if [[ "$avail" != "$enabled" ]]; then
        if [[ -e "$enabled" ]]; then
            die "Refusing to overwrite $enabled"
        fi
        if [[ "$WEBSERVER" == "apache" ]] && command -v a2ensite >/dev/null 2>&1; then
            run a2ensite "${VHOST_NAME%.conf}"
        else
            run ln -s "$avail" "$enabled"
        fi
        (( DRY_RUN )) || track_created "$enabled"
        APACHE_SITE_ENABLED_BY_US=1
        ok "enabled the site"
    else
        # RHEL conf.d: the file being present IS enabled.
        APACHE_SITE_ENABLED_BY_US=1
    fi

    # ---- VALIDATE BEFORE RELOADING ----
    # If this fails, the ERR trap rolls back: the files are removed, the site is
    # disabled, and configtest is re-run to prove the host is back where it started.
    if (( DRY_RUN )); then
        skip "would validate and reload the web server"
        return 0
    fi

    if [[ "$WEBSERVER" == "apache" ]]; then
        if "$APACHE_BIN" -t >/dev/null 2>&1; then
            ok "apache configuration is valid"
        else
            "$APACHE_BIN" -t 2>&1 | sed 's/^/      /' >&2 || true
            die "Apache rejected the new vhost. Rolling back."
        fi
        run systemctl reload "$APACHE_SERVICE"
        ok "reloaded $APACHE_SERVICE (reload, not restart — other sites undisturbed)"
    else
        if nginx -t >/dev/null 2>&1; then
            ok "nginx configuration is valid"
        else
            nginx -t 2>&1 | sed 's/^/      /' >&2 || true
            die "nginx rejected the new server block. Rolling back."
        fi
        run systemctl reload nginx
        ok "reloaded nginx (reload, not restart — other sites undisturbed)"
    fi
}

# =============================================================================
# Prefix self-check
# =============================================================================

# Prove that nothing we generated kept the default prefix.
#
# A hardcoded /opt/loghound surviving into a vhost DocumentRoot, an open_basedir or a
# systemd ReadWritePaths is a silent, confusing failure: the service starts, the vhost
# loads, and nothing works. Cheaper to grep for it than to debug it.
verify_no_hardcoded_prefix() {
    [[ "$PREFIX" == "/opt/loghound" ]] && return 0
    (( DRY_RUN )) && return 0

    step "Prefix self-check"

    local bad=0 f
    local -a generated=()
    [[ -n "$FPM_POOL_DIR" ]] && generated+=("$FPM_POOL_DIR/loghound.conf")
    [[ -n "$APACHE_SITES_AVAIL" ]] && generated+=("$APACHE_SITES_AVAIL/$VHOST_NAME")
    [[ -n "$NGINX_SITES_AVAIL" ]] && generated+=("$NGINX_SITES_AVAIL/$VHOST_NAME")
    generated+=(
        "$SYSTEMD_DIR/loghound-tail.service"
        "$SYSTEMD_DIR/loghound-score.service"
        "$SYSTEMD_DIR/loghound-retention.service"
        /etc/cron.d/loghound
    )

    for f in "${generated[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -q '/opt/loghound' "$f"; then
            fail "$f still contains /opt/loghound but the prefix is $PREFIX"
            grep -n '/opt/loghound' "$f" | sed 's/^/      /' >&2
            bad=1
        else
            ok "$(basename "$f") uses $PREFIX"
        fi
    done

    (( bad )) && die "A generated file kept the default prefix. That would fail silently at
      runtime, so the install stops here rather than leaving you to find it."
    return 0
}

# =============================================================================
# Self-test
# =============================================================================

run_tests() {
    step "Self-test"
    if (( SKIP_TESTS )); then skip "--skip-tests"; return 0; fi
    if (( DRY_RUN )); then skip "not under --dry-run"; return 0; fi
    [[ -f "$PREFIX/tests/run.php" ]] || { skip "no test suite in this checkout"; return 0; }

    if "$PHP_BIN" "$PREFIX/tests/run.php" --no-color --quiet; then
        ok "test suite passed"
    else
        warn "the test suite reported failures — see the output above"
        warn "the install continues, but look at this before trusting the numbers"
    fi
}

# =============================================================================
# Configuration wizard
# =============================================================================

run_setup() {
    step "Configuration"

    if (( DRY_RUN )); then skip "would run bin/loghound-setup"; return 0; fi

    say "Handing over to the setup wizard: it detects your access logs, shows you the"
    say "parsed result with a confidence score, and asks you to confirm before anything"
    say "is ingested. It also provisions Solr and generates the secrets."
    printf '\n'

    local -a AS=()
    if command -v runuser >/dev/null 2>&1; then
        AS=(runuser -u "$RUN_USER" --)
    elif command -v sudo >/dev/null 2>&1; then
        AS=(sudo -u "$RUN_USER" --)
    fi

    if (( ${#AS[@]} == 0 )); then
        warn "neither runuser nor sudo is available; run the wizard yourself:"
        say  "  $PHP_BIN $PREFIX/bin/loghound-setup"
        return 0
    fi

    # Pass the panel URL through so the wizard can build the beacon snippet without
    # asking again, and hand it the non-interactive flag when we are in that mode.
    local scheme="https"; [[ "$TLS_MODE" == "none" ]] && scheme="http"
    local extra=()
    [[ "$NONINTERACTIVE" == "1" ]] && extra+=(--non-interactive)

    # LOGHOUND_* variables already in this environment are inherited by the wizard, which
    # is how --non-interactive answers everything. The API key among them is never echoed
    # by the wizard and never written to the install log.
    if [[ -n "$HOSTNAME_FQDN" ]]; then
        export LOGHOUND_BASE_URL="${LOGHOUND_BASE_URL:-$scheme://$HOSTNAME_FQDN}"
    fi

    if "${AS[@]}" env LOGHOUND_BASE_URL="${LOGHOUND_BASE_URL:-}" \
            "$PHP_BIN" "$PREFIX/bin/loghound-setup" \
            --config="$PREFIX/config/loghound.php" "${extra[@]}"; then
        ok "configuration written"
    else
        warn "the setup wizard did not complete."
        say  "Run it again at any time:"
        say  "  sudo -u $RUN_USER $PHP_BIN $PREFIX/bin/loghound-setup"
        return 1
    fi

    run chmod 0640 "$PREFIX/config/loghound.php"
    run chown "$RUN_USER":"$RUN_USER" "$PREFIX/config/loghound.php"
}

# =============================================================================
# Start, and verify data actually flows
# =============================================================================

start_and_verify() {
    step "Starting ingestion"

    if (( DRY_RUN )); then skip "would start loghound-tail"; return 0; fi

    if [[ ! -f "$PREFIX/config/loghound.php" ]]; then
        warn "there is no configuration yet, so ingestion cannot start."
        say  "Run: sudo -u $RUN_USER $PHP_BIN $PREFIX/bin/loghound-setup"
        return 1
    fi

    if (( ! HAVE_SYSTEMD )); then
        warn "no systemd: start bin/loghound-tail under your own supervisor."
        return 0
    fi

    run systemctl enable --now loghound-tail.service
    ENABLED_UNITS+=(loghound-tail.service)

    if ! systemctl is-active --quiet loghound-tail.service; then
        fail "loghound-tail.service did not start"
        info "      journalctl -u loghound-tail -n 50 --no-pager"
        return 1
    fi
    ok "loghound-tail.service is running"

    # ---- wait for real data ----
    # Do NOT declare success because a unit is active. A daemon that is running and
    # indexing nothing is the exact failure this whole project exists to make visible.
    say "waiting up to ${FIRST_DOC_TIMEOUT}s for the first documents to reach Solr..."
    local waited=0 docs=0 lines=0 status
    while (( waited < FIRST_DOC_TIMEOUT )); do
        sleep 3; waited=$((waited+3))
        status="$("$PREFIX/bin/loghound-tail" --status 2>/dev/null || true)"
        [[ -z "$status" ]] && continue
        docs="$(grep -o '"docs_indexed": *[0-9]*' <<<"$status" | grep -o '[0-9]*$' | head -1 || echo 0)"
        lines="$(grep -o '"lines": *[0-9]*' <<<"$status" | grep -o '[0-9]*$' | head -1 || echo 0)"
        (( ${docs:-0} > 0 )) && break
    done

    if (( ${docs:-0} > 0 )); then
        ok "$docs document(s) indexed from $lines log line(s) — data is flowing"
        return 0
    fi

    # Honest failure, with the command that explains it, rather than a claim of success.
    warn "no documents have been indexed yet after ${FIRST_DOC_TIMEOUT}s."
    info "      This is NOT necessarily broken: on a quiet site there may simply have"
    info "      been no requests, and by default a newly watched log file is read from"
    info "      its END rather than replayed from the beginning."
    info ""
    info "      Check it yourself:"
    info "        loghound-tail --status --human"
    info "        journalctl -u loghound-tail -n 50 --no-pager"
    info "      Force a replay of an existing log to prove the pipeline works:"
    info "        sudo -u $RUN_USER $PHP_BIN $PREFIX/bin/loghound-tail --once --from-start --dry-run --verbose"
    return 0
}

# =============================================================================
# Prefix discovery
# =============================================================================

# Work out where a previous run installed to, instead of assuming the default.
#
# --uninstall on a box where someone installed to /var/www/workspace/loghound must not
# quietly do nothing (or, worse, act on a /opt/loghound that belongs to something else).
# The installed systemd unit is the authoritative record, with the /usr/local/bin symlink
# as a fallback.
discover_prefix() {
    # An explicit --prefix or LOGHOUND_PREFIX always wins.
    if [[ -n "${LOGHOUND_PREFIX:-}" ]] || [[ "$PREFIX_EXPLICIT" == "1" ]]; then
        return 0
    fi

    local found=""
    if [[ -r "$SYSTEMD_DIR/loghound-tail.service" ]]; then
        found="$(awk -F= '/^WorkingDirectory=/{print $2}' "$SYSTEMD_DIR/loghound-tail.service" | tail -1)"
    fi
    if [[ -z "$found" ]] && [[ -L /usr/local/bin/loghound-tail ]]; then
        found="$(dirname "$(dirname "$(readlink -f /usr/local/bin/loghound-tail)")")"
    fi
    if [[ -z "$found" ]] && [[ -r /etc/cron.d/loghound ]]; then
        found="$(grep -oE '[^ ]*/bin/loghound-score' /etc/cron.d/loghound | head -1 | sed 's#/bin/loghound-score##')"
    fi

    if [[ -n "$found" ]] && [[ "$found" != "$PREFIX" ]]; then
        say "discovered a previous installation at $found (not the default $PREFIX)"
        PREFIX="${found%/}"
    fi
}

# =============================================================================
# Git-based upgrade
# =============================================================================

# Is the prefix a git working copy of this project?
#
# Keeping the install directory as a checkout is a supported and, on some boxes, the
# preferred layout: a server-management platform that auto-discovers applications under a
# base directory gives you git deploy, backups, vhost and FPM management for free, with no
# registration file to lose. `git pull` in place then IS the upgrade.
prefix_is_git_checkout() {
    [[ -d "$PREFIX/.git" ]] || return 1
    git -c safe.directory="$PREFIX" -C "$PREFIX" rev-parse --git-dir >/dev/null 2>&1
}

# Fast-forward the checkout at $PREFIX.
#
# NEVER `git clean` and NEVER `git reset --hard`. config/loghound.php is untracked and
# holds the operator's API key and HMAC secret; var/ holds state.db. Either command would
# destroy them. A fast-forward-only merge is the whole safety property: if it cannot
# fast-forward, the operator has local work and we stop and say so rather than guessing.
git_upgrade() {
    local git_cmd=(git -c safe.directory="$PREFIX" -C "$PREFIX")

    say "the prefix is a git working copy — upgrading with a fast-forward pull"

    local branch
    branch="$("${git_cmd[@]}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
    [[ -z "$branch" || "$branch" == "HEAD" ]] &&         die "The checkout at $PREFIX is on a detached HEAD. Check out a branch first."

    # Report, but do not touch, local modifications to TRACKED files. Untracked files
    # (config/loghound.php, var/) are none of our business and are never mentioned as a
    # problem, because they are exactly what must survive.
    local dirty
    dirty="$("${git_cmd[@]}" status --porcelain --untracked-files=no 2>/dev/null || true)"
    if [[ -n "$dirty" ]]; then
        warn "there are local modifications to tracked files in $PREFIX:"
        sed 's/^/      /' <<<"$dirty" >&2
        info "      They will NOT be discarded. If the pull cannot fast-forward, the"
        info "      upgrade stops and leaves everything exactly as it is."
    fi

    run "${git_cmd[@]}" fetch --prune --quiet origin || die "git fetch failed in $PREFIX"

    local upstream
    upstream="$("${git_cmd[@]}" rev-parse --abbrev-ref '@{upstream}' 2>/dev/null || echo '')"
    if [[ -z "$upstream" ]]; then
        warn "branch '$branch' has no upstream; nothing to pull"
        return 0
    fi

    local before after
    before="$("${git_cmd[@]}" rev-parse --short HEAD 2>/dev/null || echo '?')"

    if ! run "${git_cmd[@]}" merge --ff-only --quiet "$upstream"; then
        die "Cannot fast-forward $PREFIX from $upstream.
      Your checkout has diverged from the remote. Nothing has been changed.
      Resolve it yourself (git log --oneline HEAD..$upstream) and re-run.
      This installer will never run 'git reset --hard' or 'git clean': that
      would delete config/loghound.php and var/state.db."
    fi

    after="$("${git_cmd[@]}" rev-parse --short HEAD 2>/dev/null || echo '?')"
    if [[ "$before" == "$after" ]]; then
        ok "already up to date at $before"
    else
        ok "updated $before -> $after"
    fi

    # config/ and var/ are untracked, so a fast-forward could not have touched them.
    # Say so explicitly: it is the guarantee people actually want to hear.
    info "config/loghound.php and var/ are untracked and were not touched"
}

# =============================================================================
# Uninstall
# =============================================================================

do_uninstall() {
    step "Uninstall"

    say "This will remove the Loghound service units, the vhost, the FPM pool and the"
    say "system user. You will be asked separately before ANY data is deleted."
    printf '\n'
    if ! confirm "Continue?" n; then
        say "Nothing was changed."
        exit 0
    fi

    # ---- services ----
    if (( HAVE_SYSTEMD )); then
        local u
        for u in loghound-tail.service loghound-score.timer loghound-score.service \
                 loghound-retention.timer loghound-retention.service; do
            if systemctl list-unit-files --no-legend 2>/dev/null | grep -q "^$u"; then
                run systemctl disable --now "$u" || true
                ok "stopped and disabled $u"
            fi
            [[ -e "$SYSTEMD_DIR/$u" ]] && { run rm -f "$SYSTEMD_DIR/$u"; ok "removed $SYSTEMD_DIR/$u"; }
        done
        run systemctl daemon-reload
    fi
    [[ -e /etc/cron.d/loghound ]] && { run rm -f /etc/cron.d/loghound; ok "removed /etc/cron.d/loghound"; }

    # ---- vhost ----
    # Track which web server we actually changed, so we reload THAT one and only that
    # one. Reloading a web server we did not touch is needless risk on a busy box.
    local removed_apache=0 removed_nginx=0 f
    for f in "$APACHE_SITES_ENABLED/$VHOST_NAME" "$APACHE_SITES_AVAIL/$VHOST_NAME" \
             "$NGINX_SITES_ENABLED/$VHOST_NAME" "$NGINX_SITES_AVAIL/$VHOST_NAME"; do
        [[ -n "$f" && -e "$f" ]] || continue
        if [[ "$f" == "$APACHE_SITES_ENABLED/$VHOST_NAME" ]] && command -v a2dissite >/dev/null 2>&1; then
            run a2dissite "${VHOST_NAME%.conf}" || true
            removed_apache=1
        else
            run rm -f "$f"
            [[ "$f" == "$APACHE_SITES_AVAIL/$VHOST_NAME" || "$f" == "$APACHE_SITES_ENABLED/$VHOST_NAME" ]] && removed_apache=1
            [[ "$f" == "$NGINX_SITES_AVAIL/$VHOST_NAME"  || "$f" == "$NGINX_SITES_ENABLED/$VHOST_NAME"  ]] && removed_nginx=1
        fi
        ok "removed $f"
    done

    # Validate before reloading, and reload only what we changed. Never leave a broken
    # host, and never disturb a web server that had nothing to do with Loghound.
    if (( removed_apache )) && [[ -n "$APACHE_BIN" ]]; then
        if "$APACHE_BIN" -t >/dev/null 2>&1; then
            run systemctl reload "$APACHE_SERVICE" || true
            ok "reloaded $APACHE_SERVICE"
        else
            warn "apache configuration is invalid after removing the vhost — NOT reloading"
            info "      run '$APACHE_BIN -t' and fix it before reloading"
        fi
    fi
    if (( removed_nginx )) && command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            run systemctl reload nginx || true
            ok "reloaded nginx"
        else
            warn "nginx configuration is invalid after removing the server block — NOT reloading"
        fi
    fi

    # ---- fpm pool ----
    if [[ -n "$FPM_POOL_DIR" && -e "$FPM_POOL_DIR/loghound.conf" ]]; then
        run rm -f "$FPM_POOL_DIR/loghound.conf"
        ok "removed $FPM_POOL_DIR/loghound.conf"
        if [[ -n "$FPM_BIN" ]] && "$FPM_BIN" -t >/dev/null 2>&1 && (( HAVE_SYSTEMD )) && [[ -n "$FPM_SERVICE" ]]; then
            run systemctl reload "$FPM_SERVICE" || true
            ok "reloaded $FPM_SERVICE"
        fi
    fi

    # ---- symlinks ----
    local cmd
    for cmd in loghound-tail loghound-setup loghound-score loghound-retention; do
        [[ -L "/usr/local/bin/$cmd" ]] && { run rm -f "/usr/local/bin/$cmd"; ok "removed /usr/local/bin/$cmd"; }
    done

    # ---- DATA: always prompted, never assumed ----
    printf '\n'
    warn "The next question is about DATA, not about software."
    say  "$PREFIX contains var/state.db (tail offsets, open sessions, beacon staging)"
    say  "and config/loghound.php (your Opensolr API key and beacon secret)."
    if confirm "Delete $PREFIX and everything in it?" n; then
        run rm -rf "$PREFIX"
        ok "removed $PREFIX"
    else
        say "kept $PREFIX"
    fi

    printf '\n'
    say "Your Solr indexes have NOT been touched. This installer will not delete an"
    say "index: it cannot tell a dedicated Loghound index from a shared Solr that"
    say "something else also writes to, and getting that wrong is unrecoverable."
    if confirm "Show the commands to remove the Loghound indexes yourself?" n; then
        # Read the ACTUAL index names out of the config rather than printing a guess.
        # They carry a random per-installation id (Opensolr index names are unique across
        # the whole platform), so a hardcoded 'loghound_hits' here would be wrong for
        # every installation and would send someone to delete somebody else's index.
        local hits_core="" sess_core=""
        if [[ -r "$PREFIX/config/loghound.php" ]] && [[ -n "$PHP_BIN" ]]; then
            hits_core="$("$PHP_BIN" -r 'define("LOGHOUND",1); $c=@require $argv[1]; echo $c["solr"]["hits_core"] ?? "";' \
                "$PREFIX/config/loghound.php" 2>/dev/null || true)"
            sess_core="$("$PHP_BIN" -r 'define("LOGHOUND",1); $c=@require $argv[1]; echo $c["solr"]["sessions_core"] ?? "";' \
                "$PREFIX/config/loghound.php" 2>/dev/null || true)"
        fi
        [[ -z "$hits_core" ]] && hits_core="<hits index name from config/loghound.php>"
        [[ -z "$sess_core" ]] && sess_core="<sessions index name from config/loghound.php>"

        printf '\n'
        say "  Your indexes are named:"
        say "    $hits_core"
        say "    $sess_core"
        printf '\n'
        say "  Opensolr managed: delete them in your Opensolr control panel"
        say "                    (https://opensolr.com — Indexes > Delete)"
        say "  Your own Solr:    curl 'http://SOLR/solr/admin/cores?action=UNLOAD\\"
        say "                          &core=$hits_core&deleteIndex=true&deleteDataDir=true'"
        say "                    and the same for $sess_core"
        printf '\n'
    fi

    # ---- user ----
    if id -u "$RUN_USER" >/dev/null 2>&1; then
        if confirm "Remove the system user '$RUN_USER'?" y; then
            run userdel "$RUN_USER" || warn "could not remove the user (files may still be owned by it)"
            ok "removed user '$RUN_USER'"
        fi
    fi

    step "Uninstalled"
    say "Log of this run: $INSTALL_LOG"
    exit 0
}

# =============================================================================
# Main
# =============================================================================

detect_platform

# --uninstall and --upgrade act on wherever the previous run installed to, which may not
# be the default. An explicit --prefix or LOGHOUND_PREFIX still wins.
if [[ "$MODE" == "uninstall" || "$MODE" == "upgrade" ]]; then
    discover_prefix
fi

if [[ "$MODE" == "uninstall" ]]; then
    do_uninstall
fi

preflight

# From here on, changes are made — arm the rollback.
ROLLBACK_ARMED=1

if [[ "$MODE" == "upgrade" ]]; then
    step "Upgrade"
    say "Prefix: $PREFIX"
    say "Refreshing code only. config/loghound.php and var/ are never touched."

    if prefix_is_git_checkout; then
        git_upgrade
    else
        say "the prefix is not a git working copy — copying files from $SRC_DIR"
        install_files
    fi

    fix_permissions
    verify_permissions
    install_units
    verify_no_hardcoded_prefix
    run_tests
    if (( HAVE_SYSTEMD )) && (( ! DRY_RUN )); then
        systemctl is-active --quiet loghound-tail.service && \
            { run systemctl restart loghound-tail.service; ok "restarted loghound-tail"; }
    fi
    ROLLBACK_ARMED=0
    step "Upgrade complete"
    say "loghound-tail --status --human"
    exit 0
fi

create_user
install_files
fix_permissions
snapshot_state
verify_permissions
install_units
resolve_tls
install_fpm_pool
install_vhost
verify_no_hardcoded_prefix
run_tests

# Past this point the host is configured and valid; a failure in the wizard must not
# roll back a working web server.
ROLLBACK_ARMED=0

SETUP_OK=1
run_setup || SETUP_OK=0
if (( SETUP_OK )); then
    start_and_verify || true
fi

# =============================================================================
# Final report
# =============================================================================

step "Done"

if (( DRY_RUN )); then
    say "Dry run complete. Nothing was changed."
    exit 0
fi

SCHEME="https"; [[ "$TLS_MODE" == "none" ]] && SCHEME="http"

cat <<EOF

    Loghound is installed at $PREFIX, running as '$RUN_USER'.

EOF

if [[ "$WEBSERVER" != "none" ]]; then
cat <<EOF
    PANEL
      $SCHEME://$HOSTNAME_FQDN/
      Sign in with the username and password you chose during setup.
EOF
if [[ "$TLS_MODE" == "selfsigned" ]]; then
cat <<EOF
      (Self-signed certificate: your browser will warn. Replace it with a real
       one, then re-run: sudo $0 --tls-mode existing --hostname $HOSTNAME_FQDN)
EOF
fi
cat <<EOF

    BEACON — add this one line to your site, before </body>. Without it,
    Loghound cannot measure real engaged time and cannot run the
    execution-plane checks that catch headless automation.

      <script src="$SCHEME://$HOSTNAME_FQDN/b.js?v=1" defer></script>

EOF
fi

cat <<EOF
    CHECK IT
      loghound-tail --status --human
      systemctl status loghound-tail.service
      systemctl list-timers 'loghound-*'
      journalctl -u loghound-tail -f

    READ NEXT
      $PREFIX/docs/INSTALL.md     the LogFormat that makes detection much stronger
      $PREFIX/docs/DETECTION.md   what each rule fires on, and why
      $PREFIX/docs/PRIVACY.md     what is collected, and what to tell your users

    Install log: $INSTALL_LOG
    Uninstall:   sudo $0 --uninstall

EOF

logfile "===== loghound installer finished successfully ====="
