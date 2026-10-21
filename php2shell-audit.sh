#!/bin/bash
#
# php2shell-audit.sh
#
# Audit script for PHP2Shell: CVE-2026-109618 + CVE-2026-109619
# PHP engine use-after-free across requests -> unauthenticated RCE /
# worker memory disclosure, before any application code runs.
#
# Bug surface:
#   CVE-2026-109618: on memory exhaustion PHP longjmp()s out of the request
#     while request memory is reachable but half initialised; shutdown then
#     reads the invalid state. Reached through multipart/form-data parsing
#     (session upload progress unserializer), which runs before the script.
#   CVE-2026-109619: a worker keeps global state pointing at memory owned by
#     the previous request (fatal-error backtraces on 8.5, OPcache state,
#     upload progress). The next request reads it before initialisation.
#   Affected: PHP 5.4.0 up to 8.5.11. Fixed upstream on 2026-10-21 in
#   8.5.12, 8.4.27, 8.3.36, 8.2.35. 7.4-8.1 got source backports only,
#   5.4-7.3 get nothing. Distros backport without bumping the version, so
#   the package changelog, not `php -v`, decides for distro builds.
#
# Trigger conditions on a target host:
#   1) A PHP build below the fix serves web requests: mod_php (highest
#      risk), php-cgi, PHP-FPM, LiteSpeed lsphp, FrankenPHP.
#   2) An unauthenticated multipart POST reaches it. No login, no form and
#      no vulnerable application code are needed.
#
# What this script does (read-only by default; no PoC execution, ever):
#   - Finds every PHP build in the usual system prefixes (distro, Sury,
#     Remi, cPanel EA, CloudLinux alt-php, Plesk, LiteSpeed, shared-hosting
#     php-cgiNN), asks each for its version and, for CLI/CGI, its ini.
#   - Looks for the fix in the owning package's changelog, then a per-distro
#     fix matrix, then the upstream version thresholds.
#   - Works out which builds serve the web (SAPI, mod_php LoadModule lines).
#   - Reports the interim settings (memory_limit=-1, upload progress off,
#     fatal_error_backtraces off on 8.5, FPM pm.max_requests=1).
#   - Scans web roots for per-directory ini overrides and web shells.
#   - Hunts logs for PHP worker crashes and shells spawned by PHP workers.
#   - Computes a risk score and prints a verdict (PATCHED / MITIGATED /
#     VULNERABLE / UNKNOWN / NOT_APPLICABLE).
#   - Optional --json emits structured output for ingest.
#
# Author handle: Quaerendir
# License: MIT
# Tested intent: Debian, Ubuntu, RHEL/Rocky/Alma, cPanel/CloudLinux, shared
# hosting without root.
#
# Usage:
#   ./php2shell-audit.sh                      # text report
#   ./php2shell-audit.sh --json               # JSON report on stdout
#   ./php2shell-audit.sh --php /path/to/php   # add a build (repeatable)
#   ./php2shell-audit.sh --webroot ~/WWW      # scan this web root (repeatable)
#   ./php2shell-audit.sh --no-webroot         # skip the web root scan
#   ./php2shell-audit.sh --since 2026-10-15   # change IoC hunt window
#   ./php2shell-audit.sh --no-hunt            # skip log and process hunt
#   ./php2shell-audit.sh --quiet              # only verdict + exit code
#
# Exit codes:
#   0 = PATCHED or NOT_APPLICABLE
#   1 = MITIGATED (unfixed builds exist, but none of them serves the web)
#   2 = VULNERABLE (an unfixed build serves web requests)
#   3 = UNKNOWN   (cannot determine; treat as suspect)
#   4 = ERROR     (script could not run; bad env / missing tools)
#
# This script never sends a request, never runs the PoC and never changes
# php.ini, pool configs or any other persistent state. It does execute the
# PHP binaries it finds, with -v and a read-only ini_get() snippet.
#

set -u
set -o pipefail
# Pinned PATH for the external commands below. It cannot protect the
# interpreter itself, which is why the shebang is /bin/bash, not env.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
# Test hook: tests/run_tests.sh prepends its mock_bin/ here. Never honoured
# for root, so the pinned PATH above still holds for real audits.
if [ -n "${PHP2SHELL_TEST_PATH:-}" ] && [ "${EUID:-0}" -ne 0 ]; then
  PATH="${PHP2SHELL_TEST_PATH}:${PATH}"
fi
LC_ALL=C
export PATH LC_ALL

VERSION="1.0.0"

# Every file the audit reads lives under $R. Empty on a real host; the tests
# point it at a fixture tree. Like the PATH hook, ignored for root.
R=""
if [ -n "${PHP2SHELL_TEST_ROOT:-}" ] && [ "${EUID:-0}" -ne 0 ]; then
  R="${PHP2SHELL_TEST_ROOT}"
fi

# ------------------------------------------------------------------ banner
print_banner() {
  # Disable colour if not a TTY or NO_COLOR set, per CLICOLOR convention.
  local C0="" C1="" C2="" C3=""
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C0=$'\033[0m'        # reset
    C1=$'\033[1;35m'     # bright magenta - title
    C2=$'\033[1;33m'     # bright yellow  - request
    C3=$'\033[0;36m'     # cyan           - subtitle
  fi
  printf '%s' "$C1"
  cat <<'BANNER'

   ___ _  _ ___ ___ ___ _        _ _
  | _ \ || | _ \_  ) __| |_  ___| | |
  |  _/ __ |  _// /\__ \ ' \/ -_) | |
  |_| |_||_|_| /___|___/_||_\___|_|_|
BANNER
  printf '%s%s     CVE-2026-109618 + CVE-2026-109619%s  PHP cross-request use-after-free\n' "$C0" "$C3" "$C0"
  printf '%s     audit script %s%s  by Quaerendir\n' "$C3" "$VERSION" "$C0"
  printf '%s' "$C2"
  cat <<'BANNER'

      POST / HTTP/1.1
      Content-Type: multipart/form-data    ====> memory_limit hit, longjmp()
      PHP_SESSION_UPLOAD_PROGRESS=1              next request: "who freed this?"

BANNER
  printf '%s' "$C0"
}

# ------------------------------------------------------------------ helpers
say()  { [ "$QUIET" -eq 1 ] && return 0; [ "$JSON" -eq 1 ] && return 0; printf '%s\n' "$*"; }
hdr()  { say ""; say "== $* =="; }
kv()   { say "  $1: $2"; }
warn() { say "  ! $*"; }
ok()   { say "  + $*"; }
bad()  { say "  - $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# JSON accumulator (flat dict)
declare -A J
jset() { J["$1"]="$2"; }

# Compare two dpkg/rpm-style package versions. Returns 0 if $1 >= $2.
ver_ge() {
  if have dpkg; then
    dpkg --compare-versions "$1" ge "$2" 2>/dev/null && return 0 || return 1
  fi
  local smaller
  smaller="$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)"
  [ "$smaller" = "$2" ]
}

# ini booleans come back from ini_get() as "1", "", "0", or the raw word.
ini_on() {
  case "${1,,}" in
    1|on|yes|true) return 0 ;;
  esac
  return 1
}

# Run a found PHP binary with a time limit. stdin is closed so a php-cgi
# that is not given a script cannot sit waiting for one.
run_php() {
  if have timeout; then
    timeout 10 "$@" </dev/null 2>/dev/null
  else
    "$@" </dev/null 2>/dev/null
  fi
}

# Upstream fix status for a PHP version "maj min pat". Thresholds are the
# 2026-10-21 releases; 7.4-8.1 only got source backports (no release to
# compare with) and 5.4-7.3 got nothing. Sets UP_STATUS / UP_DETAIL.
upstream_status() {
  local maj="$1" min="$2" pat="$3" fix=""
  if [ "$maj" -lt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -lt 4 ]; }; then
    UP_STATUS="NOT_APPLICABLE"; UP_DETAIL="PHP ${maj}.${min} predates the affected code (5.4.0)"
    return 0
  fi
  case "${maj}.${min}" in
    8.5) fix=12 ;;
    8.4) fix=27 ;;
    8.3) fix=36 ;;
    8.2) fix=35 ;;
  esac
  if [ -n "$fix" ]; then
    if [ "$pat" -ge "$fix" ]; then
      UP_STATUS="PATCHED";    UP_DETAIL="${maj}.${min}.${pat} >= ${maj}.${min}.${fix}"
    else
      UP_STATUS="VULNERABLE"; UP_DETAIL="${maj}.${min}.${pat} < ${maj}.${min}.${fix}"
    fi
  elif [ "$maj" -gt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -gt 5 ]; }; then
    UP_STATUS="UNKNOWN";      UP_DETAIL="branch ${maj}.${min} is not in the fix table"
  else
    UP_STATUS="VULNERABLE"
    UP_DETAIL="branch ${maj}.${min} is end of life: no upstream release with the fix"
  fi
}

# Distro fix matrix, snapshot 2026-10-21. Prints the first fixed package
# version for distro $1, release $2, PHP branch $3, or nothing.
#   Debian:  trixie php8.4 8.4.27-1~deb13u1 (DSA-6574-1)
#            bookworm php8.2 8.2.35-1~deb12u1 (DLA-4848-1)
#   Ubuntu:  USN-8948-1/-2: jammy php8.1 8.1.2-1ubuntu2.28,
#            noble php8.3 8.3.6-0ubuntu0.24.04.13, resolute php8.5 8.5.4-0ubuntu1.5
matrix_fixed() {
  case "${1,,} $2 $3" in
    "debian 13 8.4")    echo "8.4.27-1~deb13u1" ;;
    "debian 12 8.2")    echo "8.2.35-1~deb12u1" ;;
    "ubuntu 22.04 8.1") echo "8.1.2-1ubuntu2.28" ;;
    "ubuntu 24.04 8.3") echo "8.3.6-0ubuntu0.24.04.13" ;;
    "ubuntu 26.04 8.5") echo "8.5.4-0ubuntu1.5" ;;
  esac
}

FIX_RE='CVE-2026-109618|CVE-2026-109619|php2shell'

# Package data for one binary (path without $R). Sets P_NAME P_VERSION
# P_KIND P_CHANGELOG (fixed / absent / unreadable / none).
package_info() {
  local p="$1" line d f cl
  P_NAME=""; P_VERSION=""; P_KIND=""; P_CHANGELOG="none"
  if have dpkg; then
    line="$(dpkg -S "$p" 2>/dev/null | head -n1 || true)"
    if [ -n "$line" ]; then
      P_NAME="${line%%:*}"
      P_NAME="${P_NAME%%,*}"
      P_VERSION="$(dpkg-query -W -f='${Version}' "$P_NAME" 2>/dev/null || true)"
      P_KIND="deb"
    fi
  fi
  if [ -z "$P_KIND" ] && have rpm; then
    line="$(rpm -qf "$p" --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | head -n1 || true)"
    case "$line" in
      ""|*"not owned"*|*"No such"*) ;;
      *) P_NAME="${line%% *}"; P_VERSION="${line#* }"; P_KIND="rpm" ;;
    esac
  fi
  [ -n "$P_KIND" ] || return 0
  P_CHANGELOG="unreadable"
  if [ "$P_KIND" = "deb" ]; then
    # Debian links the php8.x-* doc dirs to php8.x-common; follow the
    # binary package first, then the common one.
    for d in "$P_NAME" "${P_NAME%%-*}-common"; do
      f="$R/usr/share/doc/${d}/changelog.Debian.gz"
      [ -r "$f" ] || continue
      if zcat "$f" 2>/dev/null | grep -qiE "$FIX_RE"; then P_CHANGELOG="fixed"; else P_CHANGELOG="absent"; fi
      break
    done
  else
    cl="$(rpm -q --changelog "$P_NAME" 2>/dev/null || true)"
    if [ -n "$cl" ]; then
      if printf '%s\n' "$cl" | grep -qiE "$FIX_RE"; then P_CHANGELOG="fixed"; else P_CHANGELOG="absent"; fi
    fi
  fi
}

# Read-only ini probe. array() keeps it valid on PHP 5.4.
# shellcheck disable=SC2016  # PHP code, $k and $v are PHP variables
INI_PROBE='foreach (array("memory_limit","session.upload_progress.enabled","fatal_error_backtraces","post_max_size","file_uploads") as $k) { $v = ini_get($k); echo $k, "=", ($v === false ? "<unset>" : $v), "\n"; } echo "session_ext=", (extension_loaded("session") ? 1 : 0), "\n";'

ini_val() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n1; }

main() {
# ------------------------------------------------------------------ args
JSON=0
QUIET=0
HUNT=1
BANNER=1
SCAN_WEB=1
SINCE="2026-10-20"   # details leaked on 2026-10-20, a day before the fix
UNTIL=""
EXTRA_PHP=()
WEBROOTS=()
while [ $# -gt 0 ]; do
  local arg="$1"
  case "$arg" in
    --json)        JSON=1; BANNER=0 ;;
    --quiet)       QUIET=1; BANNER=0 ;;
    --no-hunt)     HUNT=0 ;;
    --no-banner)   BANNER=0 ;;
    --no-webroot)  SCAN_WEB=0 ;;
    --php=*)       EXTRA_PHP+=("${arg#--php=}") ;;
    --php)         shift; [ -n "${1:-}" ] && EXTRA_PHP+=("$1") ;;
    --webroot=*)   WEBROOTS+=("${arg#--webroot=}") ;;
    --webroot)     shift; [ -n "${1:-}" ] && WEBROOTS+=("$1") ;;
    --since=*)     SINCE="${arg#--since=}" ;;
    --since)       shift; SINCE="${1:-$SINCE}" ;;
    --until=*)     UNTIL="${arg#--until=}" ;;
    --until)       shift; UNTIL="${1:-$UNTIL}" ;;
    --version)     printf '%s\n' "php2shell-audit.sh ${VERSION}"; exit 0 ;;
    -h|--help)
      awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
    -*)
      printf 'ERROR: unknown option %s\n' "$arg" >&2
      exit 4 ;;
    *)
      printf 'ERROR: unexpected argument %s\n' "$arg" >&2
      exit 4 ;;
  esac
  shift
done

# Associative arrays and ${v,,} need bash 4+.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  printf 'ERROR: requires bash >= 4 (found %s)\n' "${BASH_VERSION:-non-bash}" >&2
  exit 4
fi

for _tool in uname grep awk sed sort find readlink; do
  if ! have "$_tool"; then
    printf 'ERROR: required tool %s is missing\n' "$_tool" >&2
    exit 4
  fi
done

[ "$BANNER" -eq 1 ] && print_banner

# ------------------------------------------------------------------ inventory
HOST="$(uname -n 2>/dev/null || echo unknown)"
KMACH="$(uname -m 2>/dev/null || echo unknown)"
jset hostname "$HOST"
jset arch     "$KMACH"
jset audit_as_root "$( [ "${EUID:-0}" -eq 0 ] && echo 1 || echo 0 )"

OS_ID=""; OS_VER=""; OS_PRETTY=""
OS_RELEASE_FILE="$R/etc/os-release"
if [ -r "$OS_RELEASE_FILE" ]; then
  # Parsed as plain key=value text, not sourced - /etc/os-release is
  # shell syntax and sourcing it would execute arbitrary embedded code.
  OS_ID="$(sed -n 's/^ID=//p' "$OS_RELEASE_FILE" | head -n1 | tr -d '"'"'"'')"
  OS_VER="$(sed -n 's/^VERSION_ID=//p' "$OS_RELEASE_FILE" | head -n1 | tr -d '"'"'"'')"
  OS_PRETTY="$(sed -n 's/^PRETTY_NAME=//p' "$OS_RELEASE_FILE" | head -n1 | tr -d '"'"'"'')"
fi
jset distro_id      "$OS_ID"
jset distro_version "$OS_VER"
jset distro_pretty  "$OS_PRETTY"

hdr "Host inventory"
kv "host"   "$HOST"
kv "arch"   "$KMACH"
kv "distro" "${OS_PRETTY:-unknown}"
[ "${EUID:-0}" -ne 0 ] && warn "not root: config and logs of other users may be unreadable (fine on shared hosting)"

# ------------------------------------------------------------------ discovery
# System prefixes only: as root the script executes what it finds, so it
# never looks in home directories on its own (use --php for that).
CANDIDATES=()
# Quoted, so each pattern is expanded once, under $R, and not first against
# the live filesystem.
PHP_GLOBS=(
  '/usr/bin/php' '/usr/bin/php[0-9]*' '/usr/bin/php-cgi*' '/usr/bin/php.bin*'
  '/usr/sbin/php-fpm*' '/usr/local/bin/php*' '/usr/local/sbin/php-fpm*'
  '/usr/local/php*/bin/php' '/usr/local/php*/bin/php-cgi' '/usr/local/php*/sbin/php-fpm'
  '/opt/remi/php*/root/usr/bin/php' '/opt/remi/php*/root/usr/sbin/php-fpm'
  '/opt/cpanel/ea-php*/root/usr/bin/php' '/opt/cpanel/ea-php*/root/usr/sbin/php-fpm'
  '/opt/alt/php*/usr/bin/php' '/opt/alt/php*/usr/bin/lsphp'
  '/opt/plesk/php/*/bin/php' '/opt/plesk/php/*/sbin/php-fpm'
  '/usr/local/lsws/lsphp*/bin/lsphp' '/usr/local/bin/frankenphp' '/usr/bin/frankenphp'
)
for g in "${PHP_GLOBS[@]}"; do
  # shellcheck disable=SC2086  # $g is a glob pattern and must expand here
  for f in "$R"$g; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    case "${f##*/}" in
      php|php[0-9]*|php-cgi|php-cgi[0-9]*|php.bin*|php-fpm|php-fpm[0-9]*|lsphp|frankenphp) ;;
      *) continue ;;
    esac
    case "${f##*/}" in *-config*|*ize*|*.so) continue ;; esac
    CANDIDATES+=("$f")
  done
done
for f in "${EXTRA_PHP[@]}"; do CANDIDATES+=("$f"); done

declare -A SEEN
B_PATH=(); B_VER=(); B_SAPI=(); B_STATUS=(); B_DETAIL=(); B_WEB=(); B_BRANCH=()
B_PKG=(); B_ML=(); B_UP=(); B_FEB=(); B_INTERIM=()

# mod_php: LoadModule lines decide which branch Apache runs in-process.
MOD_PHP=0; MOD_PHP_BRANCHES=""; MOD_PHP_ANY=0
for f in "$R"/etc/apache2/mods-enabled/*.load "$R"/etc/httpd/conf.modules.d/*.conf \
         "$R"/etc/httpd/conf/httpd.conf "$R"/etc/apache2/httpd.conf "$R"/usr/local/apache/conf/httpd.conf; do
  [ -r "$f" ] || continue
  # Here-strings, not < <( ): shared hosts often deny /dev/fd to users.
  while read -r so; do
    [ -n "$so" ] || continue
    MOD_PHP=1
    if [[ "$so" =~ libphp([0-9]+\.[0-9]+)\.so$ ]]; then
      MOD_PHP_BRANCHES="${MOD_PHP_BRANCHES} ${BASH_REMATCH[1]}"
    else
      # libphp.so / libphp7.so / mod_php.so: branch not in the name.
      MOD_PHP_ANY=1
    fi
  done <<< "$(sed -n 's/^[[:space:]]*LoadModule[[:space:]]\{1,\}php[0-9]*_module[[:space:]]\{1,\}//p' "$f" | awk '{print $1}')"
done
jset mod_php          "$MOD_PHP"
jset mod_php_branches "${MOD_PHP_BRANCHES# }"

hdr "PHP builds"
n=0
for f in "${CANDIDATES[@]}"; do
  [ -x "$f" ] || { warn "${f#"$R"}: not executable, skipped"; continue; }
  real="$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")"
  [ -n "${SEEN[$real]:-}" ] && continue
  SEEN[$real]=1
  # As root, refuse to execute anything a non-root user could have replaced.
  if [ "${EUID:-0}" -eq 0 ] && [ -n "$(find "$real" \( ! -user 0 -o -perm /022 \) 2>/dev/null)" ]; then
    warn "${f}: not root-owned or group/world writable, not executed"
    continue
  fi
  vline="$(run_php "$f" -v | grep -m1 -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*( \([a-z0-9-]+\))?' || true)"
  if [[ ! "$vline" =~ ^PHP\ ([0-9]+)\.([0-9]+)\.([0-9]+)([^ ]*)( \(([a-z0-9-]+)\))?$ ]]; then
    warn "${f#"$R"}: no PHP version from -v, skipped"
    continue
  fi
  maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
  ver="${maj}.${min}.${pat}${BASH_REMATCH[4]}"
  sapi="${BASH_REMATCH[6]:-}"
  [ -z "$sapi" ] && [ "${f##*/}" = "frankenphp" ] && sapi="frankenphp"
  [ -z "$sapi" ] && sapi="unknown"
  branch="${maj}.${min}"

  upstream_status "$maj" "$min" "$pat"
  package_info "${f#"$R"}"
  status="$UP_STATUS"; detail="upstream: $UP_DETAIL"
  if [ "$UP_STATUS" = "PATCHED" ] || [ "$UP_STATUS" = "NOT_APPLICABLE" ]; then
    :
  elif [ "$P_CHANGELOG" = "fixed" ]; then
    status="PATCHED"; detail="fix listed in ${P_NAME} ${P_VERSION} changelog"
  elif [ -n "$P_KIND" ]; then
    # Distro builds keep the upstream version, so a low version proves
    # nothing on its own: the matrix or a readable changelog has to decide.
    fixed_min="$(matrix_fixed "$OS_ID" "$OS_VER" "$branch")"
    if [ -n "$fixed_min" ] && [ -n "$P_VERSION" ] && ver_ge "$P_VERSION" "$fixed_min"; then
      status="PATCHED";    detail="${P_NAME} ${P_VERSION} >= fixed ${fixed_min}"
    elif [ -n "$fixed_min" ] && [ -n "$P_VERSION" ]; then
      status="VULNERABLE"; detail="${P_NAME} ${P_VERSION} < fixed ${fixed_min}"
    elif [ "$P_CHANGELOG" = "absent" ]; then
      status="VULNERABLE"; detail="${P_NAME} ${P_VERSION}: changelog lacks the fix; ${UP_DETAIL}"
    else
      status="UNKNOWN";    detail="${P_NAME} ${P_VERSION}: changelog not readable, a backport is possible; ${UP_DETAIL}"
    fi
  else
    detail="not package-managed (custom build): ${UP_DETAIL}"
  fi

  web=0
  case "$sapi" in
    cgi-fcgi|fpm-fcgi|litespeed|frankenphp|apache2handler) web=1 ;;
  esac
  case " ${MOD_PHP_BRANCHES} " in *" ${branch} "*) web=1 ;; esac
  [ "$MOD_PHP_ANY" -eq 1 ] && [ "$sapi" = "cli" ] && web=1

  ml=""; up=""; feb=""; interim="n/a"
  if [ "$sapi" = "cli" ] || [ "$sapi" = "cgi-fcgi" ]; then
    if [ "$sapi" = "cli" ]; then
      ini="$(run_php "$f" -r "$INI_PROBE" || true)"
    else
      # php-cgi has no -r; it runs a script given on stdin.
      ini="$(printf '<?php %s' "$INI_PROBE" | { if have timeout; then timeout 10 "$f" -q; else "$f" -q; fi; } 2>/dev/null || true)"
    fi
    ml="$(ini_val "$ini" memory_limit)"
    up="$(ini_val "$ini" session.upload_progress.enabled)"
    feb="$(ini_val "$ini" fatal_error_backtraces)"
    sess="$(ini_val "$ini" session_ext)"
    if [ -n "$ml" ]; then
      up_off=1; ini_on "$up" && [ "$sess" != "0" ] && up_off=0
      feb_off=1; [ "$branch" = "8.5" ] && ini_on "$feb" && feb_off=0
      ml_off=0; [ "$ml" = "-1" ] && ml_off=1
      if [ $((up_off + feb_off + ml_off)) -eq 3 ]; then interim="full"
      elif [ $((up_off + ml_off)) -gt 0 ] || { [ "$branch" = "8.5" ] && [ "$feb_off" -eq 1 ]; }; then interim="partial"
      else interim="none"
      fi
    fi
  fi

  B_PATH+=("${f#"$R"}"); B_VER+=("$ver"); B_SAPI+=("$sapi"); B_STATUS+=("$status")
  B_DETAIL+=("$detail"); B_WEB+=("$web"); B_BRANCH+=("$branch")
  B_PKG+=("${P_NAME:+$P_NAME $P_VERSION}"); B_ML+=("$ml"); B_UP+=("$up"); B_FEB+=("$feb"); B_INTERIM+=("$interim")

  jset "php_${n}_path"    "${f#"$R"}"
  jset "php_${n}_version" "$ver"
  jset "php_${n}_sapi"    "$sapi"
  jset "php_${n}_status"  "$status"
  jset "php_${n}_detail"  "$detail"
  jset "php_${n}_web"     "$web"
  jset "php_${n}_package" "${P_NAME:+$P_NAME $P_VERSION}"
  jset "php_${n}_changelog" "$P_CHANGELOG"
  jset "php_${n}_interim" "$interim"
  [ -n "$ml" ] && jset "php_${n}_memory_limit" "$ml"
  [ -n "$ml" ] && jset "php_${n}_upload_progress" "$up"

  line="${f#"$R"}  ${ver} (${sapi})$( [ "$web" -eq 1 ] && echo ', serves web')  ${status}: ${detail}"
  case "$status" in
    PATCHED|NOT_APPLICABLE) ok "$line" ;;
    VULNERABLE)             bad "$line" ;;
    *)                      warn "$line" ;;
  esac
  n=$((n+1))
done
jset php_builds "$n"
[ "$n" -eq 0 ] && say "  . no PHP build found (use --php PATH for unusual locations)"
[ "$MOD_PHP" -eq 1 ] && warn "Apache loads mod_php (${MOD_PHP_BRANCHES# }$( [ "$MOD_PHP_ANY" -eq 1 ] && echo ' branch unknown')): highest-risk SAPI"

# ------------------------------------------------------------------ interim settings
hdr "Interim settings (reduce exposure, do not make a host safe)"
POOLS=0; POOL_ML=0; POOL_UP=0; POOL_MAXREQ=0
for f in "$R"/etc/php/*/fpm/pool.d/*.conf "$R"/etc/php-fpm.d/*.conf \
         "$R"/etc/opt/remi/php*/php-fpm.d/*.conf "$R"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf \
         "$R"/opt/alt/php*/etc/php-fpm.d/*.conf "$R"/opt/plesk/php/*/etc/php-fpm.d/*.conf; do
  [ -r "$f" ] || continue
  POOLS=$((POOLS+1))
  grep -qiE '^[[:space:]]*php_admin_value\[memory_limit\][[:space:]]*=[[:space:]]*-1' "$f" && POOL_ML=$((POOL_ML+1))
  grep -qiE '^[[:space:]]*php_admin_flag\[session\.upload_progress\.enabled\][[:space:]]*=[[:space:]]*(off|0|false|no)' "$f" && POOL_UP=$((POOL_UP+1))
  grep -qiE '^[[:space:]]*pm\.max_requests[[:space:]]*=[[:space:]]*1[[:space:]]*$' "$f" && POOL_MAXREQ=$((POOL_MAXREQ+1))
done
jset fpm_pools                  "$POOLS"
jset fpm_pools_memory_limit_off "$POOL_ML"
jset fpm_pools_upload_progress_off "$POOL_UP"
jset fpm_pools_max_requests_1   "$POOL_MAXREQ"

i=0
while [ "$i" -lt "$n" ]; do
  if [ -n "${B_ML[i]}" ] && [ "${B_STATUS[i]}" != "NOT_APPLICABLE" ]; then
    kv "${B_PATH[i]}" "memory_limit=${B_ML[i]} upload_progress=${B_UP[i]:-off}$( [ "${B_BRANCH[i]}" = "8.5" ] && echo " fatal_error_backtraces=${B_FEB[i]:-off}") -> ${B_INTERIM[i]}"
  fi
  i=$((i+1))
done
if [ "$POOLS" -gt 0 ]; then
  kv "FPM pools" "${POOLS} readable; admin memory_limit=-1: ${POOL_ML}, upload_progress off: ${POOL_UP}, pm.max_requests=1: ${POOL_MAXREQ}"
fi
say "  . values come from the global ini seen by CLI/CGI; per-pool and per-directory"
say "    overrides are reported separately. .user.ini and ini_set() apply too late."

# ------------------------------------------------------------------ web roots
if [ "$SCAN_WEB" -eq 1 ] && [ "${#WEBROOTS[@]}" -eq 0 ]; then
  for d in /var/www /srv/www /srv/http /usr/share/nginx/html; do
    [ -d "$R$d" ] && WEBROOTS+=("$R$d")
  done
  if [ -z "$R" ] && [ "${EUID:-0}" -ne 0 ] && [ -n "${HOME:-}" ]; then
    for d in public_html www WWW htdocs domains; do
      [ -d "$HOME/$d" ] && WEBROOTS+=("$HOME/$d")
    done
  fi
fi
[ "$SCAN_WEB" -eq 0 ] && WEBROOTS=()

PERDIR_INI=0; WEBSHELLS=0; RECENT_PHP=0; UPLOAD_PHP=0
# shellcheck disable=SC2016  # regex for literal $_GET etc.
WEBSHELL_RE='eval\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)|assert\(\s*\$_|(system|passthru|shell_exec|exec|popen|proc_open)\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
if [ "${#WEBROOTS[@]}" -gt 0 ]; then
  hdr "Web roots (since ${SINCE})"
  for w in "${WEBROOTS[@]}"; do
    [ -d "$w" ] || { warn "${w}: not a directory"; continue; }
    c="$(find "$w" -maxdepth 8 \( -name .user.ini -o -name .htaccess -o -name php.ini \) -type f 2>/dev/null \
          | while read -r x; do grep -qiE '^[^;#]*(upload_progress\.enabled|memory_limit|fatal_error_backtraces)' "$x" 2>/dev/null && echo "$x"; done \
          | wc -l)"
    r="$(find "$w" -type f -name '*.php' -newermt "$SINCE" 2>/dev/null | wc -l)"
    u="$(find "$w" -type f -path '*/uploads/*' -name '*.php*' ! -name 'index.php' 2>/dev/null | wc -l)"
    s="$( { find "$w" -type f -name '*.php*' -newermt "$SINCE" -size -4M -print0 2>/dev/null
            find "$w" -type f -path '*/uploads/*' -name '*.php*' -size -4M -print0 2>/dev/null; } \
          | xargs -0 -r grep -lE "$WEBSHELL_RE" 2>/dev/null | sort -u)"
    sc=0; [ -n "$s" ] && sc="$(printf '%s\n' "$s" | wc -l)"
    PERDIR_INI=$((PERDIR_INI+c)); RECENT_PHP=$((RECENT_PHP+r)); UPLOAD_PHP=$((UPLOAD_PHP+u)); WEBSHELLS=$((WEBSHELLS+sc))
    kv "${w#"$R"}" "per-dir ini overrides=${c} php changed since ${SINCE}=${r} php in uploads=${u} web shell patterns=${sc}"
    [ "$sc" -gt 0 ] && printf '%s\n' "$s" | head -n 10 | while read -r x; do bad "web shell pattern: ${x#"$R"}"; done
  done
  [ "$PERDIR_INI" -gt 0 ] && say "  . per-directory overrides found: not counted as a mitigation"
fi
jset webroots_scanned     "${#WEBROOTS[@]}"
jset perdir_ini_overrides "$PERDIR_INI"
jset php_changed_since    "$RECENT_PHP"
jset php_in_uploads       "$UPLOAD_PHP"
jset webshell_hits        "$WEBSHELLS"

# ------------------------------------------------------------------ behavioural IoC hunt
CRASH_HITS=0; SPAWN_HITS=0; SPAWN_LIST=""
if [ "$HUNT" -eq 1 ]; then
  if [ -n "${UNTIL:-}" ]; then hdr "Behavioural IoC hunt (since ${SINCE} until ${UNTIL})"
  else hdr "Behavioural IoC hunt (since ${SINCE})"; fi

  CRASH_RE='(php-fpm|php-cgi|lsphp|httpd|apache2|frankenphp|php)[^ ]*(\[[0-9]+\])?: segfault|exited on signal (6|11)|exit signal (Segmentation fault|Aborted)|AH00052'
  if have journalctl; then
    JR=(--since "$SINCE"); [ -n "$UNTIL" ] && JR+=(--until "$UNTIL")
    h="$(journalctl "${JR[@]}" --no-pager 2>/dev/null | grep -ciE "$CRASH_RE" || true)"
    CRASH_HITS=$((CRASH_HITS + ${h:-0}))
  fi
  # Log files are not date-filtered: the count covers the whole current file.
  for f in "$R"/var/log/apache2/error.log "$R"/var/log/httpd/error_log "$R"/var/log/php*-fpm.log \
           "$R"/var/log/php-fpm/error.log "$R"/usr/local/lsws/logs/error.log; do
    [ -r "$f" ] || continue
    h="$(grep -ciE "$CRASH_RE" "$f" 2>/dev/null || true)"
    CRASH_HITS=$((CRASH_HITS + ${h:-0}))
  done
  if [ "$CRASH_HITS" -gt 0 ]; then
    warn "PHP worker crash lines in logs: ${CRASH_HITS} (failed attempts crash workers)"
  else
    ok "no PHP worker crash lines in readable logs"
  fi

  # Live: a shell or downloader whose parent is a PHP worker or Apache.
  PS_OUT="$(ps -eo pid=,ppid=,comm= 2>/dev/null || true)"
  declare -A PCOMM
  while read -r pid _ comm; do [ -n "${pid:-}" ] && PCOMM[$pid]="$comm"; done <<< "$PS_OUT"
  while read -r pid ppid comm; do
    [ -n "${pid:-}" ] || continue
    case "$comm" in
      sh|bash|dash|ash|zsh|curl|wget|nc|ncat|socat|perl|python|python[0-9]*) ;;
      *) continue ;;
    esac
    case "${PCOMM[$ppid]:-}" in
      php-fpm*|php-cgi*|lsphp*|httpd|apache2|frankenphp)
        SPAWN_HITS=$((SPAWN_HITS+1))
        SPAWN_LIST="${SPAWN_LIST:+$SPAWN_LIST,}${comm}(${pid})<-${PCOMM[$ppid]}(${ppid})" ;;
    esac
  done <<< "$PS_OUT"
  if [ "$SPAWN_HITS" -gt 0 ]; then
    bad "processes spawned by PHP/Apache workers: ${SPAWN_LIST}"
  else
    ok "no shell or downloader running under a PHP/Apache worker"
  fi
fi
IOC_HITS=$((CRASH_HITS + SPAWN_HITS + WEBSHELLS))
jset crash_hits  "$CRASH_HITS"
jset spawn_hits  "$SPAWN_HITS"
jset spawn_list  "$SPAWN_LIST"
jset ioc_hits    "$IOC_HITS"

# ------------------------------------------------------------------ verdict
VULN=0; VULN_WEB=0; UNK=0; UNK_WEB=0; PATCHED_N=0; EOL_WEB=0; MODPHP_VULN=0; INTERIM_FULL_WEB=1; ANY_RELEVANT=0
i=0
while [ "$i" -lt "$n" ]; do
  case "${B_STATUS[i]}" in
    PATCHED)    PATCHED_N=$((PATCHED_N+1)); ANY_RELEVANT=1 ;;
    VULNERABLE)
      VULN=$((VULN+1)); ANY_RELEVANT=1
      if [ "${B_WEB[i]}" -eq 1 ]; then
        VULN_WEB=$((VULN_WEB+1))
        case "${B_BRANCH[i]}" in 8.2|8.3|8.4|8.5) ;; *) EOL_WEB=1 ;; esac
        case " ${MOD_PHP_BRANCHES} " in *" ${B_BRANCH[i]} "*) MODPHP_VULN=1 ;; esac
        [ "$MOD_PHP_ANY" -eq 1 ] && MODPHP_VULN=1
        [ "${B_INTERIM[i]}" = "full" ] || INTERIM_FULL_WEB=0
      fi
      ;;
    UNKNOWN)
      UNK=$((UNK+1)); ANY_RELEVANT=1
      [ "${B_WEB[i]}" -eq 1 ] && UNK_WEB=$((UNK_WEB+1))
      ;;
  esac
  i=$((i+1))
done
# Pools that pin every interim value count for FPM builds.
if [ "$POOLS" -gt 0 ] && [ "$POOL_ML" -eq "$POOLS" ] && [ "$POOL_UP" -eq "$POOLS" ]; then
  POOLS_PINNED=1
else
  POOLS_PINNED=0
fi
jset php_builds_vulnerable     "$VULN"
jset php_builds_vulnerable_web "$VULN_WEB"
jset php_builds_unknown        "$UNK"
jset php_builds_patched        "$PATCHED_N"
jset eol_branch_serves_web     "$EOL_WEB"

final="NOT_APPLICABLE"; exit_code=0; reason="no affected PHP build found"
if [ "$VULN_WEB" -gt 0 ]; then
  final="VULNERABLE"; exit_code=2; reason="${VULN_WEB} unfixed build(s) serve web requests"
elif [ "$UNK_WEB" -gt 0 ]; then
  final="UNKNOWN"; exit_code=3; reason="${UNK_WEB} web-serving build(s) could not be classified"
elif [ "$VULN" -gt 0 ]; then
  # Nothing unfixed serves the web, and the bug needs a web request.
  final="MITIGATED"; exit_code=1; reason="${VULN} unfixed build(s), none of them serves the web"
elif [ "$UNK" -gt 0 ]; then
  final="UNKNOWN"; exit_code=3; reason="${UNK} build(s) could not be classified"
elif [ "$ANY_RELEVANT" -eq 1 ]; then
  final="PATCHED"; exit_code=0; reason="every affected build carries the fix"
fi
jset verdict "$final"
jset verdict_reason "$reason"

# ------------------------------------------------------------------ risk scoring
#
# Score model (0..100). Tuned so that:
#   - patched                                         -> 0
#   - unfixed CLI only                                -> 50
#   - unfixed php-cgi/FPM serving the web, no interim -> 75
#   - unfixed mod_php                                 -> 85
#   - + IoCs                                          -> +10 (capped)
#
SCORE=0
case "$final" in
  VULNERABLE|MITIGATED) SCORE=50 ;;
  UNKNOWN)              SCORE=30 ;;
esac
if [ "$VULN_WEB" -gt 0 ] || [ "$UNK_WEB" -gt 0 ]; then
  SCORE=$((SCORE+15))
  [ "$MODPHP_VULN" -eq 1 ] && SCORE=$((SCORE+10))
  [ "$EOL_WEB" -eq 1 ]     && SCORE=$((SCORE+5))
  if [ "$VULN_WEB" -gt 0 ] && [ "$INTERIM_FULL_WEB" -eq 0 ] && [ "$POOLS_PINNED" -eq 0 ]; then
    SCORE=$((SCORE+10))
  fi
fi
[ "$IOC_HITS" -gt 0 ] && SCORE=$((SCORE+10))
[ "$SCORE" -gt 100 ] && SCORE=100
jset risk_score "$SCORE"

# ------------------------------------------------------------------ output
if [ "$JSON" -eq 1 ]; then
  # Emit JSON. Keep it dependency-free; no jq needed.  Keys are sorted;
  # values that look like non-negative integers are emitted as numbers.
  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }
  printf '{'
  first=1
  mapfile -t sorted_keys <<< "$(printf '%s\n' "${!J[@]}" | sort)"
  for k in "${sorted_keys[@]}"; do
    v="${J[$k]}"
    if [ $first -eq 1 ]; then first=0; else printf ','; fi
    if [[ "$v" =~ ^[0-9]+$ ]]; then
      printf '"%s":%s' "$k" "$v"
    else
      printf '"%s":"%s"' "$k" "$(json_escape "$v")"
    fi
  done
  printf '}\n'
  exit "$exit_code"
fi

if [ "$QUIET" -eq 1 ]; then
  printf '%s (%d/100): %s\n' "$final" "$SCORE" "$reason"
  exit "$exit_code"
fi

hdr "Summary"
kv "verdict"    "$final"
kv "reason"     "$reason"
kv "risk score" "$SCORE / 100"
kv "builds"     "total=$n patched=$PATCHED_N vulnerable=$VULN (web=$VULN_WEB) unknown=$UNK (web=$UNK_WEB)"
kv "mod_php"    "$MOD_PHP${MOD_PHP_BRANCHES:+ (${MOD_PHP_BRANCHES# })}"
kv "ioc hits"   "$IOC_HITS (crashes=$CRASH_HITS spawned=$SPAWN_HITS webshells=$WEBSHELLS)"

say ""
case "$final" in
  PATCHED)
    say "Action: none for PHP itself. Restart every PHP worker and Apache if you haven't"
    say "since the update: a running worker keeps the old code."
    ;;
  NOT_APPLICABLE)
    say "Action: none. No PHP build between 5.4.0 and the fixed releases was found."
    ;;
  MITIGATED)
    say "Action: update anyway. No unfixed build serves the web right now, but a web"
    say "server pointed at one of them makes this host vulnerable at once."
    ;;
  VULNERABLE)
    say "Action: update PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or the distro build"
    say "listing CVE-2026-109618, then restart every worker. On shared hosting, ask the"
    say "provider and switch the site to the newest branch they offer."
    say "Interim, in php.ini, the FPM pool or the server config (not .user.ini):"
    say "  memory_limit = -1                      (cap memory with cgroups instead)"
    say "  session.upload_progress.enabled = 0"
    say "  fatal_error_backtraces = 0             (8.5 only)"
    say "  pm.max_requests = 1                    (FPM; breaks the same-worker reuse)"
    say "  Optionally block multipart/form-data at the web server or WAF, if the site"
    say "  needs no uploads. None of this makes the host safe; only the update does."
    [ "$EOL_WEB" -eq 1 ] && \
    say "  An end-of-life branch serves the web: it gets no fixed release. Move off it."
    ;;
  UNKNOWN)
    say "Action: check the vendor advisory for the exact package (DSA-6574-1, USN-8948-1,"
    say "  RHSA). Treat as VULNERABLE on anything public-facing until proven otherwise."
    ;;
esac
[ "$IOC_HITS" -gt 0 ] && \
say "IoCs found: preserve logs, look for new files in web roots and cron, rotate secrets."

exit "$exit_code"

} # end main()

main "$@"
