#!/usr/bin/env bash
# Integration tests for php2shell-audit.sh.
# Each case runs the script as a child process against mocked binaries and a
# per-case fixture tree with fake PHP builds, so nothing on the real system
# is read, executed or touched.
set -u
set -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/php2shell-audit.sh"
MOCK_BIN="$ROOT/tests/mock_bin"
FIXTURES="$ROOT/tests/fixtures"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "${EUID:-0}" -eq 0 ]; then
  echo "run the tests as a normal user: the script ignores its test hooks for root" >&2
  exit 1
fi

chmod -R +x "$MOCK_BIN"

# Write one fake PHP binary. -v prints the version line, -r (CLI) and -q
# (CGI, script on stdin) print the ini probe answer from TEST_INI_*.
fake_php() {
  local file="$1" ver="$2" sapi="$3"
  mkdir -p "$(dirname "$file")"
  cat > "$file" <<EOF
#!/bin/sh
case "\$1" in
  -v) echo "PHP ${ver} (${sapi}) (built: ${TEST_PHP_BUILT-Oct 21 2026} 10:00:00) (NTS)"
      echo "Copyright (c) The PHP Group" ;;
  -r|-q) printf 'memory_limit=%s\nsession.upload_progress.enabled=%s\nfatal_error_backtraces=%s\npost_max_size=8M\nfile_uploads=1\nsession_ext=1\nsession.serialize_handler=%s\n' \\
        "\${TEST_INI_ML-128M}" "\${TEST_INI_UP-1}" "\${TEST_INI_FEB-<unset>}" "\${TEST_INI_SH-php}" ;;
esac
EOF
  chmod +x "$file"
}

# Build a fixture root for one case from TEST_* variables:
#   TEST_OS_RELEASE     fixture file for /etc/os-release
#   TEST_PHP            "path|version|sapi ..." fake PHP builds
#   TEST_LINKS          "link=target ..." symlinks inside the root
#   TEST_DPKG_OWNER     "path=package=version ..." (read by the dpkg mocks)
#   TEST_DEB_CHANGELOG  changelog.Debian.gz content for every owner package
#   TEST_DEB_DOC_DIR    write that changelog to this doc dir instead
#   TEST_APACHE_LOAD    content of /etc/apache2/mods-enabled/php.load
#   TEST_FPM_POOL       content of /etc/php/8.4/fpm/pool.d/www.conf
#   TEST_WEB_FILES      "relpath ..." files under /var/www/html; content from
#                       TEST_WEB_CONTENT (default: a harmless echo)
build_root() {
  local r="$1" spec p v s name
  mkdir -p "$r/etc"
  cp "${TEST_OS_RELEASE:-$FIXTURES/os-release-ubuntu2404}" "$r/etc/os-release"
  for spec in ${TEST_PHP:-}; do
    IFS='|' read -r p v s <<< "$spec"
    fake_php "$r$p" "$v" "$s"
  done
  for spec in ${TEST_LINKS:-}; do
    mkdir -p "$(dirname "$r${spec%%=*}")"
    ln -s "$r${spec#*=}" "$r${spec%%=*}"
  done
  if [ -n "${TEST_DEB_CHANGELOG:-}" ]; then
    for spec in ${TEST_DPKG_OWNER:-}; do
      IFS='=' read -r _ name _ <<< "$spec"
      name="${TEST_DEB_DOC_DIR:-$name}"
      mkdir -p "$r/usr/share/doc/$name"
      printf '%b\n' "$TEST_DEB_CHANGELOG" | gzip -c > "$r/usr/share/doc/$name/changelog.Debian.gz"
    done
  fi
  if [ -n "${TEST_APACHE_LOAD:-}" ]; then
    mkdir -p "$r/etc/apache2/mods-enabled"
    printf '%b\n' "$TEST_APACHE_LOAD" > "$r/etc/apache2/mods-enabled/php.load"
  fi
  if [ -n "${TEST_FPM_POOL:-}" ]; then
    mkdir -p "$r/etc/php/8.4/fpm/pool.d"
    printf '%b\n' "$TEST_FPM_POOL" > "$r/etc/php/8.4/fpm/pool.d/www.conf"
  fi
  for p in ${TEST_WEB_FILES:-}; do
    mkdir -p "$(dirname "$r/var/www/html/$p")"
    printf '%b\n' "${TEST_WEB_CONTENT:-<?php echo 1;}" > "$r/var/www/html/$p"
  done
  return 0
}

# run_case NAME [VAR=value ...] -- [key:expected ...]
# A "rc:N" expectation checks the exit code instead of a JSON key.
run_case() {
  local name="$1"; shift
  local extra_env=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do extra_env+=("$1"); shift; done
  shift || true
  local expected=("$@")

  local output rc
  output=$(
    export TEST_ARGS="--no-hunt --json"
    local e
    for e in "${extra_env[@]}"; do export "${e%%=*}=${e#*=}"; done
    r=$(mktemp -d "$TMP/root.XXXXXX")
    build_root "$r"
    export PHP2SHELL_TEST_ROOT="$r"
    export PHP2SHELL_TEST_PATH="$MOCK_BIN"
    # TEST_ARGS may name paths inside the fixture root as @ROOT@.
    # shellcheck disable=SC2086
    "$SCRIPT" ${TEST_ARGS//@ROOT@/$r} 2>/dev/null
  )
  rc=$?

  local fail=0 cond k v got
  # Guard against the pinned PATH silently bypassing the mocks: the report
  # must describe the mocked host, not the machine running the tests.
  case " ${extra_env[*]} " in
    *" TEST_ARGS="*) ;;   # non-JSON runs are checked by rc only
    *) expected=("hostname:testhost" "${expected[@]}") ;;
  esac

  for cond in "${expected[@]}"; do
    k="${cond%%:*}"; v="${cond#*:}"
    if [ "$k" = "rc" ]; then
      got="$rc"
    else
      got=$(printf '%s' "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$k','__MISSING__'))" 2>/dev/null || echo "__BADJSON__")
    fi
    if [ "$got" != "$v" ]; then
      printf 'FAIL: %s  %s expected "%s", got "%s" (rc=%d)\n' "$name" "$k" "$v" "$got" "$rc"
      fail=1
    fi
  done

  if [ $fail -eq 0 ]; then
    printf 'PASS: %s (rc=%d)\n' "$name" "$rc"
    pass=$((pass+1))
  else
    printf '      output: %s\n' "$output"
    fail_count=$((fail_count+1))
  fi
}

pass=0
fail_count=0

ARCH="TEST_OS_RELEASE=$FIXTURES/os-release-arch"
CGI84="TEST_PHP=/usr/bin/php-cgi84|8.4.24|cgi-fcgi"

# --- custom builds: upstream thresholds decide ----------------------------------
run_case "custom php-cgi 8.4.24: VULNERABLE" "$ARCH" "$CGI84" \
  -- "verdict:VULNERABLE" "rc:2" "php_builds:1" "php_0_web:1" "php_0_status:VULNERABLE"
run_case "custom php-cgi 8.4.27: PATCHED" "$ARCH" "TEST_PHP=/usr/bin/php-cgi84|8.4.27|cgi-fcgi" \
  -- "verdict:PATCHED" "rc:0"
run_case "FPM 8.5.11: VULNERABLE" "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.5|8.5.11|fpm-fcgi" -- "verdict:VULNERABLE"
run_case "FPM 8.5.12: PATCHED"    "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.5|8.5.12|fpm-fcgi" -- "verdict:PATCHED"
run_case "8.3.35: VULNERABLE"     "$ARCH" "TEST_PHP=/usr/bin/php-cgi83|8.3.35|cgi-fcgi" -- "verdict:VULNERABLE"
run_case "8.3.36: PATCHED"        "$ARCH" "TEST_PHP=/usr/bin/php-cgi83|8.3.36|cgi-fcgi" -- "verdict:PATCHED"
run_case "8.2.34: VULNERABLE"     "$ARCH" "TEST_PHP=/usr/bin/php-cgi82|8.2.34|cgi-fcgi" -- "verdict:VULNERABLE"
run_case "8.2.35: PATCHED"        "$ARCH" "TEST_PHP=/usr/bin/php-cgi82|8.2.35|cgi-fcgi" -- "verdict:PATCHED"
run_case "EOL 8.1.34 serving web: VULNERABLE" "$ARCH" "TEST_PHP=/usr/bin/php-cgi81|8.1.34|cgi-fcgi" \
  -- "verdict:VULNERABLE" "eol_branch_serves_web:1" "risk_score:80"
run_case "5.4.0: VULNERABLE"      "$ARCH" "TEST_PHP=/usr/bin/php-cgi54|5.4.0|cgi-fcgi" -- "verdict:VULNERABLE"
run_case "5.3.29: NOT_APPLICABLE" "$ARCH" "TEST_PHP=/usr/bin/php-cgi53|5.3.29|cgi-fcgi" \
  -- "verdict:NOT_APPLICABLE" "rc:0" "php_0_status:NOT_APPLICABLE"
run_case "no PHP at all: NOT_APPLICABLE" "$ARCH" -- "verdict:NOT_APPLICABLE" "php_builds:0" "rc:0"
run_case "unknown future branch 8.6: UNKNOWN" "$ARCH" "TEST_PHP=/usr/bin/php|8.6.0|cli" -- "verdict:UNKNOWN" "rc:3"

# --- what serves the web --------------------------------------------------------
run_case "unfixed CLI only: MITIGATED" "$ARCH" "TEST_PHP=/usr/bin/php|8.4.24|cli" \
  -- "verdict:MITIGATED" "rc:1" "php_0_web:0" "risk_score:50"
run_case "unfixed CLI + fixed FPM: MITIGATED" "$ARCH" \
  "TEST_PHP=/usr/bin/php8.1|8.1.34|cli /usr/sbin/php-fpm8.4|8.4.27|fpm-fcgi" \
  -- "verdict:MITIGATED" "php_builds:2" "php_builds_vulnerable_web:0"
run_case "shared-hosting zoo: VULNERABLE" "$ARCH" \
  "TEST_PHP=/usr/bin/php|8.4.24|cli /usr/bin/php-cgi53|5.3.29|cgi-fcgi /usr/bin/php-cgi74|7.4.33|cgi-fcgi /usr/bin/php-cgi85|8.5.9|cgi-fcgi /usr/bin/php.bin56|5.6.40|cli" \
  -- "verdict:VULNERABLE" "php_builds:5" "php_builds_vulnerable:4" "php_builds_vulnerable_web:2" "eol_branch_serves_web:1"
run_case "symlinked php counted once" "$ARCH" "TEST_PHP=/usr/bin/php8.4|8.4.24|cli" "TEST_LINKS=/usr/bin/php=/usr/bin/php8.4" \
  -- "php_builds:1"
run_case "php-config and phpize are not builds" "$ARCH" "TEST_PHP=/usr/local/bin/php-config84|8.4.24|cli /usr/local/bin/phpize84|8.4.24|cli /usr/local/bin/php-cgi.so|8.4.24|cli /usr/local/bin/php84-config|8.4.24|cli" \
  -- "php_builds:0"
run_case "--php adds a build" "$ARCH" "TEST_PHP=/home/u/bin/php|8.4.24|cgi-fcgi" \
  "TEST_ARGS=--no-hunt --json --php @ROOT@/home/u/bin/php" -- "rc:2"

# --- mod_php --------------------------------------------------------------------
DEB13="TEST_OS_RELEASE=$FIXTURES/os-release-debian13"
run_case "mod_php 8.4 + unfixed 8.4: VULNERABLE" "$ARCH" "TEST_PHP=/usr/bin/php8.4|8.4.24|cli" \
  "TEST_APACHE_LOAD=LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so" \
  -- "verdict:VULNERABLE" "mod_php:1" "mod_php_branches:8.4" "php_0_web:1" "risk_score:85"
run_case "mod_php 8.4 + fixed 8.4: PATCHED" "$ARCH" "TEST_PHP=/usr/bin/php8.4|8.4.27|cli" \
  "TEST_APACHE_LOAD=LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so" -- "verdict:PATCHED"
run_case "mod_php branch unknown: every CLI counts" "$ARCH" "TEST_PHP=/usr/bin/php|8.3.30|cli" \
  "TEST_APACHE_LOAD=LoadModule php_module modules/libphp.so" -- "verdict:VULNERABLE" "php_0_web:1"
run_case "mod_php for another branch: MITIGATED" "$ARCH" "TEST_PHP=/usr/bin/php8.1|8.1.34|cli" \
  "TEST_APACHE_LOAD=LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so" -- "verdict:MITIGATED"
run_case "commented-out LoadModule is ignored" "$ARCH" "TEST_PHP=/usr/bin/php8.4|8.4.24|cli" \
  "TEST_APACHE_LOAD=# LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so" -- "verdict:MITIGATED" "mod_php:0"

# --- distro packages: changelog, then matrix ------------------------------------
run_case "Debian 13 8.4.16-1~deb13u1: VULNERABLE (matrix)" "$DEB13" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.16|fpm-fcgi" "TEST_DPKG_OWNER=/usr/sbin/php-fpm8.4=php8.4-fpm=8.4.16-1~deb13u1" \
  -- "verdict:VULNERABLE" "php_0_package:php8.4-fpm 8.4.16-1~deb13u1"
run_case "Debian 13 8.4.27-1~deb13u1: PATCHED" "$DEB13" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.27|fpm-fcgi" "TEST_DPKG_OWNER=/usr/sbin/php-fpm8.4=php8.4-fpm=8.4.27-1~deb13u1" \
  -- "verdict:PATCHED"
U2404="TEST_OS_RELEASE=$FIXTURES/os-release-ubuntu2404"
run_case "Ubuntu 24.04 backport .13: PATCHED despite 8.3.6" "$U2404" \
  "TEST_PHP=/usr/sbin/php-fpm8.3|8.3.6|fpm-fcgi" "TEST_DPKG_OWNER=/usr/sbin/php-fpm8.3=php8.3-fpm=8.3.6-0ubuntu0.24.04.13" \
  -- "verdict:PATCHED" "php_0_status:PATCHED"
run_case "Ubuntu 24.04 .12: VULNERABLE" "$U2404" \
  "TEST_PHP=/usr/sbin/php-fpm8.3|8.3.6|fpm-fcgi" "TEST_DPKG_OWNER=/usr/sbin/php-fpm8.3=php8.3-fpm=8.3.6-0ubuntu0.24.04.12" \
  -- "verdict:VULNERABLE"
run_case "changelog lists the CVE: PATCHED (beats matrix)" "$U2404" \
  "TEST_PHP=/usr/sbin/php-fpm8.3|8.3.6|fpm-fcgi" "TEST_DPKG_OWNER=/usr/sbin/php-fpm8.3=php8.3-fpm=8.3.6-0ubuntu0.24.04.12" \
  "TEST_DEB_CHANGELOG=php8.3 (8.3.6-0ubuntu0.24.04.12+esm1)\n  * SECURITY UPDATE: CVE-2026-109618" \
  -- "verdict:PATCHED" "php_0_changelog:fixed"
DEB12="TEST_OS_RELEASE=$FIXTURES/os-release-debian12"
SURY="TEST_DPKG_OWNER=/usr/sbin/php-fpm8.4=php8.4-fpm=8.4.20-1+0~20260801.1+debian12~1.gbp"
run_case "Sury 8.4 on Debian 12, changelog without fix: VULNERABLE" "$DEB12" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.20|fpm-fcgi" "$SURY" "TEST_DEB_CHANGELOG=php8.4 (8.4.20-1)\n  * New upstream" \
  -- "verdict:VULNERABLE" "php_0_changelog:absent"
run_case "Sury 8.4 on Debian 12, no changelog: UNKNOWN" "$DEB12" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.20|fpm-fcgi" "$SURY" -- "verdict:UNKNOWN" "rc:3" "php_0_changelog:unreadable"
run_case "changelog found through php8.4-common" "$DEB12" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.20|fpm-fcgi" "$SURY" "TEST_DEB_DOC_DIR=php8.4-common" \
  "TEST_DEB_CHANGELOG=php8.4 (8.4.20-1+deb12u9)\n  * Fix php2shell (CVE-2026-109619)" -- "verdict:PATCHED"
ROCKY="TEST_OS_RELEASE=$FIXTURES/os-release-rocky9"
RPMOWN="TEST_RPM_OWNER=/usr/sbin/php-fpm=php-fpm=8.3.19-1.el9_7"
run_case "Rocky 9 changelog with fix: PATCHED" "$ROCKY" "TEST_PHP=/usr/sbin/php-fpm|8.3.19|fpm-fcgi" "$RPMOWN" \
  "TEST_RPM_CHANGELOG=* Wed Oct 21 2026 - 8.3.19-2\n- Fix CVE-2026-109618 CVE-2026-109619" -- "verdict:PATCHED"
run_case "Rocky 9 changelog without fix: VULNERABLE" "$ROCKY" "TEST_PHP=/usr/sbin/php-fpm|8.3.19|fpm-fcgi" "$RPMOWN" \
  "TEST_RPM_CHANGELOG=* Mon Aug 10 2026 - 8.3.19-1\n- rebase" -- "verdict:VULNERABLE" "php_0_package:php-fpm 8.3.19-1.el9_7"
run_case "Rocky 9 no changelog: UNKNOWN" "$ROCKY" "TEST_PHP=/usr/sbin/php-fpm|8.3.19|fpm-fcgi" "$RPMOWN" -- "verdict:UNKNOWN"

# --- vendor builds: CloudLinux alt-php, cPanel ea-php ----------------------------
ALT74="TEST_PHP=/opt/alt/php74/usr/bin/lsphp|7.4.33|litespeed"
run_case "alt-php in CageFS, no package data: UNKNOWN" "$ROCKY" "$ALT74" \
  -- "verdict:UNKNOWN" "rc:3" "php_0_status:UNKNOWN" "php_0_web:1"
run_case "alt-php built in September: VULNERABLE" "$ROCKY" "$ALT74" "TEST_PHP_BUILT=Sep  7 2026" \
  -- "verdict:VULNERABLE" "php_0_status:VULNERABLE"
run_case "alt-php built 2026-10-01: still UNKNOWN" "$ROCKY" "$ALT74" "TEST_PHP_BUILT=Oct  1 2026" \
  -- "verdict:UNKNOWN"
run_case "Sury, no changelog, built in August: VULNERABLE" "$DEB12" \
  "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.20|fpm-fcgi" "$SURY" "TEST_PHP_BUILT=Aug 10 2026" -- "verdict:VULNERABLE"
run_case "old build date never fails a fixed version" "$ARCH" "TEST_PHP=/usr/bin/php-cgi84|8.4.27|cgi-fcgi" \
  "TEST_PHP_BUILT=Aug 10 2026" -- "verdict:PATCHED"
run_case "alt-php changelog lists the fix: PATCHED" "$ROCKY" "$ALT74" \
  "TEST_RPM_OWNER=/opt/alt/php74/usr/bin/lsphp=alt-php74-cli=7.4.33-81.el10" \
  "TEST_RPM_CHANGELOG=- Fix CVE-2026-109618, CVE-2026-109619" -- "verdict:PATCHED"
run_case "ea-php84 8.4.26 backport: PATCHED by changelog" "$ROCKY" \
  "TEST_PHP=/opt/cpanel/ea-php84/root/usr/sbin/php-fpm|8.4.26|fpm-fcgi" \
  "TEST_RPM_OWNER=/opt/cpanel/ea-php84/root/usr/sbin/php-fpm=ea-php84-php-fpm=8.4.26-2.cpanel" \
  "TEST_RPM_CHANGELOG=- EA-13371: patch CVE-2026-109618 CVE-2026-109619" -- "verdict:PATCHED"
run_case "alt-php CLI next to patched FPM: UNKNOWN stays non-web" "$ROCKY" \
  "TEST_PHP=/opt/alt/php82/usr/bin/php|8.2.33|cli /usr/sbin/php-fpm|8.3.36|fpm-fcgi" \
  -- "verdict:UNKNOWN" "php_builds_unknown:1" "php_1_status:UNKNOWN" "php_1_web:0"

# --- interim settings (score only, never the verdict) ----------------------------
run_case "no interim settings: 75" "$ARCH" "$CGI84" -- "php_0_interim:none" "risk_score:75"
run_case "full interim on 8.4: still VULNERABLE, 65" "$ARCH" "$CGI84" "TEST_INI_ML=-1" "TEST_INI_UP=0" \
  -- "verdict:VULNERABLE" "php_0_interim:full" "risk_score:65"
run_case "8.5 with backtraces on: partial" "$ARCH" "TEST_PHP=/usr/bin/php-cgi85|8.5.9|cgi-fcgi" \
  "TEST_INI_ML=-1" "TEST_INI_UP=0" "TEST_INI_FEB=1" -- "php_0_interim:partial" "risk_score:75"
run_case "8.5 with backtraces off: full" "$ARCH" "TEST_PHP=/usr/bin/php-cgi85|8.5.9|cgi-fcgi" \
  "TEST_INI_ML=-1" "TEST_INI_UP=0" "TEST_INI_FEB=0" -- "php_0_interim:full"
run_case "upload progress On as word: counted on" "$ARCH" "$CGI84" "TEST_INI_ML=-1" "TEST_INI_UP=On" -- "php_0_interim:partial"
run_case "upload progress Off as word: counted off" "$ARCH" "$CGI84" "TEST_INI_ML=-1" "TEST_INI_UP=Off" -- "php_0_interim:full"
run_case "FPM pool pins interim values: 65" "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.24|fpm-fcgi" \
  "TEST_FPM_POOL=[www]\npm.max_requests = 1\nphp_admin_value[memory_limit] = -1\nphp_admin_flag[session.upload_progress.enabled] = off" \
  -- "verdict:VULNERABLE" "fpm_pools:1" "fpm_pools_memory_limit_off:1" "fpm_pools_upload_progress_off:1" "fpm_pools_max_requests_1:1" "risk_score:65"

# --- web roots and IoC hunt -----------------------------------------------------
# The payload is assembled from pieces so that antivirus scanners (ESET,
# Defender) do not flag or lock this file for a web shell signature.
# shellcheck disable=SC2016  # the PHP payload must stay literal
SHELL_PAYLOAD='<?php ev''al(base''64_dec''ode($_PO''ST["c"]));'
run_case "web shell in uploads" "$ARCH" "$CGI84" "TEST_WEB_FILES=wp-content/uploads/2026/10/x.php" \
  "TEST_WEB_CONTENT=$SHELL_PAYLOAD" \
  -- "webshell_hits:1" "php_in_uploads:1" "ioc_hits:1" "risk_score:85"
run_case "clean recent PHP is not a shell" "$ARCH" "$CGI84" "TEST_WEB_FILES=index.php wp-content/uploads/index.php" \
  -- "webshell_hits:0" "php_in_uploads:0" "php_changed_since:2"
run_case "per-directory .user.ini is reported, not counted" "$ARCH" "$CGI84" "TEST_WEB_FILES=.user.ini" \
  "TEST_WEB_CONTENT=session.upload_progress.enabled = 0\nmemory_limit = -1" \
  -- "perdir_ini_overrides:1" "php_0_interim:none" "verdict:VULNERABLE"
run_case "--no-webroot skips the scan" "$ARCH" "$CGI84" "TEST_WEB_FILES=index.php" \
  "TEST_ARGS=--no-hunt --json --no-webroot" -- "webroots_scanned:0" "php_changed_since:0"
run_case "worker crashes in the journal" "$ARCH" "$CGI84" "TEST_ARGS=--json --no-webroot" \
  "TEST_JOURNAL=php-fpm8.4[123]: segfault at 0 ip 0\nWARNING: [pool www] child 4242 exited on signal 11 (SIGSEGV)\nnoise" \
  -- "crash_hits:2" "ioc_hits:2"
run_case "shell spawned by php-fpm" "$ARCH" "$CGI84" "TEST_ARGS=--json --no-webroot" \
  "TEST_PS=900:1:php-fpm8.4 901:900:php-fpm8.4 902:901:sh 903:902:curl 950:500:bash" \
  -- "spawn_hits:1" "ioc_hits:1"

# --- CVE-2026-115560: session upload progress + runtime serialize handler -------
# Not fixed by the PHP2Shell releases, so it is reported next to the verdict
# and never changes it.
P84OK="TEST_PHP=/usr/bin/php-cgi84|8.4.27|cgi-fcgi"
SH_APP='<?php ini_set("session.serialize_handler", "php"); session_start();'
run_case "115560: patched PHP, php_serialize + ini_set + upload progress on: EXPOSED" "$ARCH" "$P84OK" \
  "TEST_INI_SH=php_serialize" "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" \
  -- "cve_115560:EXPOSED" "cve_115560_code_files:1" "verdict:PATCHED" "rc:0"
run_case "115560: upload progress off: MITIGATED" "$ARCH" "$P84OK" \
  "TEST_INI_SH=php_binary" "TEST_INI_UP=0" "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" \
  -- "cve_115560:MITIGATED"
run_case "115560: configured handler is already php: NOT_EXPOSED" "$ARCH" "$P84OK" \
  "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" -- "cve_115560:NOT_EXPOSED" "cve_115560_code_files:1"
run_case "115560: non-php handler but no ini_set in code: NOT_EXPOSED" "$ARCH" "$P84OK" \
  "TEST_INI_SH=php_serialize" "TEST_WEB_FILES=index.php" -- "cve_115560:NOT_EXPOSED" "cve_115560_code_files:0"
run_case "115560: no web root scanned: CHECK" "$ARCH" "$P84OK" "TEST_INI_SH=php_serialize" \
  "TEST_ARGS=--no-hunt --json --no-webroot" -- "cve_115560:CHECK"
run_case "115560: only CLI builds: NOT_APPLICABLE" "$ARCH" "TEST_PHP=/usr/bin/php|8.4.24|cli" \
  -- "cve_115560:NOT_APPLICABLE"
run_case "115560: FPM pools pin upload progress off: MITIGATED" "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.27|fpm-fcgi" \
  "TEST_FPM_POOL=[www]\nphp_admin_flag[session.upload_progress.enabled] = off" "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" \
  -- "cve_115560:MITIGATED"
run_case "115560: FPM, pool sets php_serialize, state unknown: CHECK" "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.27|fpm-fcgi" \
  "TEST_FPM_POOL=[www]\nphp_admin_value[session.serialize_handler] = php_serialize" "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" \
  -- "cve_115560:CHECK" "fpm_pools_serialize_handler_nonphp:1"
run_case "115560: FPM, handler not visible: CHECK" "$ARCH" "TEST_PHP=/usr/sbin/php-fpm8.4|8.4.27|fpm-fcgi" \
  "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" -- "cve_115560:CHECK"
run_case "115560: .htaccess sets php_binary, app switches it: EXPOSED" "$ARCH" "$P84OK" \
  "TEST_WEB_FILES=.htaccess app.php" "TEST_WEB_CONTENT=php_value session.serialize_handler php_binary\n$SH_APP" \
  -- "cve_115560:EXPOSED" "cve_115560_perdir_nonphp:1"
run_case "115560: leaves an unfixed PHP2Shell verdict alone" "$ARCH" "$CGI84" \
  "TEST_INI_SH=php_serialize" "TEST_WEB_FILES=app.php" "TEST_WEB_CONTENT=$SH_APP" \
  -- "cve_115560:EXPOSED" "verdict:VULNERABLE" "rc:2" "risk_score:75"

quiet_out=$(
  qroot=$(mktemp -d "$TMP/root.XXXXXX")
  export TEST_INI_SH=php_serialize TEST_OS_RELEASE="$FIXTURES/os-release-arch"
  export TEST_PHP="/usr/bin/php-cgi84|8.4.27|cgi-fcgi" TEST_WEB_FILES=app.php TEST_WEB_CONTENT="$SH_APP"
  build_root "$qroot"
  PHP2SHELL_TEST_ROOT="$qroot" PHP2SHELL_TEST_PATH="$MOCK_BIN" "$SCRIPT" --quiet 2>/dev/null
)
if [ "$(printf '%s\n' "$quiet_out" | sed -n 1p | cut -d' ' -f1)" = "PATCHED" ] && \
   printf '%s\n' "$quiet_out" | sed -n 2p | grep -q '^CVE-2026-115560 EXPOSED: '; then
  echo "PASS: 115560 quiet mode keeps the verdict first and adds a second line"; pass=$((pass+1))
else
  printf 'FAIL: 115560 quiet mode output: %s\n' "$quiet_out"; fail_count=$((fail_count+1))
fi

# --- text mode, CLI, hardening --------------------------------------------------
run_case "text report exits like JSON" "$ARCH" "$CGI84" "TEST_ARGS=--no-banner" -- "rc:2"
run_case "banner + full hunt runs clean" "$ARCH" "$CGI84" "TEST_ARGS=--since 2026-10-01 --until 2026-10-22" -- "rc:2"
run_case "quiet mode exits like JSON" "$ARCH" "TEST_PHP=/usr/bin/php|8.4.24|cli" "TEST_ARGS=--quiet" -- "rc:1"
run_case "--version" "TEST_ARGS=--version" -- "rc:0"
run_case "unknown option: ERROR" "TEST_ARGS=--bogus" -- "rc:4"

marker="$TMP/sourced-marker"
# shellcheck disable=SC2016  # the $( ) must reach the file unexpanded
printf 'ID=arch\nPRETTY_NAME="$(touch %s)"\n' "$marker" > "$TMP/os-release-hostile"
run_case "os-release is parsed, not sourced" "TEST_OS_RELEASE=$TMP/os-release-hostile" -- "distro_id:arch"
if [ -e "$marker" ]; then
  echo "FAIL: os-release was executed"; fail_count=$((fail_count+1))
else
  echo "PASS: os-release was not executed"; pass=$((pass+1))
fi

printf '\nTotal: %d passed, %d failed\n' "$pass" "$fail_count"
[ "$fail_count" -eq 0 ]
