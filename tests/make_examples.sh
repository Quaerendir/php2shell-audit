#!/usr/bin/env bash
# Regenerates examples/ from a fixture host: unpatched Debian 13 with mod_php
# 8.4, a distro FPM 8.4 and a leftover CLI 8.1. Run as a normal user.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
r=$(mktemp -d); trap 'rm -rf "$r"' EXIT
mk() {
  mkdir -p "$(dirname "$r$1")"
  # shellcheck disable=SC2016  # $1 belongs to the generated script
  printf '#!/bin/sh\ncase "$1" in -v) echo "PHP %s (%s) (built: Aug 10 2026 11:47:25) (NTS)";; -r|-q) printf "memory_limit=128M\nsession.upload_progress.enabled=1\nfatal_error_backtraces=\nsession_ext=1\n";; esac\n' "$2" "$3" > "$r$1"
  chmod +x "$r$1"
}
cp "$ROOT/tests/fixtures/os-release-debian13" "$r/etc-os-release"; mkdir -p "$r/etc"; mv "$r/etc-os-release" "$r/etc/os-release"
mk /usr/bin/php8.4 8.4.16 cli
mk /usr/bin/php8.1 8.1.34 cli
mk /usr/sbin/php-fpm8.4 8.4.16 fpm-fcgi
mkdir -p "$r/etc/apache2/mods-enabled" "$r/etc/php/8.4/fpm/pool.d" "$r/var/www/html/wp-content/uploads"
echo 'LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so' > "$r/etc/apache2/mods-enabled/php8.4.load"
printf '[www]\npm = dynamic\npm.max_children = 20\n' > "$r/etc/php/8.4/fpm/pool.d/www.conf"
echo '<?php echo 1;' > "$r/var/www/html/index.php"
export PHP2SHELL_TEST_ROOT="$r" PHP2SHELL_TEST_PATH="$ROOT/tests/mock_bin" TEST_UNAME_N=web01
export TEST_DPKG_OWNER="/usr/bin/php8.4=php8.4-cli=8.4.16-1~deb13u1 /usr/sbin/php-fpm8.4=php8.4-fpm=8.4.16-1~deb13u1"
export TEST_JOURNAL='Oct 21 09:12:44 web01 kernel: php-fpm8.4[31337]: segfault at 7f00 ip 55d0 sp 7ffc error 4'
"$ROOT/php2shell-audit.sh" --no-banner | sed "s#$r##g" > "$ROOT/examples/sample-output.txt" || true
"$ROOT/php2shell-audit.sh" --json | sed "s#$r##g" > "$ROOT/examples/sample-output.json" || true
