# php2shell-audit

![CVE](https://img.shields.io/badge/CVE-2026--109618-red?style=flat-square)
![CVE](https://img.shields.io/badge/CVE-2026--109619-red?style=flat-square)
![Name](https://img.shields.io/badge/PHP2Shell-PHP%20core%20UAF-red?style=flat-square)
![CVSS](https://img.shields.io/badge/CVSS%20v4-9.2%20CRITICAL-critical?style=flat-square)
![Disclosed](https://img.shields.io/badge/fixed-2026--10--21-yellow?style=flat-square)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25?style=flat-square&logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0.1-informational?style=flat-square)
[![CI](https://github.com/Quaerendir/php2shell-audit/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/Quaerendir/php2shell-audit/actions/workflows/shellcheck.yml)

Read-only audit script for **PHP2Shell**: **CVE-2026-109618** and **CVE-2026-109619**. Both are use-after-free bugs in the PHP engine itself. An unauthenticated attacker can get remote code execution as the web worker user, or read leftover worker memory, before any application code runs.

```
   ___ _  _ ___ ___ ___ _        _ _
  | _ \ || | _ \_  ) __| |_  ___| | |
  |  _/ __ |  _// /\__ \ ' \/ -_) | |
  |_| |_||_|_| /___|___/_||_\___|_|_|
     CVE-2026-109618 + CVE-2026-109619  PHP cross-request use-after-free
```

## TL;DR

A PHP worker serves many requests in a row. Both bugs leave the worker holding pointers into memory that belonged to an earlier request:

| CVE | Producer | Consumer |
|---|---|---|
| CVE-2026-109618 | Memory exhaustion: PHP `longjmp()`s out while request memory is half initialised | Request shutdown, and the session upload-progress unserializer during multipart parsing |
| CVE-2026-109619 | Fatal errors, uncaught errors, failed `require`, timeouts; saved fatal-error backtraces on 8.5; OPcache state | INI diagnostics before request start, session upload progress |

The known trigger is a `multipart/form-data` POST, which PHP parses before the script starts. No login, no form and no vulnerable application code are needed. Clean WordPress, Drupal, Magento and the rest are all exposed, because the bug is in PHP.

| | |
|---|---|
| Affected | PHP 5.4.0 through 8.5.11, every web SAPI: mod_php (highest risk), php-cgi, PHP-FPM, LiteSpeed, FrankenPHP |
| Fixed upstream | **8.5.12, 8.4.27, 8.3.36, 8.2.35** (2026-10-21) |
| End of life | 7.4–8.1: source backports only, no release. 5.4–7.3: no fix |
| Debian | trixie `php8.4 8.4.27-1~deb13u1` (DSA-6574-1), bookworm `php8.2 8.2.35-1~deb12u1` (DLA-4848-1) |
| Ubuntu | USN-8948-1/-2: jammy `php8.1 8.1.2-1ubuntu2.28`, noble `php8.3 8.3.6-0ubuntu0.24.04.13`, resolute `php8.5 8.5.4-0ubuntu1.5` |
| RHEL family | errata per stream; AlmaLinux 8/9/10 shipped on release day |
| Remi | no update on release day |

Distro states are a 2026-10-21 snapshot. Distros backport without bumping the PHP version, so on a distro build **`php -v` proves nothing**: the package changelog decides.

## What this script does

It only triages and changes nothing. It never sends a request, never runs a PoC and never edits `php.ini` or pool configs. It does execute the PHP binaries it finds, with `-v` and a read-only `ini_get()` snippet.

- **Finds every PHP build** in the usual system prefixes: distro and Sury (`/usr/bin/php*`, `/usr/sbin/php-fpm*`), Remi, cPanel EA, CloudLinux alt-php, Plesk, LiteSpeed `lsphp`, FrankenPHP, and the `php-cgiNN` / `php.binNN` zoo of shared hosting. Symlinks are counted once; `php-config`/`phpize` are skipped. `--php PATH` adds more.
- **Decides per build**:
  1. a changelog that names CVE-2026-109618/109619 or php2shell always wins (`changelog.Debian.gz`, also via `php8.x-common`; `rpm -q --changelog`)
  2. otherwise the distro matrix above
  3. otherwise the upstream thresholds; a distro build with no readable changelog stays UNKNOWN, because a backport is possible
  4. vendor builds (`/opt/alt`, `/opt/cpanel`, `/opt/remi`, `/opt/plesk`) whose package data is not visible, as inside CloudLinux CageFS, are UNKNOWN too: vendors backport below the upstream number (cPanel's fixed ea-php84 is 8.4.26)
  5. either kind of UNKNOWN becomes VULNERABLE when `php -v` shows a build date before 2026-10-01: such a build cannot carry a backport
- **Works out what serves the web**: the SAPI (`cgi-fcgi`, `fpm-fcgi`, `litespeed`, `frankenphp`) and Apache `LoadModule php_module` lines. A `libphp8.4.so` ties mod_php to the 8.4 CLI; an unversioned `libphp.so` makes every CLI build count.
- **Reports the interim settings** per build and per FPM pool: `memory_limit=-1`, `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` on 8.5, `pm.max_requests=1`.
- **Scans web roots** (`/var/www`, `/srv/www`, …; without root also `~/public_html`, `~/www`, `~/WWW`, `~/domains`) for per-directory ini overrides, PHP changed since `--since`, PHP in `uploads/`, and web-shell patterns.
- **Hunts** the journal and Apache/FPM/LiteSpeed error logs for worker crashes (`segfault`, `exited on signal 11`, `AH00052`), and the live process table for a shell or downloader whose parent is a PHP worker or Apache.
- Produces a risk score from 0 to 100 and a verdict.

It runs fine **without root**, which is the normal case on shared hosting. It then sees only what that user can read.

### Verdict rules

- **PATCHED**: every affected build carries the fix.
- **VULNERABLE**: at least one unfixed build serves web requests.
- **MITIGATED**: unfixed builds exist, but none of them serves the web (for example a leftover CLI 8.1 next to a patched FPM 8.4). The bug needs a web request, but pointing a server at such a build reopens it at once.
- **UNKNOWN**: a build could not be classified: a distro package below the upstream version with no readable changelog, or a branch not in the table.
- **NOT_APPLICABLE**: no PHP between 5.4.0 and the fixed releases.

The interim settings and per-directory overrides **never change the verdict**. PHP says they reduce exposure but do not make a host safe, and that `.user.ini` and `ini_set()` apply too late. They only lower the score.

## Usage

```bash
./php2shell-audit.sh                          # full text report
./php2shell-audit.sh --json                   # machine-readable JSON, no banner
./php2shell-audit.sh --quiet --no-hunt        # one-line verdict for mass scans
./php2shell-audit.sh --php /opt/custom/bin/php  # audit an extra build (repeatable)
./php2shell-audit.sh --webroot /srv/sites     # scan this web root (repeatable)
./php2shell-audit.sh --no-webroot             # skip the web root scan
./php2shell-audit.sh --since 2026-10-15 --until 2026-10-22  # IoC window
./php2shell-audit.sh --version
```

On a shared host without a copy of the script:

```bash
ssh user@host 'bash -s -- --no-banner' < php2shell-audit.sh
```

As root, the script refuses to execute a PHP binary that is not root-owned or is group/world writable.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | `PATCHED` or `NOT_APPLICABLE` |
| 1 | `MITIGATED` (unfixed builds, none serves the web) |
| 2 | `VULNERABLE` (an unfixed build serves web requests) |
| 3 | `UNKNOWN` (treat as suspect on anything public-facing) |
| 4 | `ERROR` (script could not run; missing tools or bad environment) |

These are the same as in `cve-2026-99999-audit`, `cve-2026-46331-audit` and `linux-pagecache-cve-audit`.

### Sample output

See [`examples/sample-output.txt`](examples/sample-output.txt) for an unpatched Debian 13 host with mod_php 8.4, distro FPM and a leftover CLI 8.1, and [`examples/sample-output.json`](examples/sample-output.json) for the JSON form. Regenerate them with `bash tests/make_examples.sh`.

## Risk scoring model

| Signal | Weight |
|---|---|
| Verdict `VULNERABLE` or `MITIGATED` | +50 |
| Verdict `UNKNOWN` | +30 |
| An unfixed or unknown build serves the web | +15 |
| …through mod_php | +10 |
| …on an end-of-life branch | +5 |
| …and the interim settings are missing (neither global ini nor every FPM pool) | +10 |
| IoCs (worker crashes, spawned shells, web-shell patterns) | +10 |

The score is capped at 100. An unfixed CLI-only host scores 50, an unfixed php-cgi/FPM host 75, unfixed mod_php 85.

## Mass deployment

```bash
ansible -i inventory all -m script -a "php2shell-audit.sh --json --no-hunt" --become | tee /tmp/audit.jsonl
grep -v '^[a-z]' /tmp/audit.jsonl | jq -s 'group_by(.verdict) | map({verdict: .[0].verdict, hosts: length})'
```

```yaml
- name: audit PHP2Shell
  ansible.builtin.script: php2shell-audit.sh --quiet --no-hunt
  register: audit
  failed_when: audit.rc == 2
  changed_when: false
```

## Mitigations (if you need to delay patching)

Update and **restart every worker** (`systemctl restart php8.4-fpm apache2`); a running worker keeps the old code. On shared hosting, ask the provider and move the site to the newest branch they offer.

Until then, in `php.ini`, the FPM pool or the server config (not `.user.ini`):

```ini
memory_limit = -1                   ; counter-intuitive; cap memory with cgroups instead
session.upload_progress.enabled = 0
fatal_error_backtraces = 0          ; PHP 8.5 only
; FPM pool:
php_admin_value[memory_limit] = -1
php_admin_flag[session.upload_progress.enabled] = off
pm.max_requests = 1                 ; breaks the same-worker reuse
```

- Avoid `RLIMIT_AS` / `RLIMIT_DATA`; PHP says they make the attack easier.
- If the site needs no uploads, block `multipart/form-data` at the web server or WAF. That breaks uploads and some checkout forms.
- Hiding errors (`display_errors`, `error_reporting`, `@`) does nothing.
- End-of-life PHP behind a VPN or off the public network.

## Not covered

- The web-SAPI ini is read from the global config that CLI/CGI see. Per-vhost `php_admin_value`, Plesk/cPanel per-domain settings and `PHP_VALUE` passed by a frontend are not visible; FPM binaries get no ini probe (their pools are read instead).
- Log files are grepped whole, not by date; only the journal honours `--since`/`--until`.
- A clean exploit leaves no crash, so zero IoCs proves nothing.
- Custom builds (shared hosting) are judged by version only; a provider could in theory patch without bumping it.

## Tests

```bash
bash tests/run_tests.sh   # 63 cases: fake PHP builds + mocked dpkg/rpm/ps/journalctl; must not run as root
```

The test hooks (`PHP2SHELL_TEST_PATH`, `PHP2SHELL_TEST_ROOT`) are ignored when EUID is 0. Every JSON case also asserts the mocked hostname, which catches mocks silently bypassed by the pinned `PATH`. The web-shell fixture is assembled from pieces so antivirus scanners don't lock the test file.

## References

- PHP: https://www.php.net/archive/2026.php (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
- Blacklens analysis: https://www.blacklens.io/en/insights/php2shell-kritische-rce-lucken-in-php
- Sansec: https://sansec.io/research/php2shell
- JFrog: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Tenable FAQ: https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote
- Ubuntu: https://ubuntu.com/blog/php2shell-vulnerability-fixes-available
- AlmaLinux: https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

For authorised defensive use on systems you own or are explicitly permitted to audit. The script never runs a PoC and never modifies system state. Treat the verdict as triage, not as proof of compromise or proof of safety.
