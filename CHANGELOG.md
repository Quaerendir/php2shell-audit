# Changelog

All notable changes to `php2shell-audit` are documented here.

## [1.1.0] — 2026-10-24

### Added
- CVE-2026-115560 check, reported separately as `cve_115560` (`EXPOSED` / `CHECK` / `NOT_EXPOSED` / `MITIGATED` / `NOT_APPLICABLE`). PHP announced it on 2026-10-23 as a session upload progress flaw that the 2026-10-21 releases do not fix. Exposed when upload progress is on, the config sets `session.serialize_handler` to `php_binary`/`php_serialize` (global ini, FPM pool, `.htaccess`/`.user.ini`) and PHP files in the web roots `ini_set()` it before `session_start()`.
- JSON keys `cve_115560`, `cve_115560_reason`, `cve_115560_code_files`, `cve_115560_perdir_nonphp`, `cve_115560_upload_progress_on`, `cve_115560_upload_progress_unknown`, `fpm_pools_serialize_handler_nonphp`.
- `--quiet` prints a second line `CVE-2026-115560 <status>: <reason>`; the first line is unchanged.

### Notes
- The new check never changes the verdict, the exit code or the risk score: no build can be patched for it yet.

## [1.0.1] — 2026-10-22

### Fixed
- Vendor builds under `/opt/alt` (CloudLinux alt-php), `/opt/cpanel` (ea-php), `/opt/remi` and `/opt/plesk` with no visible package data are now UNKNOWN, not VULNERABLE. Vendors backport without reaching the upstream version (ea-php84 is fixed at 8.4.26), and inside CageFS `rpm` cannot see these packages. Found on a CloudLinux/LiteSpeed shared host.

### Added
- Build-date rule: a build that would otherwise be UNKNOWN is VULNERABLE when `php -v` says it was built before 2026-10-01. Such a build cannot carry a backport; the cutoff leaves room for embargoed early fixes.

## [1.0.0] — 2026-10-22

### Added
- First release. Read-only audit for PHP2Shell (CVE-2026-109618, CVE-2026-109619): PHP engine use-after-free across requests, unauthenticated RCE.
- Discovery of every PHP build in the usual prefixes: distro, Sury, Remi, cPanel EA, CloudLinux alt-php, Plesk, LiteSpeed, FrankenPHP and shared-hosting `php-cgiNN`/`php.binNN`; `--php` for others.
- Per-build fix detection: package changelog (CVE IDs or "php2shell") first, then the distro matrix as of 2026-10-21 (Debian 13/12, Ubuntu 22.04/24.04/26.04), then upstream thresholds 8.5.12, 8.4.27, 8.3.36, 8.2.35. Distro builds without a readable changelog stay UNKNOWN.
- Web exposure from the SAPI and Apache `LoadModule` lines; unfixed CLI-only builds give MITIGATED.
- Interim settings per build and per FPM pool, web root scan (per-dir overrides, PHP in uploads, web-shell patterns), log and process IoC hunt. Interim settings never change the verdict.
- Works without root (shared hosting); avoids process substitution, which such hosts often deny.
- Same hardening as the sibling audits: pinned `PATH`, `#!/bin/bash`, os-release parsed as text, test hooks ignored for root; as root it refuses to run non-root-owned or writable PHP binaries.
- 55 regression tests and ShellCheck in CI; every verdict-relevant branch is mutation-tested.
