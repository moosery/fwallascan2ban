# Changelog

All notable changes to fwallascan2ban are documented here.

---

## [2.0.4] - 2026-05-04

### Changed
- Firewalla MSP API calls now retry on transient failures. On a curl-level network error, HTTP 429 (rate limit), or HTTP 5xx (server error), the request is retried up to 3 times total with delays of 5s and 10s between attempts. Retries are logged to the journal. All API operations (ban, reconciliation, list/rule creation) benefit automatically.
- `banned --sort-date` output now uses consistent 13-char source column width, matching the default `banned` view. `[auto:tomcat  ]` and `[auto:safeline]` now align correctly.

---

## [2.0.3] - 2026-05-04

### Added
- CHANGELOG.md

---

## [2.0.2] - 2026-05-04

### Fixed
- SafeLine failregex pattern now matches Python's `json.dumps` output, which includes spaces after colons (`"src_ip": "1.2.3.4"` rather than `"src_ip":"1.2.3.4"`). The pattern was silently matching nothing, so no SafeLine events were being banned. Updated pattern: `"src_ip":\s*"<HOST>"[^}]*"action":\s*"deny"`
- Updated example log line format in README to reflect actual output

---

## [2.0.1] - 2026-05-03

### Fixed
- Firewalla MSP API POST requests now accept HTTP 201 Created as success (was checking only for 200), fixing silent failures when creating new target lists and block rules
- Overflow target list name matching now correctly identifies numbered suffix lists (e.g. `WebServer-Blocklist-2`); previously the suffix check was too permissive
- Removed duplicate `|| *pos == ' '` in JSON parser character skip logic
- `BannedEntry.source` field widened from 32 to 48 bytes to safely hold longer source tags
- `filter_init` and `logmon_init` now accept `const ConfigLogSource *` directly, removing the awkward Config overlay pattern introduced during v2.0.0 refactor
- `ftell()` return value now checked before assigning to `file_offset` in logmon
- `find_host_group()` in filter.c replaced dead counting loop with correct implementation
- Fixed `append_ignoreregex()` magic number — now uses `sizeof` instead of hardcoded `63`
- Added `#include <ctype.h>` for `isdigit()` in firewalla.c

### Changed
- `BAN_SOURCE_AUTO` macro removed; auto bans always use `"auto:<name>"` form since v2.0.0
- Source column format in `banned` output widened to accommodate longer source tags

---

## [2.0.0] - 2026-05-01

### Changed (Breaking)
- Removed all support for the legacy `[Monitor]` + `[Filters]` failregex configuration format. Configs using `[Monitor]` sections will now produce a fatal error at startup with a message directing users to `[Log:name]` sections. Anyone upgrading from v1.x must migrate their config.
- `failregex` is no longer valid in `[Filters]` — that section now accepts `ignoreregex` only
- `ConfigMonitor` struct removed from `include/config.h`
- `using_legacy_config` flag removed

---

## [1.3.1] - 2026-04-30

### Changed
- `SAFELINE_HOST` no longer has a default value — it must be explicitly set in the environment file. The daemon exits with an error if `SAFELINE_HOST` is unset when the SafeLine poller runs.

---

## [1.3.0] - 2026-04-29

### Added
- **Multi-log source support**: A single daemon instance can now monitor up to 8 log files simultaneously using named `[Log:name]` config sections. Each source has its own `log_pattern`, `maxretry`, `log_scan_interval`, and `failregex` patterns.
- **SafeLine WAF integration**: New `safeline-poll` Python script polls the SafeLine open platform API for denied-IP events every 60 seconds (systemd timer). Events are written as JSON lines to `/var/log/safeline-waf/attacks.log` and picked up by a `[Log:safeline]` source. Works on the SafeLine free plan.
- `make install-safeline` / `make uninstall-safeline` targets for the SafeLine poller components
- Ban source tags are now source-qualified: `auto:tomcat`, `auto:safeline`, etc.
- **Database versioning**: `banned.db` now includes a `# db_version: 2` header. On first startup after upgrading from any pre-v1.3.0 install, the old database is automatically backed up to `banned.db.v1.bak` before continuing.
- `rescan` and `rescan-all` commands now apply to all configured log sources

---

## [1.2.3] - 2026-04-20

### Changed
- `banned` (default view, without `--sort-date`) now includes the target list name column, consistent with the `--sort-date` view

---

## [1.2.2] - 2026-04-19

### Changed
- `banned --sort-date` output now includes the target list name for each entry

---

## [1.2.1] - 2026-04-18

### Changed
- `--fw-rules` flag documented in README client commands table

### Fixed
- `fw-rule` IPs are shown in a separate section in `banned --sort-date` output, consistent with the default `banned` view

---

## [1.2.0] - 2026-04-17

### Added
- **Firewalla individual rule coexistence**: During reconciliation, fwallascan2ban now detects IPs that Firewalla has independently blocked via individual IP rules. Those IPs are removed from the managed target list (freeing capacity) and recorded in the local db with a `fw-rule` source tag. The filter engine treats them as already-banned so they are not re-processed.
- `banned --fw-rules` flag to include `fw-rule` IPs as a separate section in the banned list output

---

## [1.1.0] - 2026-04-10

### Added
- `rules` client command — shows active failregex patterns and maxretry threshold for the running daemon
- `banned --sort-date` option — lists all banned IPs sorted by ban date, oldest first (newest at bottom)
- Banned IP timestamps now displayed in local time with UTC offset in parentheses

### Fixed
- Segfault and ban-loop on IPs that were already banned during `rescan-all`
- `reload` command now correctly re-reads the config file and recompiles failregex patterns (previously only triggered reconciliation)
- Wakeup on inotify file change events was not firing reliably

### Changed
- Target list IPs are sorted on every PATCH to Firewalla, not only during reconciliation
- Suppressed noisy log output when a rescan finds the same file with no new content

---

## [1.0.0] - Initial release

### Features
- Monitors a web server access log in real time using Linux inotify
- Matches log lines against configurable PCRE2 `failregex` patterns (fail2ban-compatible syntax)
- Bans IPs at the network edge by adding them to a Firewalla MSP target list via the REST API
- Associated block rule enforces the ban at the Firewalla perimeter
- Periodic reconciliation keeps local state in sync with Firewalla
- Banned IPs persisted to `banned.db` — survive daemon restarts
- Log rotation handled automatically via strftime patterns + directory scanning
- Overflow target lists created automatically when `max_targets` is reached
- `fwallascan2ban-client` CLI for status, ban/unban, pending IPs, reload, rescan
- Systemd service unit included
- `ignoreregex` global ignore list (IPs/CIDR ranges)
- Manual ban/unban via client
- `-r` flag for full log rescan on startup
