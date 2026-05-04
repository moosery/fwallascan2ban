# fwallascan2ban

A fail2ban-style daemon for Linux that monitors web server access logs, detects malicious requests using PCRE2 regex patterns, and automatically bans offending IP addresses via the [Firewalla MSP API](https://docs.firewalla.net) by adding them to a managed target list backed by a firewall block rule.

## How It Works

1. Monitors a web server log file in real time using Linux inotify
2. Matches each new log line against configurable `failregex` patterns (fail2ban-compatible PCRE2 syntax)
3. When an IP's hit count reaches `maxretry`, it is added to a Firewalla MSP target list via the REST API
4. The associated block rule on the Firewalla enforces the ban at the network perimeter — traffic from the banned IP is dropped before it reaches your server
5. Runs periodic reconciliation to keep local state in sync with Firewalla

Banned IPs are persisted to a local `banned.db` file and survive daemon restarts. Log rotation is handled automatically.

## Requirements

- Linux (inotify required)
- Firewalla with MSP (Managed Security Portal) access
- MSP API version 2.10.0 or later (rule creation API)
- libcurl (for HTTPS API calls)
- libpcre2-8 (for PCRE2 regex matching)

```
apt install libcurl4-openssl-dev libpcre2-dev
```

## Building

```
make
```

Produces two binaries:
- `fwallascan2ban` — the daemon
- `fwallascan2ban-client` — the CLI client

## Installation

```
sudo make install
```

This installs:
- `/usr/local/sbin/fwallascan2ban`
- `/usr/local/bin/fwallascan2ban-client`
- `/etc/fwallascan2ban/fwallascan2ban.conf` (from example, if not already present)
- `/etc/fwallascan2ban/fwallascan2ban.env` (from example, if not already present)
- `/etc/systemd/system/fwallascan2ban.service`

## Multiple Log Sources

A single daemon instance can monitor up to 8 log files simultaneously using named `[Log:name]` sections in the config. Each source has its own file path, `maxretry`, and `failregex` patterns.

```ini
[Log:tomcat]
log_pattern  = /var/log/tomcat10/access_log.%Y-%m-%d.log
maxretry     = 3
failregex    = ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*\.(php|env|git).*"
               ^<HOST> - - \[.*\] "CONNECT .*"

[Log:safeline]
log_pattern  = /var/log/safeline-waf/attacks.log
maxretry     = 1
failregex    = "src_ip":"<HOST>"[^}]*"action":"deny"
```

When multiple sources are configured, bans carry a source-qualified tag: `auto:tomcat`, `auto:safeline`, etc. Single-source configs (and legacy configs) continue to use the plain `auto` tag.

### Backward Compatibility

Existing configs using the `[Monitor]` and `[Filters]` sections continue to work without any changes. The daemon synthesizes a `default` log source from those sections automatically and bans are still tagged `auto`.

### SafeLine WAF Integration

SafeLine WAF (running on a separate VM) can forward attack events as syslog to rsyslog on the webserver, which writes the raw JSON to a local file. See `rsyslog-safeline.conf.example` for the rsyslog configuration. SafeLine log lines look like:

```
{"time":1714900000,"src_ip":"1.2.3.4","src_port":54321,...,"action":"deny"}
```

With `maxretry = 1`, every SafeLine block event results in an immediate ban at the Firewalla.

> **Note:** The current log scanner processes single-line records only. Both Tomcat access logs and SafeLine JSON events are single-line, so both work correctly with the current implementation.

## Configuration

### Credentials

Edit `/etc/fwallascan2ban/fwallascan2ban.env` (chmod 600):

```
FW_MSP_DOMAIN=yourname.firewalla.net
FW_MSP_TOKEN=your_personal_access_token
```

Your MSP domain is the hostname you see in the browser when logged into the MSP portal. Your personal access token is generated under Account Settings in the portal.

### Config File

Edit `/etc/fwallascan2ban/fwallascan2ban.conf`. The file is heavily commented — see `fwallascan2ban.conf.example` for full documentation of every option.

Key settings:

| Setting | Description | Default |
|---|---|---|
| `box_name` | Friendly name of your Firewalla box as shown in MSP | required |
| `target_list_name` | Name of the MSP target list to add banned IPs to | required |
| `max_targets` | Max IPs per target list before overflow list is created | 1000 |
| `reconcile_interval` | Seconds between periodic reconciliation passes | 3600 |

Per log-source settings (in each `[Log:name]` section):

| Setting | Description | Default |
|---|---|---|
| `log_pattern` | Path to the log file, with strftime codes for rotation | required |
| `maxretry` | Number of pattern matches before an IP is banned | 3 |
| `log_scan_interval` | Seconds between directory scans for log rotation | 60 |
| `failregex` | One or more patterns to match; each must contain `<HOST>` | required |

### Failregex Patterns

Patterns use standard PCRE2 syntax. The special token `<HOST>` is replaced at startup with a capture group matching IPv4 and IPv6 addresses. Syntax is compatible with fail2ban filter files.

Example patterns for Tomcat/web servers (place in `[Log:tomcat]`):

```ini
failregex = ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*\.(php|env|git|cgi|sh|sql).*"
            ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*/(wp-admin|wp-content|config|backup).*"
            ^<HOST> - - \[.*\] "CONNECT .*"
            ^<HOST> - - \[.*\] "-" 400 (?:-|\d+)
            ^<HOST> - - \[.*\] "GET .*/manager/html.*" 401 \d+
```

Example pattern for SafeLine WAF (place in `[Log:safeline]`):

```ini
failregex = "src_ip":"<HOST>"[^}]*"action":"deny"
```

### Ignore List

Add your own IP, internal networks, and trusted addresses to `ignoreregex` in the `[Filters]` section to prevent accidental banning. The ignore list applies globally to all log sources. Supports single IPs and CIDR ranges. The placeholder IP and loopback addresses are always ignored automatically.

```ini
[Filters]
ignoreregex = 192.168.1.0/24
              203.0.113.10
```

## Running

```
systemctl enable --now fwallascan2ban
```

To rescan the current log from the beginning on startup (catches attacks that occurred before the daemon was running), add `-r` to `ExecStart` in the service file:

```ini
ExecStart=/usr/local/sbin/fwallascan2ban -c /etc/fwallascan2ban/fwallascan2ban.conf -r
```

View logs:

```
journalctl -u fwallascan2ban -f
```

## Client Commands

The `fwallascan2ban-client` tool communicates with the running daemon over a Unix socket.

| Command | Description |
|---|---|
| `fwallascan2ban-client status` | Daemon status, uptime, target list inventory, pending IPs |
| `fwallascan2ban-client banned` | All banned IPs with source tag and timestamp, grouped by list |
| `fwallascan2ban-client banned --fw-rules` | Same, plus a separate section for IPs blocked by Firewalla individual rules |
| `fwallascan2ban-client banned --sort-date` | All banned IPs sorted by date, oldest first (newest at bottom) |
| `fwallascan2ban-client banned --sort-date --fw-rules` | Sorted banned IPs, then a separate sorted section for Firewalla individual rule IPs |
| `fwallascan2ban-client pending` | IPs that have matched patterns but not yet reached maxretry |
| `fwallascan2ban-client rules` | Show active failregex scan patterns and maxretry threshold |
| `fwallascan2ban-client ban <ip>` | Manually ban an IP immediately |
| `fwallascan2ban-client unban <ip>` | Remove a banned IP from Firewalla and local db |
| `fwallascan2ban-client reload` | Reload config and trigger reconciliation (same as SIGHUP) |
| `fwallascan2ban-client rescan` | Switch to the newest log file |
| `fwallascan2ban-client rescan-all` | Reprocess the current log file from the beginning |

## Target List Overflow

When a target list reaches `max_targets`, the daemon automatically creates a numbered overflow list (`WebServer-Blocklist-2`, `-3`, etc.) and a corresponding block rule for each. Reconciliation can consolidate lists when space becomes available.

## Ban Sources

Each entry in the banned list carries a source tag:

| Tag | Meaning |
|---|---|
| `auto` | Banned automatically by log pattern matching |
| `manual` | Banned manually via `fwallascan2ban-client ban` |
| `firewalla` | Found in Firewalla target list but not in local db (added externally via MSP portal or mobile app) |
| `fw-rule` | Blocked by a Firewalla individual IP block rule; removed from our target list to free capacity |
| `placeholder` | Placeholder IP keeping an otherwise empty list alive (never a real ban) |

## Coexistence with Firewalla's Own Block Rules

Firewalla's threat intelligence may independently create individual IP block rules for the same addresses that fwallascan2ban manages via its target list. During each reconciliation pass, fwallascan2ban detects these individual rules and automatically removes the corresponding IPs from its managed target lists, freeing capacity for new bans. The affected IPs are recorded in the local database with the `fw-rule` source tag.

This means:

- **Reconciliation actively deduplicates** — if Firewalla adds an individual block rule for an IP that is in our target list, the next reconciliation removes it from the list. The IP remains blocked at the Firewalla level. No action is needed.
- **Filter engine is seeded** — after reconciliation, the log scanner marks all `fw-rule` IPs as already-banned so they are not re-processed. If the same IP appears in the log again, it is silently ignored.
- **Future reconciliations skip `fw-rule` IPs** — they are not presented to the reconciliation logic as "expected in target list", so there is no re-add loop.
- **Unbanning** — `fwallascan2ban-client unban <ip>` removes the IP from the target list and local db, but any individual Firewalla block rule is not touched. The IP remains blocked at the Firewalla level until that rule is removed manually via the MSP portal.
- **If Firewalla removes the individual rule** — the `fw-rule` tag persists in the local db until the next log match or manual `ban` command re-adds the IP through the normal path.

## Database Versioning

The local `banned.db` file includes a `# db_version: 2` header as of v1.3.0. On the first startup after upgrading from v1.2.x, the daemon automatically detects the old format and copies the existing database to `banned.db.v1.bak` before continuing. The original data is preserved and the database is upgraded transparently.

## Files

| Path | Description |
|---|---|
| `/etc/fwallascan2ban/fwallascan2ban.conf` | Main configuration file |
| `/etc/fwallascan2ban/fwallascan2ban.env` | Credentials (MSP domain and token) |
| `/etc/fwallascan2ban/rsyslog-safeline.conf.example` | rsyslog config for SafeLine WAF syslog |
| `/var/lib/fwallascan2ban/banned.db` | Local persistent state of all banned IPs |
| `/var/lib/fwallascan2ban/banned.db.v1.bak` | Backup of pre-v1.3.0 database (created once on upgrade) |
| `/run/fwallascan2ban/fwallascan2ban.sock` | Unix socket for client communication |
