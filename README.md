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
| `maxretry` | Number of pattern matches before an IP is banned | 3 |
| `log_pattern` | Path to the log file, with strftime codes for rotation | required |
| `reconcile_interval` | Seconds between periodic reconciliation passes | 3600 |

### Failregex Patterns

Patterns use standard PCRE2 syntax. The special token `<HOST>` is replaced at startup with a capture group matching IPv4 and IPv6 addresses. Syntax is compatible with fail2ban filter files.

Example patterns for Tomcat/web servers are included in the example config:

```ini
failregex = ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*\.(php|env|git|cgi|sh|sql).*"
            ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*/(wp-admin|wp-content|config|backup).*"
            ^<HOST> - - \[.*\] "CONNECT .*"
            ^<HOST> - - \[.*\] "-" 400 (?:-|\d+)
            ^<HOST> - - \[.*\] "GET .*/manager/html.*" 401 \d+
```

### Ignore List

Add your own IP, internal networks, and trusted addresses to `ignoreregex` to prevent accidental banning. Supports single IPs and CIDR ranges. The placeholder IP and loopback addresses are always ignored automatically.

```ini
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
| `fwallascan2ban-client banned` | All banned IPs with source tag and timestamp |
| `fwallascan2ban-client pending` | IPs that have matched patterns but not yet reached maxretry |
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
| `placeholder` | Placeholder IP keeping an otherwise empty list alive (never a real ban) |

## Coexistence with Firewalla's Own Block Rules

Firewalla's threat intelligence may independently create individual IP block rules (type `ip`) for the same addresses that fwallascan2ban manages via its target list. These are separate mechanisms and coexist without conflict — an IP blocked by both is simply double-blocked, which is harmless.

Two things to be aware of:

- **Reconciliation** — `fw_ip_is_banned()` checks only the managed target lists, not individual Firewalla rules. If an IP has a Firewalla-added individual rule but is not in the target list, reconciliation may re-add it to the target list. This is redundant but harmless.
- **Unbanning** — `fwallascan2ban-client unban <ip>` removes the IP from the target list and local db, but any individual Firewalla block rule for the same IP is not touched. The IP will remain blocked at the Firewalla level until that rule is removed manually via the MSP portal.

## Files

| Path | Description |
|---|---|
| `/etc/fwallascan2ban/fwallascan2ban.conf` | Main configuration file |
| `/etc/fwallascan2ban/fwallascan2ban.env` | Credentials (MSP domain and token) |
| `/var/lib/fwallascan2ban/banned.db` | Local persistent state of all banned IPs |
| `/run/fwallascan2ban/fwallascan2ban.sock` | Unix socket for client communication |
