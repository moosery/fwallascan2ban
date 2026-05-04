/* =============================================================================
 * fwallascan2ban.c
 * Main daemon for fwallascan2ban
 *
 * Startup sequence:
 *   1. Parse command line arguments
 *   2. Load and validate config file
 *   3. Initialize all subsystems
 *   4. Connect to Firewalla MSP API, resolve box GID
 *   5. Load local banned.db state file
 *   6. Run reconciliation
 *   7. Seed filter engine with already-banned IPs
 *   8. Open Unix domain socket for client communication
 *   9. Initialize log monitor
 *  10. Enter main event loop
 *
 * Main loop:
 *   - Poll log file for new lines (inotify, 1 second timeout)
 *   - Process each line through filter engine
 *   - Ban IPs that hit threshold via Firewalla API
 *   - Update local banned.db
 *   - Handle client connections on Unix socket
 *   - Run periodic reconciliation
 *   - Handle signals (SIGTERM, SIGINT, SIGHUP)
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#include "config.h"
#include "ignore.h"
#include "filter.h"
#include "logmon.h"
#include "firewalla.h"

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define DAEMON_VERSION          "2.0.2"
#define DEFAULT_CONFIG_PATH     "/etc/fwallascan2ban/fwallascan2ban.conf"
#define SOCKET_PATH             "/run/fwallascan2ban/fwallascan2ban.sock"
#define DB_PATH                 "/var/lib/fwallascan2ban/banned.db"
#define SOCKET_DIR              "/run/fwallascan2ban"
#define DB_DIR                  "/var/lib/fwallascan2ban"
#define SOCKET_BACKLOG          8
#define MAX_CLIENT_MSG          256
#define MAX_RESPONSE_LEN        65536
#define DB_MAX_IPS              (FW_MAX_TARGET_LISTS * FW_MAX_IPS_PER_LIST)

/* Ban source tags */
#define BAN_SOURCE_MANUAL       "manual"
#define BAN_SOURCE_FIREWALLA    "firewalla"
#define BAN_SOURCE_FW_RULE      "fw-rule"
#define BAN_SOURCE_PLACEHOLDER  "placeholder"
#define BAN_SOURCE_REMOVED      "removed"

/* -----------------------------------------------------------------------------
 * DB entry - one record in the local banned.db
 * ----------------------------------------------------------------------------- */

typedef struct {
    char    ip[FW_MAX_IP_LEN];      /* IP address string                */
    char    source[48];             /* auto[:name], manual, firewalla…  */
    char    timestamp[32];          /* Human-readable timestamp         */
    bool    active;                 /* false if marked [removed]        */
} DbEntry;

/* -----------------------------------------------------------------------------
 * Per-log-source state
 * ----------------------------------------------------------------------------- */

/* Context passed as userdata to each logmon's line callback */
typedef struct {
    void   *state;   /* DaemonState * — void to avoid forward-decl issue */
    int     source_idx;
} LogSourceCtx;

typedef struct {
    LogmonState     logmon;
    FilterEngine    filter;
    char            name[32];   /* matches ConfigLogSource.name */
} LogSource;

/* -----------------------------------------------------------------------------
 * Daemon state - everything in one place
 * ----------------------------------------------------------------------------- */

typedef struct {
    Config          config;
    IgnoreList      ignore;
    LogSource       sources[CONFIG_MAX_LOG_SOURCES];
    int             source_count;
    LogSourceCtx    source_ctxs[CONFIG_MAX_LOG_SOURCES];
    FwClient        firewalla;

    DbEntry         db[DB_MAX_IPS];
    int             db_count;

    int             server_sock;        /* Unix domain socket fd        */
    time_t          started_at;         /* Daemon start time            */
    time_t          last_reconcile;     /* Last reconciliation time     */
    bool            running;            /* Main loop flag               */
    bool            reload_requested;   /* SIGHUP received              */
    unsigned long   lines_processed;    /* Total log lines processed    */
} DaemonState;

/* -----------------------------------------------------------------------------
 * Global state (for signal handlers)
 * ----------------------------------------------------------------------------- */

static volatile sig_atomic_t g_running         = 1;
static volatile sig_atomic_t g_reload_requested = 0;

/* -----------------------------------------------------------------------------
 * Signal handlers
 * ----------------------------------------------------------------------------- */

static void handle_sigterm(int sig)
{
    (void)sig;
    g_running = 0;
}

static void handle_sighup(int sig)
{
    (void)sig;
    g_reload_requested = 1;
}

/* -----------------------------------------------------------------------------
 * Local DB functions
 * ----------------------------------------------------------------------------- */

/*
 * db_migrate_v1 - Detect a v1 (no version header) db and create a backup.
 * Called before db_load so the original file is preserved if migration runs.
 * db_save will write the v2 header on the next save.
 */
static void db_migrate_v1(void)
{
    FILE *fp = fopen(DB_PATH, "r");
    if (fp == NULL)
        return;

    bool has_version = false;
    char line[256];
    for (int i = 0; i < 5 && fgets(line, sizeof(line), fp) != NULL; i++) {
        if (strncmp(line, "# db_version:", 13) == 0) {
            has_version = true;
            break;
        }
    }
    fclose(fp);

    if (has_version)
        return;

    /* v1 detected — copy to .v1.bak and rewrite with v2 header so
     * subsequent startups don't re-run migration. */
    char bak_path[300];
    snprintf(bak_path, sizeof(bak_path), "%s.v1.bak", DB_PATH);

    /* Read all existing lines into memory */
    fp = fopen(DB_PATH, "r");
    if (fp == NULL)
        return;

    /* Buffer for all data lines (non-comment, non-empty) */
    static char data_buf[1 << 20]; /* 1 MB — more than enough */
    size_t data_len = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Preserve non-header comment lines and data lines */
        if (strncmp(line, "# fwallascan2ban", 16) == 0 ||
            strncmp(line, "# format:", 9) == 0 ||
            strncmp(line, "# db_version:", 13) == 0)
            continue; /* skip old header lines — we'll rewrite them */
        size_t llen = strlen(line);
        if (data_len + llen < sizeof(data_buf)) {
            memcpy(data_buf + data_len, line, llen);
            data_len += llen;
        }
    }
    fclose(fp);

    /* Write backup copy (original content) */
    FILE *src = fopen(DB_PATH, "r");
    FILE *dst = fopen(bak_path, "w");
    if (src != NULL && dst != NULL) {
        char buf[8192];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, n, dst);
    }
    if (src) fclose(src);
    if (dst) fclose(dst);

    /* Rewrite db with v2 header so migration doesn't re-run next startup */
    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", DB_PATH);
    FILE *out = fopen(tmp_path, "w");
    if (out != NULL) {
        fprintf(out, "# fwallascan2ban banned.db\n");
        fprintf(out, "# db_version: 2\n");
        fprintf(out, "# format: ip,source,timestamp\n");
        fwrite(data_buf, 1, data_len, out);
        fclose(out);
        rename(tmp_path, DB_PATH);
        printf("db: migrated v1 database to v2 format, backup: %s\n", bak_path);
    }
}

/*
 * db_load - Load banned.db from disk into memory.
 * Format: ip,source,timestamp
 */
static int db_load(DaemonState *state)
{
    FILE *fp = fopen(DB_PATH, "r");
    if (fp == NULL) {
        if (errno == ENOENT) {
            printf("db: no existing banned.db found, starting fresh\n");
            return 0;
        }
        fprintf(stderr, "db: cannot open '%s': %s\n",
                DB_PATH, strerror(errno));
        return -1;
    }

    char line[256];
    state->db_count = 0;

    while (fgets(line, sizeof(line), fp) != NULL &&
           state->db_count < DB_MAX_IPS)
    {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0')
            continue;

        /* Parse: ip,source,timestamp */
        char *ip     = strtok(line, ",");
        char *source = strtok(NULL, ",");
        char *ts     = strtok(NULL, ",");

        if (ip == NULL || source == NULL)
            continue;

        DbEntry *e = &state->db[state->db_count];
        strncpy(e->ip,        ip,     FW_MAX_IP_LEN - 1);
        strncpy(e->source,    source, sizeof(e->source) - 1);
        strncpy(e->timestamp, ts ? ts : "unknown", sizeof(e->timestamp) - 1);
        e->active = (strcmp(source, BAN_SOURCE_REMOVED) != 0);
        state->db_count++;
    }

    fclose(fp);
    printf("db: loaded %d entries from %s\n", state->db_count, DB_PATH);
    return 0;
}

/*
 * db_save - Save the current in-memory db to disk.
 */
static int db_save(DaemonState *state)
{
    /* Write to temp file then rename for atomicity */
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", DB_PATH);

    FILE *fp = fopen(tmp_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "db: cannot write '%s': %s\n",
                tmp_path, strerror(errno));
        return -1;
    }

    fprintf(fp, "# fwallascan2ban banned.db\n");
    fprintf(fp, "# db_version: 2\n");
    fprintf(fp, "# format: ip,source,timestamp\n");

    for (int i = 0; i < state->db_count; i++) {
        DbEntry *e = &state->db[i];
        fprintf(fp, "%s,%s,%s\n", e->ip, e->source, e->timestamp);
    }

    fclose(fp);

    if (rename(tmp_path, DB_PATH) != 0) {
        fprintf(stderr, "db: rename failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * db_find - Find a DbEntry by IP. Returns pointer or NULL if not found.
 */
static DbEntry *db_find(DaemonState *state, const char *ip)
{
    for (int i = 0; i < state->db_count; i++) {
        if (strcmp(state->db[i].ip, ip) == 0)
            return &state->db[i];
    }
    return NULL;
}

/*
 * db_add - Add an entry to the local db.
 */
static int db_add(DaemonState *state, const char *ip,
                  const char *source)
{
    if (state->db_count >= DB_MAX_IPS) {
        fprintf(stderr, "db: database full\n");
        return -1;
    }

    /* Check for existing entry and update it */
    DbEntry *existing = db_find(state, ip);
    if (existing != NULL) {
        strncpy(existing->source, source, sizeof(existing->source) - 1);
        existing->active = true;

        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);
        strftime(existing->timestamp, sizeof(existing->timestamp),
                 "%Y-%m-%d %H:%M:%S", tm);
        return 0;
    }

    DbEntry *e = &state->db[state->db_count];
    memset(e, 0, sizeof(DbEntry));
    strncpy(e->ip,     ip,     FW_MAX_IP_LEN - 1);
    strncpy(e->source, source, sizeof(e->source) - 1);
    e->active = true;

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(e->timestamp, sizeof(e->timestamp),
             "%Y-%m-%d %H:%M:%S", tm_info);

    state->db_count++;
    return 0;
}

/*
 * db_remove - Mark a db entry as removed.
 */
static void db_remove(DaemonState *state, const char *ip)
{
    DbEntry *e = db_find(state, ip);
    if (e != NULL) {
        strncpy(e->source, BAN_SOURCE_REMOVED, sizeof(e->source) - 1);
        e->active = false;
    }
}

/*
 * db_get_active_ips - Get array of active IP strings for reconciliation.
 * Returns count of active IPs.
 */
static int db_get_active_ips(DaemonState *state,
                              const char **ips, int max)
{
    int count = 0;
    for (int i = 0; i < state->db_count && count < max; i++) {
        if (state->db[i].active &&
            strcmp(state->db[i].source, BAN_SOURCE_FW_RULE) != 0)
            ips[count++] = state->db[i].ip;
    }
    return count;
}

/* -----------------------------------------------------------------------------
 * Unix domain socket server
 * ----------------------------------------------------------------------------- */

/*
 * setup_socket - Create and bind the Unix domain socket.
 */
static int setup_socket(void)
{
    /* Create socket directory if needed */
    mkdir(SOCKET_DIR, 0755);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket: create failed: %s\n", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Remove stale socket file */
    unlink(SOCKET_PATH);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "socket: bind failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, SOCKET_BACKLOG) < 0) {
        fprintf(stderr, "socket: listen failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set permissions so non-root can connect */
    chmod(SOCKET_PATH, 0666);

    return fd;
}

/*
 * format_uptime - Format uptime seconds into human-readable string.
 */
static void format_uptime(time_t seconds, char *out, size_t len)
{
    long days    = seconds / 86400;
    long hours   = (seconds % 86400) / 3600;
    long minutes = (seconds % 3600) / 60;
    long secs    = seconds % 60;

    if (days > 0)
        snprintf(out, len, "%ld days, %ld hours, %ld minutes",
                 days, hours, minutes);
    else if (hours > 0)
        snprintf(out, len, "%ld hours, %ld minutes", hours, minutes);
    else if (minutes > 0)
        snprintf(out, len, "%ld minutes, %ld seconds", minutes, secs);
    else
        snprintf(out, len, "%ld seconds", secs);
}

/*
 * handle_client_status - Build status response string.
 */
static void handle_client_status(DaemonState *state,
                                  char *resp, size_t resp_len)
{
    time_t now    = time(NULL);
    time_t uptime = now - state->started_at;
    char   uptime_str[64];
    format_uptime(uptime, uptime_str, sizeof(uptime_str));

    int active_banned = 0;
    for (int i = 0; i < state->db_count; i++) {
        if (state->db[i].active &&
            strcmp(state->db[i].source, BAN_SOURCE_PLACEHOLDER) != 0)
            active_banned++;
    }

    size_t pos = 0;
    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Status:          running\n"
        "Version:         %s\n"
        "PID:             %d\n"
        "Uptime:          %s\n"
        "Lines processed: %lu\n"
        "-------------------------------------------\n"
        "Log sources:     %d\n",
        DAEMON_VERSION,
        getpid(),
        uptime_str,
        state->lines_processed,
        state->source_count);

    for (int si = 0; si < state->source_count && pos < resp_len; si++) {
        LogmonStatus st;
        logmon_get_status(&state->sources[si].logmon, &st);
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "  [%-14s] %s (%lu lines)\n",
            state->sources[si].name,
            st.current_path,
            st.lines_processed);
    }

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "-------------------------------------------\n"
        "Target Lists:    %d\n",
        state->firewalla.list_count);

    for (int i = 0; i < state->firewalla.list_count && pos < resp_len; i++) {
        const FwManagedList *ml = &state->firewalla.lists[i];
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "  %-30s (%d/%d IPs)\n",
            ml->list.name,
            ml->list.ip_count,
            state->config.target_list.max_targets);
    }

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Total banned:    %d\n"
        "-------------------------------------------\n",
        active_banned);

    /* Pending IPs — collect from all filter engines */
    PendingIP pending[256];
    int pending_count = 0;
    for (int si = 0; si < state->source_count; si++) {
        PendingIP src_pending[64];
        int n = filter_get_pending(&state->sources[si].filter, src_pending, 64);
        for (int i = 0; i < n && pending_count < 256; i++)
            pending[pending_count++] = src_pending[i];
    }

    if (pending_count > 0) {
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "Pending IPs (not yet banned):\n");
        for (int i = 0; i < pending_count && pos < resp_len; i++) {
            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "  %-20s hits: %d/%d\n",
                pending[i].ip,
                pending[i].hits,
                pending[i].maxretry);
        }
    } else {
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "Pending IPs:     none\n");
    }
}

/*
 * format_timestamp - Convert a stored UTC timestamp string into a dual-timezone
 * display string: "YYYY-MM-DD HH:MM:SS TZ (YYYY-MM-DD HH:MM:SS UTC)".
 * Falls back to the raw UTC string if parsing fails.
 * out must be at least 80 bytes.
 */
static void format_timestamp(const char *utc_str, char *out, size_t out_len)
{
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));

    if (strptime(utc_str, "%Y-%m-%d %H:%M:%S", &tm_utc) == NULL) {
        strncpy(out, utc_str, out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }

    time_t t = timegm(&tm_utc);

    struct tm *local = localtime(&t);
    char local_str[40];
    strftime(local_str, sizeof(local_str), "%Y-%m-%d %H:%M:%S %Z", local);

    snprintf(out, out_len, "%s (%s UTC)", local_str, utc_str);
}

/*
 * handle_client_banned - Build banned list response string.
 */
static void handle_client_banned(DaemonState *state,
                                  char *resp, size_t resp_len,
                                  bool include_fw_rules)
{
    size_t pos = 0;
    int    total = 0;

    for (int li = 0; li < state->firewalla.list_count; li++) {
        const FwManagedList *ml = &state->firewalla.lists[li];

        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "Banned IPs - %s (%d/%d)\n"
            "----------------------------------------\n",
            ml->list.name,
            ml->list.ip_count,
            state->config.target_list.max_targets);

        for (int ii = 0; ii < ml->list.ip_count && pos < resp_len; ii++) {
            const char *ip = ml->list.ips[ii].ip;

            bool is_placeholder = (strcmp(ip,
                state->config.target_list.placeholder_ip) == 0);

            DbEntry *e = db_find(state, ip);
            const char *source = e ? e->source : BAN_SOURCE_FIREWALLA;

            if (is_placeholder)
                source = BAN_SOURCE_PLACEHOLDER;

            char ts[80];
            format_timestamp(e ? e->timestamp : "unknown", ts, sizeof(ts));

            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "  %-20s [%-13s] %-26s %s\n",
                ip, source, ml->list.name, ts);

            if (!is_placeholder)
                total++;
        }

        pos += (size_t)snprintf(resp + pos, resp_len - pos, "\n");
    }

    if (include_fw_rules) {
        int fw_rule_count = 0;
        for (int i = 0; i < state->db_count; i++) {
            if (strcmp(state->db[i].source, BAN_SOURCE_FW_RULE) == 0 &&
                state->db[i].active)
                fw_rule_count++;
        }

        if (fw_rule_count > 0) {
            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "Blocked by Firewalla individual rules (%d)\n"
                "----------------------------------------\n",
                fw_rule_count);
            for (int i = 0; i < state->db_count && pos < resp_len; i++) {
                DbEntry *e = &state->db[i];
                if (strcmp(e->source, BAN_SOURCE_FW_RULE) != 0 || !e->active)
                    continue;
                char ts[80];
                format_timestamp(e->timestamp, ts, sizeof(ts));
                pos += (size_t)snprintf(resp + pos, resp_len - pos,
                    "  %-20s [%-13s] %s\n", e->ip, e->source, ts);
                total++;
            }
            pos += (size_t)snprintf(resp + pos, resp_len - pos, "\n");
        }
    }

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Total banned: %d across %d list(s)\n",
        total, state->firewalla.list_count);
    (void)pos;
}

/*
 * handle_client_banned_by_date - Build banned list sorted by timestamp.
 */
static void handle_client_banned_by_date(DaemonState *state,
                                          char *resp, size_t resp_len,
                                          bool include_fw_rules)
{
    typedef struct {
        char ip[FW_MAX_IP_LEN];
        char source[48];
        char list_name[FW_MAX_NAME_LEN];
        char timestamp[32];
    } BannedEntry;

    /* Collect target-list IPs — static to avoid large stack allocation */
    static BannedEntry entries[DB_MAX_IPS];
    int count = 0;

    for (int li = 0; li < state->firewalla.list_count; li++) {
        const FwTargetList *list = &state->firewalla.lists[li].list;
        for (int ii = 0; ii < list->ip_count; ii++) {
            const char *ip = list->ips[ii].ip;
            if (strcmp(ip, state->config.target_list.placeholder_ip) == 0)
                continue;
            if (count >= DB_MAX_IPS)
                break;

            DbEntry *e = db_find(state, ip);
            strncpy(entries[count].ip, ip, FW_MAX_IP_LEN - 1);
            strncpy(entries[count].source,
                    e ? e->source : BAN_SOURCE_FIREWALLA,
                    sizeof(entries[count].source) - 1);
            strncpy(entries[count].list_name, list->name, FW_MAX_NAME_LEN - 1);
            strncpy(entries[count].timestamp,
                    e ? e->timestamp : "unknown", 31);
            count++;
        }
    }

    /* Sort target-list IPs by timestamp ascending (oldest first) */
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (strcmp(entries[i].timestamp, entries[j].timestamp) > 0) {
                BannedEntry tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    size_t pos = 0;
    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Banned IPs (sorted by date, oldest first)\n"
        "----------------------------------------\n");

    for (int i = 0; i < count && pos < resp_len; i++) {
        char ts[80];
        format_timestamp(entries[i].timestamp, ts, sizeof(ts));
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "  %-20s [%-11s] %-26s %s\n",
            entries[i].ip, entries[i].source, entries[i].list_name, ts);
    }

    int total = count;

    if (include_fw_rules) {
        /* Collect fw-rule IPs separately — static to avoid large stack allocation */
        static BannedEntry fw_entries[DB_MAX_IPS];
        int fw_count = 0;

        for (int i = 0; i < state->db_count && fw_count < DB_MAX_IPS; i++) {
            DbEntry *e = &state->db[i];
            if (strcmp(e->source, BAN_SOURCE_FW_RULE) != 0 || !e->active)
                continue;
            strncpy(fw_entries[fw_count].ip, e->ip, FW_MAX_IP_LEN - 1);
            strncpy(fw_entries[fw_count].source, e->source,
                    sizeof(fw_entries[fw_count].source) - 1);
            strncpy(fw_entries[fw_count].timestamp, e->timestamp, 31);
            fw_count++;
        }

        /* Sort fw-rule IPs by timestamp ascending */
        for (int i = 0; i < fw_count - 1; i++) {
            for (int j = i + 1; j < fw_count; j++) {
                if (strcmp(fw_entries[i].timestamp,
                           fw_entries[j].timestamp) > 0) {
                    BannedEntry tmp = fw_entries[i];
                    fw_entries[i] = fw_entries[j];
                    fw_entries[j] = tmp;
                }
            }
        }

        if (fw_count > 0) {
            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "\nBlocked by Firewalla individual rules (%d, oldest first)\n"
                "----------------------------------------\n",
                fw_count);
            for (int i = 0; i < fw_count && pos < resp_len; i++) {
                char ts[80];
                format_timestamp(fw_entries[i].timestamp, ts, sizeof(ts));
                pos += (size_t)snprintf(resp + pos, resp_len - pos,
                    "  %-20s [%-13s] %s\n",
                    fw_entries[i].ip, fw_entries[i].source, ts);
            }
            total += fw_count;
        }
    }

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "\nTotal banned: %d\n", total);
    (void)pos;
}

/*
 * handle_client_rules - Show active failregex patterns per log source.
 */
static void handle_client_rules(DaemonState *state,
                                 char *resp, size_t resp_len)
{
    size_t pos = 0;

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Active scan rules (%d log source%s)\n"
        "----------------------------------------\n",
        state->source_count,
        state->source_count == 1 ? "" : "s");

    for (int si = 0; si < state->source_count && pos < resp_len; si++) {
        const ConfigLogSource *src = &state->config.log_sources[si];
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "[Log:%s] — %d pattern%s, maxretry=%d\n",
            src->name,
            src->failregex_count,
            src->failregex_count == 1 ? "" : "s",
            src->maxretry);
        for (int i = 0; i < src->failregex_count && pos < resp_len; i++) {
            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "  [%d] %s\n", i + 1, src->failregex[i]);
        }
        if (src->failregex_count == 0)
            pos += (size_t)snprintf(resp + pos, resp_len - pos,
                "  No patterns configured.\n");
        if (si + 1 < state->source_count)
            pos += (size_t)snprintf(resp + pos, resp_len - pos, "\n");
    }

    (void)pos;
}

/*
 * handle_client_pending - Build pending IPs response string.
 */
static void handle_client_pending(DaemonState *state,
                                   char *resp, size_t resp_len)
{
    PendingIP pending[256];
    int count = 0;
    for (int si = 0; si < state->source_count; si++) {
        PendingIP src_pending[64];
        int n = filter_get_pending(&state->sources[si].filter, src_pending, 64);
        for (int i = 0; i < n && count < 256; i++)
            pending[count++] = src_pending[i];
    }
    size_t pos = 0;

    if (count == 0) {
        snprintf(resp, resp_len, "No pending IPs.\n");
        return;
    }

    pos += (size_t)snprintf(resp + pos, resp_len - pos,
        "Pending IPs (not yet banned):\n"
        "------------------------------\n");

    for (int i = 0; i < count && pos < resp_len; i++) {
        pos += (size_t)snprintf(resp + pos, resp_len - pos,
            "  %-20s hits: %d/%d\n",
            pending[i].ip,
            pending[i].hits,
            pending[i].maxretry);
    }
    (void)pos;
}

/*
 * process_fw_rule_ips - Update db and filter for IPs that fw_reconcile found
 * are covered by Firewalla individual block rules. Those IPs have already been
 * removed from our managed target lists by fw_reconcile. Here we tag them in
 * the db so future reconciliations skip them, and seed the filter engine so
 * the log scanner won't try to re-ban them.
 */
static void process_fw_rule_ips(DaemonState *state)
{
    int count = state->firewalla.individual_rule_ip_count;
    if (count == 0)
        return;

    bool changed = false;
    for (int i = 0; i < count; i++) {
        const char *ip = state->firewalla.individual_rule_ips[i];
        DbEntry *e = db_find(state, ip);
        if (e == NULL || strcmp(e->source, BAN_SOURCE_FW_RULE) != 0) {
            db_add(state, ip, BAN_SOURCE_FW_RULE);
            changed = true;
        }
        for (int si = 0; si < state->source_count; si++)
            filter_mark_banned(&state->sources[si].filter, ip);
    }
    if (changed)
        db_save(state);
}

/*
 * do_ban_ip - Ban an IP via Firewalla and update local db.
 * source should be an "auto:<name>" tag or BAN_SOURCE_MANUAL.
 */
static int do_ban_ip(DaemonState *state, const char *ip, const char *source)
{
    FwBanResult result;
    if (fw_ban_ip(&state->firewalla, &state->config, ip, &result) != 0) {
        fprintf(stderr, "ban: failed to ban %s: %s\n",
                ip, result.error_msg);
        return -1;
    }

    if (result.already_banned) {
        printf("ban: %s already banned\n", ip);
        for (int si = 0; si < state->source_count; si++)
            filter_mark_banned(&state->sources[si].filter, ip);
        return 0;
    }

    /* Update local db */
    db_add(state, ip, source);
    db_save(state);

    /* Mark in all filter engines */
    for (int si = 0; si < state->source_count; si++)
        filter_mark_banned(&state->sources[si].filter, ip);

    printf("ban: [%s] %s -> %s\n", source, ip, result.list_name);

    if (result.new_list_created)
        printf("ban: created new overflow list '%s'\n", result.list_name);

    return 0;
}

/*
 * do_unban_ip - Unban an IP from Firewalla and update local db.
 */
static int do_unban_ip(DaemonState *state, const char *ip)
{
    FwUnbanResult result;
    if (fw_unban_ip(&state->firewalla, &state->config, ip, &result) != 0) {
        fprintf(stderr, "unban: failed to unban %s: %s\n",
                ip, result.error_msg);
        return -1;
    }

    if (result.not_found) {
        printf("unban: %s was not banned\n", ip);
        return 0;
    }

    /* Update local db */
    db_remove(state, ip);
    db_save(state);

    printf("unban: removed %s from %s\n", ip, result.list_name);
    return 0;
}

/*
 * handle_client_connection - Handle a single client connection.
 * Reads command, dispatches, writes response.
 */
static void handle_client_connection(DaemonState *state, int client_fd)
{
    char cmd[MAX_CLIENT_MSG];
    ssize_t n = recv(client_fd, cmd, sizeof(cmd) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    cmd[n] = '\0';

    /* Strip trailing newline */
    size_t len = strlen(cmd);
    while (len > 0 && (cmd[len-1] == '\n' || cmd[len-1] == '\r'))
        cmd[--len] = '\0';

    char *response = calloc(MAX_RESPONSE_LEN, 1);
    if (response == NULL) {
        close(client_fd);
        return;
    }

    if (strcmp(cmd, "status") == 0) {
        handle_client_status(state, response, MAX_RESPONSE_LEN);

    } else if (strcmp(cmd, "banned") == 0) {
        handle_client_banned(state, response, MAX_RESPONSE_LEN, false);

    } else if (strcmp(cmd, "banned-fw") == 0) {
        handle_client_banned(state, response, MAX_RESPONSE_LEN, true);

    } else if (strcmp(cmd, "banned-date") == 0) {
        handle_client_banned_by_date(state, response, MAX_RESPONSE_LEN, false);

    } else if (strcmp(cmd, "banned-date-fw") == 0) {
        handle_client_banned_by_date(state, response, MAX_RESPONSE_LEN, true);

    } else if (strcmp(cmd, "pending") == 0) {
        handle_client_pending(state, response, MAX_RESPONSE_LEN);

    } else if (strcmp(cmd, "rules") == 0) {
        handle_client_rules(state, response, MAX_RESPONSE_LEN);

    } else if (strncmp(cmd, "ban ", 4) == 0) {
        const char *ip = cmd + 4;
        if (do_ban_ip(state, ip, BAN_SOURCE_MANUAL) == 0)
            snprintf(response, MAX_RESPONSE_LEN, "OK: banned %s\n", ip);
        else
            snprintf(response, MAX_RESPONSE_LEN, "ERROR: failed to ban %s\n", ip);

    } else if (strncmp(cmd, "unban ", 6) == 0) {
        const char *ip = cmd + 6;
        if (do_unban_ip(state, ip) == 0)
            snprintf(response, MAX_RESPONSE_LEN, "OK: unbanned %s\n", ip);
        else
            snprintf(response, MAX_RESPONSE_LEN,
                     "ERROR: failed to unban %s\n", ip);

    } else if (strcmp(cmd, "reload") == 0) {
        g_reload_requested = 1;
        snprintf(response, MAX_RESPONSE_LEN, "OK: reload requested\n");

    } else if (strcmp(cmd, "rescan") == 0) {
        for (int si = 0; si < state->source_count; si++)
            logmon_request_rescan(&state->sources[si].logmon, false);
        snprintf(response, MAX_RESPONSE_LEN,
                 "OK: rescan requested on %d source(s)\n", state->source_count);

    } else if (strcmp(cmd, "rescan-all") == 0) {
        for (int si = 0; si < state->source_count; si++)
            logmon_request_rescan(&state->sources[si].logmon, true);
        snprintf(response, MAX_RESPONSE_LEN,
                 "OK: rescan-all requested on %d source(s)\n",
                 state->source_count);

    } else {
        snprintf(response, MAX_RESPONSE_LEN,
                 "ERROR: unknown command '%s'\n"
                 "Commands: status, banned, pending, rules, "
                 "ban <ip>, unban <ip>, reload\n", cmd);
    }

    /* Send response */
    send(client_fd, response, strlen(response), 0);
    free(response);
    close(client_fd);
}

/* -----------------------------------------------------------------------------
 * Log line callback - called by logmon for each new line
 * ----------------------------------------------------------------------------- */

static void on_log_line(const char *line, void *userdata)
{
    LogSourceCtx *ctx   = (LogSourceCtx *)userdata;
    DaemonState  *state = (DaemonState *)ctx->state;
    LogSource    *src   = &state->sources[ctx->source_idx];
    FilterResult  result;

    state->lines_processed++;

    if (filter_process_line(&src->filter, &state->ignore, line, &result) != 0)
        return;

    if (!result.matched || result.ignored || result.already_banned)
        return;

    if (result.ban_triggered) {
        char source_tag[48];
        snprintf(source_tag, sizeof(source_tag), "auto:%s", src->name);
        printf("filter: [%s] ban triggered for %s (hits: %d)\n",
               src->name, result.ip, result.hit_count);
        do_ban_ip(state, result.ip, source_tag);
    }
}

/* -----------------------------------------------------------------------------
 * Initialization
 * ----------------------------------------------------------------------------- */

/*
 * init_log_source - Initialize a single LogSource (filter engine + logmon).
 * Builds a per-source Config overlay so the existing filter_init/logmon_init
 * APIs are used without modification.
 */
static int init_log_source(DaemonState *state, int idx, bool rescan_mode)
{
    const ConfigLogSource *src_cfg = &state->config.log_sources[idx];
    LogSource             *ls      = &state->sources[idx];
    LogSourceCtx          *ctx     = &state->source_ctxs[idx];

    strncpy(ls->name, src_cfg->name, sizeof(ls->name) - 1);

    ctx->state      = state;
    ctx->source_idx = idx;

    if (filter_init(&ls->filter, src_cfg) != 0) {
        fprintf(stderr, "fwallascan2ban: filter_init failed for [Log:%s]\n",
                src_cfg->name);
        return -1;
    }

    if (logmon_init(&ls->logmon, src_cfg, on_log_line, ctx) != 0) {
        fprintf(stderr, "fwallascan2ban: logmon_init failed for [Log:%s]\n",
                src_cfg->name);
        filter_free(&ls->filter);
        return -1;
    }

    if (rescan_mode)
        logmon_request_rescan(&ls->logmon, true);

    return 0;
}

static int daemon_init(DaemonState *state, const char *config_path,
                       bool rescan_mode)
{
    memset(state, 0, sizeof(DaemonState));
    state->server_sock = -1;
    state->started_at  = time(NULL);

    /* Create required directories */
    mkdir(SOCKET_DIR, 0755);
    mkdir(DB_DIR, 0755);

    /* Load config */
    printf("fwallascan2ban: loading config from %s\n", config_path);
    if (config_load(config_path, &state->config) != 0) {
        fprintf(stderr, "fwallascan2ban: config load failed\n");
        return -1;
    }
    if (config_validate(&state->config) != 0) {
        fprintf(stderr, "fwallascan2ban: config validation failed\n");
        return -1;
    }

    /* Initialize ignore list */
    if (ignore_init(&state->ignore, &state->config) != 0) {
        fprintf(stderr, "fwallascan2ban: ignore init failed\n");
        return -1;
    }

    /* Initialize Firewalla client */
    printf("fwallascan2ban: connecting to Firewalla MSP...\n");
    if (fw_init(&state->firewalla, &state->config) != 0) {
        fprintf(stderr, "fwallascan2ban: Firewalla init failed\n");
        return -1;
    }

    /* Migrate db from v1 format if needed, then load */
    db_migrate_v1();
    if (db_load(state) != 0) {
        fprintf(stderr, "fwallascan2ban: db load failed\n");
        return -1;
    }

    /* Run reconciliation */
    static const char *db_ips[DB_MAX_IPS];
    int db_ip_count = db_get_active_ips(state, db_ips, DB_MAX_IPS);

    FwReconcileReport report;
    if (fw_reconcile(&state->firewalla, &state->config,
                     db_ips, db_ip_count, &report) != 0) {
        fprintf(stderr, "fwallascan2ban: reconciliation failed\n");
        return -1;
    }

    /* Handle IPs found in Firewalla but not in db */
    if (report.in_fw_not_db > 0 &&
        state->config.reconciliation.on_ip_in_firewalla_not_db ==
        ON_FW_NOT_DB_ADD)
    {
        static FwIP all_ips[DB_MAX_IPS];
        static char list_ids[DB_MAX_IPS][FW_MAX_ID_LEN];
        int total = fw_get_all_banned_ips(&state->firewalla, all_ips,
                                           DB_MAX_IPS, list_ids);
        for (int i = 0; i < total; i++) {
            const char *ip = all_ips[i].ip;
            if (strcmp(ip, state->config.target_list.placeholder_ip) == 0)
                continue;
            if (db_find(state, ip) == NULL)
                db_add(state, ip, BAN_SOURCE_FIREWALLA);
        }
        db_save(state);
    }

    /* Set up Unix domain socket */
    state->server_sock = setup_socket();
    if (state->server_sock < 0) {
        fprintf(stderr, "fwallascan2ban: socket setup failed\n");
        return -1;
    }

    /* Initialize all log sources (filter engines + logmons) */
    int n_sources = state->config.log_source_count;
    for (int i = 0; i < n_sources; i++) {
        if (init_log_source(state, i, rescan_mode) != 0) {
            fprintf(stderr, "fwallascan2ban: failed to init log source %d (%s)\n",
                    i, state->config.log_sources[i].name);
            return -1;
        }
        state->source_count++;
    }

    /* Process IPs now covered by Firewalla individual rules
     * (needs sources initialized so filter_mark_banned covers all engines) */
    process_fw_rule_ips(state);

    /* Seed all filter engines with currently banned IPs */
    static FwIP banned_ips[DB_MAX_IPS];
    static char banned_list_ids[DB_MAX_IPS][FW_MAX_ID_LEN];
    int banned_count = fw_get_all_banned_ips(&state->firewalla,
                                              banned_ips, DB_MAX_IPS,
                                              banned_list_ids);
    static const char *banned_ip_ptrs[DB_MAX_IPS];
    for (int i = 0; i < banned_count; i++)
        banned_ip_ptrs[i] = banned_ips[i].ip;
    for (int si = 0; si < state->source_count; si++)
        filter_mark_banned_bulk(&state->sources[si].filter,
                                 banned_ip_ptrs, banned_count);

    state->last_reconcile = time(NULL);
    state->running        = true;

    printf("fwallascan2ban: initialized successfully\n");
    for (int i = 0; i < state->source_count; i++)
        printf("fwallascan2ban: monitoring [%s] %s\n",
               state->sources[i].name,
               state->config.log_sources[i].log_pattern);
    printf("fwallascan2ban: listening on %s\n", SOCKET_PATH);

    return 0;
}

static void daemon_shutdown(DaemonState *state)
{
    printf("fwallascan2ban: shutting down...\n");

    for (int i = 0; i < state->source_count; i++) {
        logmon_free(&state->sources[i].logmon);
        filter_free(&state->sources[i].filter);
    }
    ignore_free(&state->ignore);
    fw_free(&state->firewalla);
    config_free(&state->config);

    if (state->server_sock >= 0) {
        close(state->server_sock);
        unlink(SOCKET_PATH);
    }

    printf("fwallascan2ban: shutdown complete\n");
}

/* -----------------------------------------------------------------------------
 * Main event loop
 * ----------------------------------------------------------------------------- */

static void run_main_loop(DaemonState *state)
{
    printf("fwallascan2ban: entering main loop\n");

    static const char *db_ips[DB_MAX_IPS];

    while (g_running) {

        /* Check for reload request */
        if (g_reload_requested) {
            g_reload_requested = 0;
            printf("fwallascan2ban: reloading config from %s\n",
                   state->config.config_path);

            static Config new_config;
            if (config_load(state->config.config_path, &new_config) != 0) {
                fprintf(stderr, "fwallascan2ban: config_load failed, "
                        "keeping old config\n");
            } else {
                /* Tear down all existing log sources */
                for (int i = 0; i < state->source_count; i++) {
                    logmon_free(&state->sources[i].logmon);
                    filter_free(&state->sources[i].filter);
                }
                state->source_count = 0;

                ignore_free(&state->ignore);
                state->config = new_config;
                ignore_init(&state->ignore, &state->config);

                /* Re-init each log source from the new config */
                for (int i = 0; i < state->config.log_source_count; i++) {
                    if (init_log_source(state, i, false) == 0)
                        state->source_count++;
                    else
                        fprintf(stderr, "fwallascan2ban: reload: failed to "
                                "init [Log:%s]\n",
                                state->config.log_sources[i].name);
                }

                int total_patterns = 0;
                for (int i = 0; i < state->config.log_source_count; i++)
                    total_patterns += state->config.log_sources[i].failregex_count;
                printf("fwallascan2ban: config reloaded — %d source(s), "
                       "%d total patterns\n",
                       state->source_count, total_patterns);
            }

            /* Re-run reconciliation after reload */
            int db_ip_count = db_get_active_ips(state, db_ips, DB_MAX_IPS);
            FwReconcileReport report;
            fw_reconcile(&state->firewalla, &state->config,
                         db_ips, db_ip_count, &report);
            state->last_reconcile = time(NULL);

            /* Process IPs now covered by Firewalla individual rules */
            process_fw_rule_ips(state);

            /* Re-seed all filter engines with already-banned IPs */
            static FwIP reload_banned_ips[DB_MAX_IPS];
            static char reload_banned_list_ids[DB_MAX_IPS][FW_MAX_ID_LEN];
            int reload_banned_count = fw_get_all_banned_ips(
                &state->firewalla, reload_banned_ips,
                DB_MAX_IPS, reload_banned_list_ids);
            static const char *reload_banned_ptrs[DB_MAX_IPS];
            for (int i = 0; i < reload_banned_count; i++)
                reload_banned_ptrs[i] = reload_banned_ips[i].ip;
            for (int si = 0; si < state->source_count; si++)
                filter_mark_banned_bulk(&state->sources[si].filter,
                                        reload_banned_ptrs,
                                        reload_banned_count);
        }

        /* Check periodic reconciliation */
        if (state->config.reconciliation.reconcile_interval > 0) {
            time_t now = time(NULL);
            if (now - state->last_reconcile >=
                state->config.reconciliation.reconcile_interval)
            {
                printf("fwallascan2ban: running periodic reconciliation\n");
                int db_ip_count = db_get_active_ips(state, db_ips,
                                                     DB_MAX_IPS);
                FwReconcileReport report;
                fw_reconcile(&state->firewalla, &state->config,
                             db_ips, db_ip_count, &report);
                process_fw_rule_ips(state);
                state->last_reconcile = now;
            }
        }

        /* Use select() to monitor all inotify fds and the socket fd */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(state->server_sock, &read_fds);

        int max_fd = state->server_sock;
        for (int si = 0; si < state->source_count; si++) {
            int ifd = state->sources[si].logmon.inotify_fd;
            if (ifd >= 0) {
                FD_SET(ifd, &read_fds);
                if (ifd > max_fd)
                    max_fd = ifd;
            }
        }

        struct timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (ready < 0) {
            if (errno == EINTR)
                continue; /* Signal received - loop back to check g_running */
            fprintf(stderr, "fwallascan2ban: select error: %s\n",
                    strerror(errno));
            break;
        }

        /* Handle client connections */
        if (ready > 0 && FD_ISSET(state->server_sock, &read_fds)) {
            int client_fd = accept(state->server_sock, NULL, NULL);
            if (client_fd >= 0)
                handle_client_connection(state, client_fd);
        }

        /* Poll all log sources for new lines */
        for (int si = 0; si < state->source_count; si++)
            logmon_poll(&state->sources[si].logmon, 0);
    }
}

/* -----------------------------------------------------------------------------
 * Entry point
 * ----------------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -c <path>   Config file path (default: %s)\n",
           DEFAULT_CONFIG_PATH);
    printf("  -d          Debug mode (dump config and exit)\n");
    printf("  -r          Rescan mode: reprocess current log from beginning\n");
    printf("  -v          Print version and exit\n");
    printf("  -h          Print this help and exit\n");
}

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG_PATH;
    bool debug_mode     = false;
    bool rescan_mode    = false;
    int opt;

    while ((opt = getopt(argc, argv, "c:dvhr")) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'r':
                rescan_mode = true;
                break;
            case 'v':
                printf("fwallascan2ban version %s\n", DAEMON_VERSION);
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Set up signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = handle_sighup;
    sigaction(SIGHUP, &sa, NULL);

    /* Ignore SIGPIPE - handle broken client connections gracefully */
    signal(SIGPIPE, SIG_IGN);

    setlinebuf(stdout);
    setlinebuf(stderr);

    printf("fwallascan2ban v%s starting\n", DAEMON_VERSION);

    /* Initialize daemon */
    static DaemonState state; /* static so it's zero-initialized */
    if (daemon_init(&state, config_path, rescan_mode) != 0) {
        fprintf(stderr, "fwallascan2ban: initialization failed\n");
        return 1;
    }

    /* Debug mode - dump state and exit */
    if (debug_mode) {
        config_dump(&state.config);
        ignore_dump(&state.ignore);
        for (int i = 0; i < state.source_count; i++) {
            printf("--- Filter [Log:%s] ---\n", state.sources[i].name);
            filter_dump(&state.sources[i].filter);
        }
        fw_dump(&state.firewalla);
        daemon_shutdown(&state);
        return 0;
    }

    /* Run main loop */
    run_main_loop(&state);

    /* Clean shutdown */
    daemon_shutdown(&state);
    return 0;
}
