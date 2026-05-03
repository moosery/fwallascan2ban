/* =============================================================================
 * fwallascan2ban-client.c
 * Client CLI tool for fwallascan2ban
 *
 * Connects to the running daemon via Unix domain socket and sends commands.
 * The daemon must be running for any commands to work.
 *
 * Usage:
 *   fwallascan2ban-client status
 *   fwallascan2ban-client banned
 *   fwallascan2ban-client pending
 *   fwallascan2ban-client ban <ip>
 *   fwallascan2ban-client unban <ip>
 *   fwallascan2ban-client reload
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define SOCKET_PATH         "/run/fwallascan2ban/fwallascan2ban.sock"
#define MAX_CMD_LEN         256
#define MAX_RESPONSE_LEN    65536
#define CLIENT_VERSION      "1.2.0"

/* -----------------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    printf("Usage: %s <command> [arguments]\n\n", prog);
    printf("Commands:\n");
    printf("  status          Show daemon status, statistics, and pending IPs\n");
    printf("  banned          List all banned IPs across all target lists\n");
    printf("  banned --sort-date  List banned IPs sorted by date (oldest first)\n");
    printf("  banned --fw-rules   Include IPs blocked by Firewalla individual rules\n");
    printf("  banned --sort-date --fw-rules  Both options combined\n");
    printf("  pending         List IPs approaching the ban threshold\n");
    printf("  rules           Show active failregex scan patterns\n");
    printf("  ban <ip>        Manually ban an IP address immediately\n");
    printf("  unban <ip>      Remove a banned IP from the target list\n");
    printf("  reload          Reload config and run reconciliation\n");
    printf("  rescan          Rescan log directory and switch to newest file\n");
    printf("  rescan-all      Rescan and reprocess current log from beginning\n");
    printf("  version         Print client version\n");
    printf("  help            Print this help message\n");
    printf("\nExamples:\n");
    printf("  %s status\n", prog);
    printf("  %s ban 1.2.3.4\n", prog);
    printf("  %s unban 1.2.3.4\n", prog);
    printf("\nThe daemon must be running for commands to work.\n");
    printf("Socket: %s\n", SOCKET_PATH);
}

/*
 * connect_to_daemon - Connect to the daemon's Unix domain socket.
 * Returns socket fd on success, -1 on failure.
 */
static int connect_to_daemon(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error: cannot create socket: %s\n",
                strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno == ENOENT || errno == ECONNREFUSED) {
            fprintf(stderr,
                    "error: cannot connect to fwallascan2ban daemon.\n"
                    "Is the daemon running? Check: systemctl status fwallascan2ban\n");
        } else {
            fprintf(stderr, "error: connect failed: %s\n", strerror(errno));
        }
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * send_command - Send a command string to the daemon and print the response.
 * Returns 0 on success, -1 on failure.
 */
static int send_command(const char *cmd)
{
    int fd = connect_to_daemon();
    if (fd < 0)
        return -1;

    /* Send command */
    if (send(fd, cmd, strlen(cmd), 0) < 0) {
        fprintf(stderr, "error: send failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Read and print response */
    char   *response = malloc(MAX_RESPONSE_LEN);
    if (response == NULL) {
        fprintf(stderr, "error: out of memory\n");
        close(fd);
        return -1;
    }

    size_t  total    = 0;
    ssize_t n;

    while (total < MAX_RESPONSE_LEN - 1 &&
           (n = recv(fd, response + total,
                     MAX_RESPONSE_LEN - 1 - total, 0)) > 0)
    {
        total += (size_t)n;
    }

    response[total] = '\0';

    if (total > 0)
        printf("%s", response);

    free(response);
    close(fd);
    return 0;
}

/* -----------------------------------------------------------------------------
 * Entry point
 * ----------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    /* Local commands - no daemon needed */
    if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 ||
        strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(command, "version") == 0 || strcmp(command, "-v") == 0 ||
        strcmp(command, "--version") == 0) {
        printf("fwallascan2ban-client version %s\n", CLIENT_VERSION);
        return 0;
    }

    /* Commands that require the daemon */
    char cmd[MAX_CMD_LEN];

    if (strcmp(command, "status") == 0) {
        return send_command("status") == 0 ? 0 : 1;

    } else if (strcmp(command, "banned") == 0) {
        bool sort_date = false;
        bool fw_rules  = false;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--sort-date") == 0) sort_date = true;
            else if (strcmp(argv[i], "--fw-rules") == 0) fw_rules  = true;
        }
        const char *subcmd = sort_date
            ? (fw_rules ? "banned-date-fw" : "banned-date")
            : (fw_rules ? "banned-fw"      : "banned");
        return send_command(subcmd) == 0 ? 0 : 1;

    } else if (strcmp(command, "pending") == 0) {
        return send_command("pending") == 0 ? 0 : 1;

    } else if (strcmp(command, "rules") == 0) {
        return send_command("rules") == 0 ? 0 : 1;

    } else if (strcmp(command, "reload") == 0) {
        return send_command("reload") == 0 ? 0 : 1;

    } else if (strcmp(command, "rescan") == 0) {
        return send_command("rescan") == 0 ? 0 : 1;

    } else if (strcmp(command, "rescan-all") == 0) {
        return send_command("rescan-all") == 0 ? 0 : 1;

    } else if (strcmp(command, "ban") == 0) {
        if (argc < 3) {
            fprintf(stderr, "error: 'ban' requires an IP address argument\n");
            fprintf(stderr, "Usage: %s ban <ip>\n", argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "ban %s", argv[2]);
        return send_command(cmd) == 0 ? 0 : 1;

    } else if (strcmp(command, "unban") == 0) {
        if (argc < 3) {
            fprintf(stderr,
                    "error: 'unban' requires an IP address argument\n");
            fprintf(stderr, "Usage: %s unban <ip>\n", argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "unban %s", argv[2]);
        return send_command(cmd) == 0 ? 0 : 1;

    } else {
        fprintf(stderr, "error: unknown command '%s'\n\n", command);
        print_usage(argv[0]);
        return 1;
    }
}
