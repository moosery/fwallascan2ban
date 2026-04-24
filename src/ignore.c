/* =============================================================================
 * ignore.c
 * IP ignore list (ignoreregex) handling for fwallascan2ban
 *
 * Manages the list of IP addresses and CIDR ranges that should never be
 * banned. See ignore.h for full documentation.
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ignore.h"

/* -----------------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------------- */

/*
 * parse_cidr - Parse an IPv4 address or CIDR range string into an IgnoreEntry.
 *
 * Accepts:
 *   "192.168.1.1"       - single host (becomes /32)
 *   "192.168.1.0/24"    - CIDR range
 *
 * Returns 0 on success, -1 on invalid format.
 */
static int parse_cidr(const char *str, IgnoreEntry *entry)
{
    char        buf[64];
    char       *slash;
    int         prefix_len = 32;    /* Default to /32 (single host) */
    struct in_addr addr;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Check for CIDR prefix */
    slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            fprintf(stderr, "ignore: invalid prefix length in '%s'\n", str);
            return -1;
        }
    }

    /* Parse the IP address */
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        fprintf(stderr, "ignore: invalid IPv4 address in '%s'\n", str);
        return -1;
    }

    /* Build netmask from prefix length */
    uint32_t netmask = (prefix_len == 0)
        ? 0
        : (~0u << (32 - prefix_len));

    /* Store in host byte order for easy comparison */
    entry->network  = ntohl(addr.s_addr) & netmask;
    entry->netmask  = netmask;
    entry->is_ipv6  = false;
    strncpy(entry->raw, str, sizeof(entry->raw) - 1);

    return 0;
}

/*
 * parse_ipv6 - Parse an IPv6 address string into an IgnoreEntry.
 *
 * Currently only supports exact match (no CIDR). Used for ::1 loopback.
 *
 * Returns 0 on success, -1 on invalid format.
 */
static int parse_ipv6(const char *str, IgnoreEntry *entry)
{
    /* We store IPv6 as raw string for exact comparison only.
     * network and netmask fields are unused for IPv6 entries. */
    entry->network  = 0;
    entry->netmask  = 0;
    entry->is_ipv6  = true;
    strncpy(entry->raw, str, sizeof(entry->raw) - 1);
    return 0;
}

/*
 * is_ipv6 - Returns true if the string looks like an IPv6 address.
 */
static bool is_ipv6_str(const char *str)
{
    return (strchr(str, ':') != NULL);
}

/* -----------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------------- */

int ignore_init(IgnoreList *list, const Config *config)
{
    memset(list, 0, sizeof(IgnoreList));

    /* Always add IPv4 loopback */
    if (ignore_add(list, "127.0.0.1") != 0)
        return -1;

    /* Always add IPv4 loopback range */
    if (ignore_add(list, "127.0.0.0/8") != 0)
        return -1;

    /* Always add IPv6 loopback */
    if (ignore_add(list, "::1") != 0)
        return -1;

    /* Always add the placeholder IP */
    if (config->target_list.placeholder_ip[0] != '\0') {
        if (ignore_add(list, config->target_list.placeholder_ip) != 0)
            return -1;
    }

    /* Add all ignoreregex entries from config */
    for (int i = 0; i < config->filters.ignoreregex_count; i++) {
        if (ignore_add(list, config->filters.ignoreregex[i]) != 0)
            return -1;
    }

    return 0;
}

void ignore_free(IgnoreList *list)
{
    /* All fields are fixed-size arrays - nothing to free */
    (void)list;
}

int ignore_add(IgnoreList *list, const char *entry)
{
    if (list->count >= IGNORE_MAX_ENTRIES) {
        fprintf(stderr, "ignore: ignore list full (max %d entries)\n",
                IGNORE_MAX_ENTRIES);
        return -1;
    }

    /* Check for duplicate before adding */
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->entries[i].raw, entry) == 0)
            return 0; /* Already present, silently skip */
    }

    IgnoreEntry *e = &list->entries[list->count];
    memset(e, 0, sizeof(IgnoreEntry));

    int rc;
    if (is_ipv6_str(entry)) {
        rc = parse_ipv6(entry, e);
    } else {
        rc = parse_cidr(entry, e);
    }

    if (rc == 0)
        list->count++;

    return rc;
}

bool ignore_check(const IgnoreList *list, const char *ip)
{
    if (is_ipv6_str(ip)) {
        /* IPv6: exact string match only */
        for (int i = 0; i < list->count; i++) {
            if (list->entries[i].is_ipv6 &&
                strcmp(list->entries[i].raw, ip) == 0) {
                return true;
            }
        }
        return false;
    }

    /* IPv4: convert to uint32 and check against each entry */
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        /* Not a valid IPv4 address - don't ignore, let filter handle it */
        return false;
    }

    uint32_t host_ip = ntohl(addr.s_addr);

    for (int i = 0; i < list->count; i++) {
        const IgnoreEntry *e = &list->entries[i];
        if (e->is_ipv6)
            continue;
        /* Check if host_ip falls within this entry's network */
        if ((host_ip & e->netmask) == e->network)
            return true;
    }

    return false;
}

void ignore_dump(const IgnoreList *list)
{
    printf("=== Ignore list (%d entries) ===\n", list->count);
    for (int i = 0; i < list->count; i++) {
        const IgnoreEntry *e = &list->entries[i];
        if (e->is_ipv6) {
            printf("  [%d] %s (IPv6 exact)\n", i, e->raw);
        } else {
            printf("  [%d] %s (network=0x%08X mask=0x%08X)\n",
                   i, e->raw, e->network, e->netmask);
        }
    }
    printf("================================\n");
}