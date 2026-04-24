#ifndef IGNORE_H
#define IGNORE_H

/* =============================================================================
 * ignore.h
 * IP ignore list (ignoreregex) handling for fwallascan2ban
 *
 * Manages the list of IP addresses and CIDR ranges that should never be
 * banned, regardless of how many failregex patterns they match.
 *
 * Supports:
 *   - Single IPv4 addresses:    192.168.1.1
 *   - IPv4 CIDR ranges:         192.168.1.0/24
 *   - IPv6 loopback:            ::1
 *   - IPv4 loopback:            127.0.0.1
 *   - Automatic internal entries (placeholder IP, loopbacks)
 *
 * The ignore list is built at startup from:
 *   1. The ignoreregex entries in the config file
 *   2. The placeholder_ip from the config (always added automatically)
 *   3. 127.0.0.1 and ::1 (always added automatically)
 * ============================================================================= */

#include <stdbool.h>
#include <stdint.h>
#include "config.h"

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define IGNORE_MAX_ENTRIES  128     /* Maximum number of ignore list entries    */

/* -----------------------------------------------------------------------------
 * Structs
 * ----------------------------------------------------------------------------- */

/* A single ignore list entry - either a host IP or a CIDR range */
typedef struct {
    uint32_t    network;    /* Network address in host byte order   */
    uint32_t    netmask;    /* Netmask in host byte order           */
    bool        is_ipv6;    /* true if this is an IPv6 entry        */
    char        raw[64];    /* Original string from config          */
} IgnoreEntry;

/* The ignore list - collection of all entries */
typedef struct {
    IgnoreEntry entries[IGNORE_MAX_ENTRIES];
    int         count;
} IgnoreList;

/* -----------------------------------------------------------------------------
 * Function prototypes
 * ----------------------------------------------------------------------------- */

/*
 * ignore_init - Initialize an IgnoreList from a loaded Config.
 *
 * Populates the ignore list from the config's ignoreregex entries and
 * automatically adds:
 *   - 127.0.0.1 (IPv4 loopback)
 *   - ::1       (IPv6 loopback)
 *   - The placeholder_ip from config
 *
 * Parameters:
 *   list   - Pointer to an IgnoreList to initialize
 *   config - Pointer to a loaded Config struct
 *
 * Returns:
 *   0 on success
 *  -1 on error (invalid entry, list full)
 */
int ignore_init(IgnoreList *list, const Config *config);

/*
 * ignore_free - Free any resources used by an IgnoreList.
 *
 * Parameters:
 *   list - Pointer to an IgnoreList to free
 *
 * Notes:
 *   Currently all fields are fixed-size arrays so this is a no-op,
 *   but provided for future extensibility.
 */
void ignore_free(IgnoreList *list);

/*
 * ignore_check - Check whether a given IP address should be ignored.
 *
 * Tests the IP against all entries in the ignore list. For CIDR entries,
 * performs a proper subnet match. For host entries, performs an exact match.
 *
 * Parameters:
 *   list - Pointer to an initialized IgnoreList
 *   ip   - IP address string to check (IPv4 dotted decimal or IPv6)
 *
 * Returns:
 *   true  if the IP matches any ignore list entry (should be ignored)
 *   false if the IP does not match any entry (may be banned)
 */
bool ignore_check(const IgnoreList *list, const char *ip);

/*
 * ignore_add - Add a single IP address or CIDR range to the ignore list.
 *
 * Parameters:
 *   list  - Pointer to an IgnoreList to add to
 *   entry - IP address or CIDR range string (e.g. "192.168.1.0/24")
 *
 * Returns:
 *   0 on success
 *  -1 on error (invalid format, list full)
 */
int ignore_add(IgnoreList *list, const char *entry);

/*
 * ignore_dump - Print the ignore list to stdout for debugging.
 *
 * Parameters:
 *   list - Pointer to an initialized IgnoreList
 */
void ignore_dump(const IgnoreList *list);

#endif /* IGNORE_H */