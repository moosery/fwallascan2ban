#ifndef FILTER_H
#define FILTER_H

/* =============================================================================
 * filter.h
 * Log line pattern matching and IP hit counter for fwallascan2ban
 *
 * Manages the failregex patterns from the config file and maintains a
 * per-IP hit counter table. When an IP's hit count reaches the maxretry
 * threshold it is flagged for banning.
 *
 * The <HOST> token in failregex patterns is replaced at init time with
 * a compiled regex group that matches both IPv4 and IPv6 addresses.
 *
 * Hit counters persist for the lifetime of the daemon. There is no
 * time window (findtime) — hits accumulate indefinitely until the IP
 * is banned or the daemon is restarted/reloaded.
 *
 * Uses POSIX extended regular expressions (regex.h) — no external
 * dependencies required.
 * ============================================================================= */

#include <stdbool.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "config.h"
#include "ignore.h"

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define FILTER_HOST_PATTERN \
    "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" \
    "|[0-9a-fA-F:]{2,39})"

#define FILTER_MAX_IP_LEN       64      /* Maximum length of an IP string           */
#define FILTER_HIT_TABLE_SIZE   4096    /* Hash table size for IP hit counters      */
                                        /* Should be a power of 2                   */

/* -----------------------------------------------------------------------------
 * Structs
 * ----------------------------------------------------------------------------- */

/* A single compiled failregex pattern */
typedef struct {
    pcre2_code *compiled;           /* Compiled PCRE2 regex                     */
    char        raw[CONFIG_MAX_VALUE]; /* Original pattern string from config   */
    int         host_group;         /* Capture group index for <HOST> match     */
} FilterPattern;

/* A single entry in the IP hit counter hash table */
typedef struct HitEntry {
    char            ip[FILTER_MAX_IP_LEN];  /* IP address string                */
    int             hits;                   /* Number of times this IP matched  */
    bool            banned;                 /* true if already queued for ban   */
    struct HitEntry *next;                  /* Next entry in chain (collision)  */
} HitEntry;

/* The filter engine - compiled patterns and hit counter table */
typedef struct {
    FilterPattern   patterns[CONFIG_MAX_PATTERNS];  /* Compiled regex patterns  */
    int             pattern_count;                  /* Number of patterns       */
    int             maxretry;                       /* Ban threshold            */
    HitEntry       *hit_table[FILTER_HIT_TABLE_SIZE]; /* IP hit counter table  */
    int             total_hits;                     /* Total lines matched      */
    int             total_ips_seen;                 /* Unique IPs seen          */
    int             total_banned;                   /* Total IPs flagged        */
} FilterEngine;

/* Result of processing a single log line */
typedef struct {
    bool    matched;                        /* true if any pattern matched      */
    bool    ignored;                        /* true if IP is in ignore list     */
    bool    already_banned;                 /* true if IP was already banned    */
    bool    ban_triggered;                  /* true if hit count >= maxretry    */
    char    ip[FILTER_MAX_IP_LEN];          /* Extracted IP address             */
    int     hit_count;                      /* Current hit count for this IP    */
    int     pattern_index;                  /* Index of matched pattern         */
} FilterResult;

/* A pending IP - approaching but not yet at the ban threshold */
typedef struct {
    char    ip[FILTER_MAX_IP_LEN];  /* IP address string                        */
    int     hits;                   /* Current hit count                        */
    int     maxretry;               /* Ban threshold                            */
} PendingIP;

/* -----------------------------------------------------------------------------
 * Function prototypes
 * -----------------------------------------------------------------------------*/

/*
 * filter_init - Initialize the filter engine from a log source config.
 *
 * Compiles all failregex patterns, replacing <HOST> with the IPv4/IPv6
 * capture group pattern. Initializes the hit counter hash table.
 *
 * Parameters:
 *   engine - Pointer to a FilterEngine to initialize
 *   src    - Pointer to the ConfigLogSource for this log source
 *
 * Returns:
 *   0 on success
 *  -1 on error (regex compile failure)
 */
int filter_init(FilterEngine *engine, const ConfigLogSource *src);

/*
 * filter_free - Free all resources used by a FilterEngine.
 *
 * Frees compiled regex patterns and all hit counter hash table entries.
 *
 * Parameters:
 *   engine - Pointer to a FilterEngine to free
 */
void filter_free(FilterEngine *engine);

/*
 * filter_process_line - Process a single log line through the filter engine.
 *
 * Tests the line against all compiled failregex patterns. If a match is
 * found, extracts the IP address, checks it against the ignore list, and
 * increments its hit counter. If the hit counter reaches maxretry, sets
 * ban_triggered in the result.
 *
 * Parameters:
 *   engine  - Pointer to an initialized FilterEngine
 *   ignore  - Pointer to an initialized IgnoreList
 *   line    - Log line string to process
 *   result  - Pointer to a FilterResult to populate
 *
 * Returns:
 *   0 on success (result populated)
 *  -1 on error
 */
int filter_process_line(FilterEngine *engine, const IgnoreList *ignore,
                        const char *line, FilterResult *result);

/*
 * filter_mark_banned - Mark an IP as banned in the hit counter table.
 *
 * Called after an IP has been successfully added to the Firewalla target
 * list. Prevents the IP from being queued for banning again.
 *
 * Parameters:
 *   engine - Pointer to an initialized FilterEngine
 *   ip     - IP address string to mark as banned
 */
void filter_mark_banned(FilterEngine *engine, const char *ip);

/*
 * filter_mark_banned_bulk - Mark multiple IPs as banned at startup.
 *
 * Called during startup reconciliation to mark all IPs already in the
 * Firewalla target list as banned so they are not re-queued.
 *
 * Parameters:
 *   engine - Pointer to an initialized FilterEngine
 *   ips    - Array of IP address strings
 *   count  - Number of IPs in the array
 */
void filter_mark_banned_bulk(FilterEngine *engine, const char **ips, int count);

/*
 * filter_get_pending - Get a list of IPs approaching the ban threshold.
 *
 * Returns all IPs that have at least one hit but have not yet reached
 * maxretry and have not been banned. Used by fwallascan2ban-client pending.
 *
 * Parameters:
 *   engine  - Pointer to an initialized FilterEngine
 *   pending - Array of PendingIP structs to populate
 *   max     - Maximum number of entries to return
 *
 * Returns:
 *   Number of pending IPs found (0 if none)
 */
int filter_get_pending(const FilterEngine *engine, PendingIP *pending, int max);

/*
 * filter_dump - Print filter engine state to stdout for debugging.
 *
 * Parameters:
 *   engine - Pointer to an initialized FilterEngine
 */
void filter_dump(const FilterEngine *engine);

#endif /* FILTER_H */