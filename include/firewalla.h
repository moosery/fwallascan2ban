#ifndef FIREWALLA_H
#define FIREWALLA_H

/* =============================================================================
 * firewalla.h
 * Firewalla MSP API client for fwallascan2ban
 *
 * Provides all communication with the Firewalla MSP REST API via libcurl.
 * Handles authentication, target list management, rule management, and
 * the startup reconciliation process.
 *
 * API base URL: https://{msp_domain}/v2/
 *
 * Endpoints used:
 *   GET    /v2/boxes                          - Resolve box name to GID
 *   GET    /v2/devices                        - Resolve scope names to IDs
 *   GET    /v2/target-lists                   - List all target lists
 *   GET    /v2/target-lists/{id}              - Get a specific target list
 *   POST   /v2/target-lists                   - Create a new target list
 *   PATCH  /v2/target-lists/{id}              - Update a target list
 *   GET    /v2/rules                          - List all rules
 *   POST   /v2/rules                          - Create a new rule
 *
 * All API calls are synchronous. libcurl handles TLS/HTTPS transparently.
 * ============================================================================= */

#include <stdbool.h>
#include "config.h"

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define FW_MAX_ID_LEN           64      /* Maximum length of a UUID/ID string   */
#define FW_MAX_NAME_LEN         256     /* Maximum length of a name string      */
#define FW_MAX_IP_LEN           64      /* Maximum length of an IP string       */
#define FW_MAX_IPS_PER_LIST     2000    /* Maximum IPs we support per list      */
#define FW_MAX_TARGET_LISTS     32      /* Maximum number of target lists       */
#define FW_MAX_RULES            64      /* Maximum number of rules              */
#define FW_MAX_INDIVIDUAL_RULES 256     /* Max individual Firewalla IP rules    */
#define FW_API_TIMEOUT_SECS     30      /* libcurl request timeout              */
#define FW_RETRY_MAX            3       /* Total attempts (1 initial + 2 retries) */
#define FW_RETRY_DELAY_SECS     5       /* Base retry delay; multiplied by attempt# */
#define FW_TARGET_LIST_PREFIX   "-"     /* Separator for numbered overflow lists*/

/* -----------------------------------------------------------------------------
 * Structs
 * ----------------------------------------------------------------------------- */

/* A single IP entry in a target list */
typedef struct {
    char    ip[FW_MAX_IP_LEN];          /* IP address string                    */
} FwIP;

/* A Firewalla MSP target list */
typedef struct {
    char    id[FW_MAX_ID_LEN];          /* Target list ID (TL-xxxx-...)         */
    char    name[FW_MAX_NAME_LEN];      /* Target list name                     */
    char    category[FW_MAX_NAME_LEN];  /* Category (malware, etc.)             */
    char    notes[CONFIG_MAX_VALUE];    /* Notes                                */
    FwIP    ips[FW_MAX_IPS_PER_LIST];   /* IP entries                           */
    int     ip_count;                   /* Number of IPs in the list            */
    int     number;                     /* Sequence number (1, 2, 3...)         */
} FwTargetList;

/* A Firewalla MSP block rule */
typedef struct {
    char    id[FW_MAX_ID_LEN];          /* Rule ID                              */
    char    name[FW_MAX_NAME_LEN];      /* Rule name                            */
    char    action[FW_MAX_NAME_LEN];    /* block or allow                       */
    char    direction[FW_MAX_NAME_LEN]; /* bidirection, inbound, outbound       */
    char    notes[CONFIG_MAX_VALUE];    /* Rule notes                           */
    char    target_list_id[FW_MAX_ID_LEN]; /* Associated target list ID        */
    char    scope_type[FW_MAX_NAME_LEN];   /* none, network, device            */
    char    scope_value[FW_MAX_ID_LEN];    /* Resolved scope ID                */
    bool    active;                     /* true if rule is active               */
} FwRule;

/* A managed target list + rule pair */
typedef struct {
    FwTargetList    list;               /* The target list                      */
    FwRule          rule;               /* The associated block rule            */
    bool            has_rule;           /* true if a rule exists for this list  */
    bool            is_full;            /* true if list is at max_targets       */
} FwManagedList;

/* The complete Firewalla client state */
typedef struct {
    char            msp_domain[CONFIG_MAX_VALUE];   /* MSP domain               */
    char            msp_token[CONFIG_MAX_VALUE];    /* MSP API token            */
    char            box_gid[FW_MAX_ID_LEN];         /* Resolved box GID         */
    char            scope_id[FW_MAX_ID_LEN];        /* Resolved scope ID        */
    char            scope_type[FW_MAX_NAME_LEN];    /* none, network, device    */
    FwManagedList   lists[FW_MAX_TARGET_LISTS];     /* Managed list+rule pairs  */
    int             list_count;                     /* Number of managed lists  */
    int             total_ips;                      /* Total IPs across lists   */
    void           *curl_handle;                    /* libcurl easy handle      */
    char            individual_rule_ips[FW_MAX_INDIVIDUAL_RULES][FW_MAX_IP_LEN];
    int             individual_rule_ip_count;       /* IPs blocked by FW rules  */
} FwClient;

/* Reconciliation report - returned after reconcile() */
typedef struct {
    int     lists_found;            /* Number of matching target lists found    */
    int     total_ips_found;        /* Total IPs found across all lists         */
    int     duplicates_found;       /* Number of duplicate IPs found            */
    int     duplicates_action;      /* Number of duplicates acted on            */
    int     in_fw_not_db;           /* IPs in Firewalla but not in db           */
    int     in_fw_not_db_action;    /* Number acted on                          */
    int     in_db_not_fw;           /* IPs in db but not in Firewalla           */
    int     in_db_not_fw_action;    /* Number acted on                          */
    int     missing_rules;          /* Rules missing for target lists           */
    int     missing_rules_created;  /* Missing rules created                    */
    int     lists_consolidated;     /* Number of lists consolidated             */
    int     fw_rule_found;          /* IPs covered by Firewalla individual rules*/
    int     fw_rule_removed;        /* IPs removed from our lists (FW owns them)*/
    int     errors;                 /* Number of errors encountered             */
} FwReconcileReport;

/* Result of a ban operation */
typedef struct {
    bool    success;                /* true if ban succeeded                    */
    bool    already_banned;         /* true if IP was already in a list         */
    bool    placeholder_removed;    /* true if placeholder was removed          */
    bool    new_list_created;       /* true if an overflow list was created     */
    bool    new_rule_created;       /* true if a new rule was created           */
    char    list_id[FW_MAX_ID_LEN]; /* ID of the list the IP was added to      */
    char    list_name[FW_MAX_NAME_LEN]; /* Name of the list                    */
    char    error_msg[256];         /* Error message if success is false        */
} FwBanResult;

/* Result of an unban operation */
typedef struct {
    bool    success;                /* true if unban succeeded                  */
    bool    not_found;              /* true if IP was not found in any list     */
    bool    placeholder_added;      /* true if placeholder was added            */
    bool    list_consolidated;      /* true if consolidation ran                */
    char    list_id[FW_MAX_ID_LEN]; /* ID of the list the IP was removed from  */
    char    list_name[FW_MAX_NAME_LEN]; /* Name of the list                    */
    char    error_msg[256];         /* Error message if success is false        */
} FwUnbanResult;

/* -----------------------------------------------------------------------------
 * Function prototypes
 * ----------------------------------------------------------------------------- */

/*
 * fw_init - Initialize the Firewalla API client.
 *
 * Initializes libcurl, sets up authentication headers, and resolves the
 * box GID from the configured box_name via GET /v2/boxes. Optionally
 * resolves the scope ID if rule_scope_type is configured.
 *
 * Parameters:
 *   client - Pointer to a FwClient to initialize
 *   config - Pointer to a loaded Config struct
 *
 * Returns:
 *   0 on success
 *  -1 on error (curl init failure, box not found, scope not found)
 */
int fw_init(FwClient *client, const Config *config);

/*
 * fw_free - Free all resources used by a FwClient.
 *
 * Cleans up libcurl handle and any allocated memory.
 *
 * Parameters:
 *   client - Pointer to a FwClient to free
 */
void fw_free(FwClient *client);

/*
 * fw_reconcile - Perform the full startup reconciliation process.
 *
 * Fetches all target lists and rules from Firewalla, compares them with
 * the local banned.db, and resolves discrepancies according to the
 * reconciliation config options. Populates client->lists with the
 * current managed list inventory.
 *
 * Steps:
 *   1. Fetch all target lists matching the base name pattern
 *   2. Build master deduped IP set across all lists
 *   3. Handle duplicates per on_duplicate_ip config
 *   4. Compare with local db, handle discrepancies per config
 *   5. Verify block rules exist for each list, create if missing
 *   6. Consolidate lists if space available per on_list_consolidation
 *   7. Populate report with summary statistics
 *
 * Parameters:
 *   client  - Pointer to an initialized FwClient
 *   config  - Pointer to a loaded Config struct
 *   db_ips  - Array of IP strings from local banned.db
 *   db_count - Number of IPs in db_ips
 *   report  - Pointer to a FwReconcileReport to populate
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int fw_reconcile(FwClient *client, const Config *config,
                 const char **db_ips, int db_count,
                 FwReconcileReport *report);

/*
 * fw_ban_ip - Add an IP address to the current active target list.
 *
 * Finds the target list with available capacity, adds the IP, and
 * PATCHes the list back to Firewalla. If the placeholder IP is present
 * it is removed. If all lists are full, creates a new overflow list
 * and corresponding block rule.
 *
 * Parameters:
 *   client - Pointer to an initialized FwClient
 *   config - Pointer to a loaded Config struct
 *   ip     - IP address string to ban
 *   result - Pointer to a FwBanResult to populate
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int fw_ban_ip(FwClient *client, const Config *config,
              const char *ip, FwBanResult *result);

/*
 * fw_unban_ip - Remove an IP address from whichever target list it is in.
 *
 * Searches all managed target lists for the IP, removes it, and PATCHes
 * the list back to Firewalla. If the list would become empty, inserts the
 * placeholder IP. Triggers consolidation if configured.
 *
 * Parameters:
 *   client - Pointer to an initialized FwClient
 *   config - Pointer to a loaded Config struct
 *   ip     - IP address string to unban
 *   result - Pointer to a FwUnbanResult to populate
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int fw_unban_ip(FwClient *client, const Config *config,
                const char *ip, FwUnbanResult *result);

/*
 * fw_ip_is_banned - Check whether an IP is in any managed target list.
 *
 * Parameters:
 *   client - Pointer to an initialized FwClient
 *   ip     - IP address string to check
 *
 * Returns:
 *   true  if the IP is found in any managed target list
 *   false if not found
 */
bool fw_ip_is_banned(const FwClient *client, const char *ip);

/*
 * fw_get_all_banned_ips - Get a flat list of all banned IPs across all
 * managed target lists, excluding the placeholder IP.
 *
 * Parameters:
 *   client    - Pointer to an initialized FwClient
 *   ips       - Array of FwIP structs to populate
 *   max       - Maximum number of entries to return
 *   list_ids  - Parallel array of list ID strings (which list each IP is in)
 *
 * Returns:
 *   Number of IPs returned
 */
int fw_get_all_banned_ips(const FwClient *client, FwIP *ips, int max,
                          char list_ids[][FW_MAX_ID_LEN]);

/*
 * fw_create_target_list - Create a new target list on Firewalla.
 *
 * Used internally by fw_reconcile() and fw_ban_ip() when overflow is needed.
 *
 * Parameters:
 *   client   - Pointer to an initialized FwClient
 *   config   - Pointer to a loaded Config struct
 *   number   - Sequence number for the new list (1 = base name, 2+ = suffix)
 *   out_list - Pointer to an FwTargetList to populate with the created list
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int fw_create_target_list(FwClient *client, const Config *config,
                          int number, FwTargetList *out_list);

/*
 * fw_create_rule - Create a new block rule on Firewalla for a target list.
 *
 * Used internally by fw_reconcile() and fw_ban_ip() when a new list is created.
 *
 * Parameters:
 *   client    - Pointer to an initialized FwClient
 *   config    - Pointer to a loaded Config struct
 *   list      - Pointer to the target list to create a rule for
 *   number    - Sequence number for the rule name
 *   out_rule  - Pointer to an FwRule to populate with the created rule
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int fw_create_rule(FwClient *client, const Config *config,
                   const FwTargetList *list, int number, FwRule *out_rule);

/*
 * fw_dump - Print the current FwClient state to stdout for debugging.
 *
 * Parameters:
 *   client - Pointer to an initialized FwClient
 */
void fw_dump(const FwClient *client);

#endif /* FIREWALLA_H */