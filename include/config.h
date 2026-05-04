#ifndef CONFIG_H
#define CONFIG_H

/* =============================================================================
 * config.h
 * Configuration file parser for fwallascan2ban
 *
 * Parses the fwallascan2ban.conf INI-style configuration file and populates
 * a Config struct that is used throughout the program.
 *
 * Supports:
 *   - INI-style sections [SectionName]
 *   - Key/value pairs separated by =
 *   - Comments beginning with #
 *   - Multi-line values indented with spaces or tabs (failregex, ignoreregex)
 *   - Environment variable substitution via ${VAR_NAME} syntax
 * ============================================================================= */

#include <stdbool.h>

/* ----------------------------------------------------------------------------- 
 * Constants
 * ----------------------------------------------------------------------------- */

#define CONFIG_MAX_LINE         4096    /* Maximum length of a config file line  */
#define CONFIG_MAX_VALUE        4096    /* Maximum length of a config value       */
#define CONFIG_MAX_PATH         1024    /* Maximum length of a file path          */
#define CONFIG_MAX_NAME         256     /* Maximum length of a name field         */
#define CONFIG_MAX_PATTERNS     64      /* Maximum number of failregex patterns   */
#define CONFIG_MAX_IGNORE       64      /* Maximum number of ignoreregex entries  */
#define CONFIG_MAX_LOG_SOURCES  8       /* Maximum number of [Log:name] sources   */

/* Default values */
#define CONFIG_DEFAULT_MAXRETRY             3
#define CONFIG_DEFAULT_LOG_SCAN_INTERVAL    60
#define CONFIG_DEFAULT_MAX_TARGETS          1000
#define CONFIG_DEFAULT_RECONCILE_INTERVAL   3600
#define CONFIG_DEFAULT_PLACEHOLDER_IP       "192.0.2.1"
#define CONFIG_DEFAULT_RULE_ACTION          "block"
#define CONFIG_DEFAULT_RULE_DIRECTION       "bidirection"
#define CONFIG_DEFAULT_ON_MISSING           "create"
#define CONFIG_DEFAULT_ON_DUPLICATE         "remove"
#define CONFIG_DEFAULT_ON_FW_NOT_DB         "add"
#define CONFIG_DEFAULT_ON_DB_NOT_FW         "add"
#define CONFIG_DEFAULT_ON_MISSING_RULE      "create"
#define CONFIG_DEFAULT_ON_CONSOLIDATION     "consolidate"

/* ----------------------------------------------------------------------------- 
 * Enumerations
 * ----------------------------------------------------------------------------- */

/* What to do when target list is missing */
typedef enum {
    ON_MISSING_CREATE,
    ON_MISSING_ERROR
} OnMissing;

/* What to do with duplicate IPs across target lists */
typedef enum {
    ON_DUPLICATE_REMOVE,
    ON_DUPLICATE_KEEP,
    ON_DUPLICATE_ERROR
} OnDuplicate;

/* What to do when IP is in Firewalla but not in local db */
typedef enum {
    ON_FW_NOT_DB_ADD,
    ON_FW_NOT_DB_REMOVE,
    ON_FW_NOT_DB_ERROR
} OnFwNotDb;

/* What to do when IP is in local db but not in Firewalla */
typedef enum {
    ON_DB_NOT_FW_ADD,
    ON_DB_NOT_FW_REMOVE,
    ON_DB_NOT_FW_ERROR
} OnDbNotFw;

/* What to do when a target list has no block rule */
typedef enum {
    ON_MISSING_RULE_CREATE,
    ON_MISSING_RULE_ERROR
} OnMissingRule;

/* What to do when consolidation is possible */
typedef enum {
    ON_CONSOLIDATION_CONSOLIDATE,
    ON_CONSOLIDATION_IGNORE,
    ON_CONSOLIDATION_ERROR
} OnConsolidation;

/* Rule direction */
typedef enum {
    RULE_DIRECTION_BIDIRECTION,
    RULE_DIRECTION_INBOUND,
    RULE_DIRECTION_OUTBOUND
} RuleDirection;

/* Rule scope type */
typedef enum {
    RULE_SCOPE_NONE,        /* No scope - applies globally */
    RULE_SCOPE_NETWORK,     /* Scoped to a specific LAN    */
    RULE_SCOPE_DEVICE       /* Scoped to a specific device */
} RuleScopeType;

/* ----------------------------------------------------------------------------- 
 * Config structs
 * ----------------------------------------------------------------------------- */

/* [MSP] section */
typedef struct {
    char msp_domain[CONFIG_MAX_VALUE];  /* Firewalla MSP domain            */
    char msp_token[CONFIG_MAX_VALUE];   /* Firewalla MSP API token         */
    char box_name[CONFIG_MAX_NAME];     /* Firewalla box friendly name     */
} ConfigMSP;

/* [TargetList] section */
typedef struct {
    char        target_list_name[CONFIG_MAX_NAME];      /* Base name of target list     */
    char        target_list_category[CONFIG_MAX_NAME];  /* Category (malware, etc.)     */
    char        target_list_notes[CONFIG_MAX_VALUE];    /* Notes for new lists          */
    OnMissing   target_list_on_missing;                 /* Behavior when list missing   */
    int         max_targets;                            /* Max IPs per target list      */
    char        placeholder_ip[64];                     /* Placeholder IP address       */
} ConfigTargetList;

/* [Rule] section */
typedef struct {
    char            rule_name[CONFIG_MAX_NAME];     /* Base name for block rules        */
    char            rule_action[CONFIG_MAX_NAME];   /* block or allow                   */
    RuleDirection   rule_direction;                 /* bidirection, inbound, outbound   */
    char            rule_notes[CONFIG_MAX_VALUE];   /* Notes for new rules              */
    bool            rule_auto_create;               /* Auto-create rules                */
    RuleScopeType   rule_scope_type;                /* none, network, device            */
    char            rule_scope_value[CONFIG_MAX_NAME]; /* Scope name to resolve         */
} ConfigRule;

/* [Monitor] section */
typedef struct {
    char    log_pattern[CONFIG_MAX_PATH];   /* Log file path with strftime codes    */
    int     maxretry;                       /* Hit threshold before banning         */
    int     log_scan_interval;             /* Seconds between directory scans      */
} ConfigMonitor;

/* [Reconciliation] section */
typedef struct {
    int                 reconcile_interval;         /* Seconds between reconciliations  */
    OnDuplicate         on_duplicate_ip;            /* Duplicate IP behavior            */
    OnFwNotDb           on_ip_in_firewalla_not_db;  /* In FW not db behavior            */
    OnDbNotFw           on_ip_in_db_not_firewalla;  /* In db not FW behavior            */
    OnMissingRule       on_missing_rule;            /* Missing rule behavior            */
    OnConsolidation     on_list_consolidation;      /* Consolidation behavior           */
} ConfigReconciliation;

/* [Filters] section */
typedef struct {
    char    failregex[CONFIG_MAX_PATTERNS][CONFIG_MAX_VALUE];   /* Fail patterns        */
    int     failregex_count;                                    /* Number of patterns   */
    char    ignoreregex[CONFIG_MAX_IGNORE][64];                 /* Ignore entries       */
    int     ignoreregex_count;                                  /* Number of entries    */
} ConfigFilters;

/* [Log:name] section — one per monitored log source */
typedef struct {
    char    name[32];                                           /* Source identifier    */
    char    log_pattern[CONFIG_MAX_PATH];                       /* Log path (strftime)  */
    int     maxretry;                                           /* Ban threshold        */
    int     log_scan_interval;                                  /* Dir scan interval    */
    char    failregex[CONFIG_MAX_PATTERNS][CONFIG_MAX_VALUE];   /* Fail patterns        */
    int     failregex_count;                                    /* Number of patterns   */
} ConfigLogSource;

/* Master config struct - holds all sections */
typedef struct {
    ConfigMSP               msp;
    ConfigTargetList        target_list;
    ConfigRule              rule;
    ConfigMonitor           monitor;        /* Legacy — kept for backward compat parsing */
    ConfigReconciliation    reconciliation;
    ConfigFilters           filters;        /* Legacy — kept for backward compat parsing */
    ConfigLogSource         log_sources[CONFIG_MAX_LOG_SOURCES]; /* Active log sources */
    int                     log_source_count;
    bool                    using_legacy_config; /* true if synthesized from [Monitor]+[Filters] */
    char                    config_path[CONFIG_MAX_PATH]; /* Path to loaded config file */
} Config;

/* ----------------------------------------------------------------------------- 
 * Function prototypes
 * ----------------------------------------------------------------------------- */

/*
 * config_load - Parse a config file and populate a Config struct.
 *
 * Parameters:
 *   path   - Path to the config file
 *   config - Pointer to a Config struct to populate
 *
 * Returns:
 *   0 on success
 *  -1 on error (file not found, parse error, missing required fields)
 *
 * Notes:
 *   - Expands ${ENV_VAR} references using getenv()
 *   - Logs errors to stderr
 *   - Sets defaults for optional fields
 */
int config_load(const char *path, Config *config);

/*
 * config_free - Free any dynamically allocated config resources.
 *
 * Parameters:
 *   config - Pointer to a Config struct to free
 *
 * Notes:
 *   Currently all config fields are fixed-size arrays so this is a no-op,
 *   but provided for future extensibility.
 */
void config_free(Config *config);

/*
 * config_dump - Print the loaded config to stdout for debugging.
 *
 * Parameters:
 *   config - Pointer to a populated Config struct
 */
void config_dump(const Config *config);

/*
 * config_validate - Validate a loaded config for required fields and
 * logical consistency.
 *
 * Parameters:
 *   config - Pointer to a populated Config struct
 *
 * Returns:
 *   0 if valid
 *  -1 if invalid (logs specific errors to stderr)
 */
int config_validate(const Config *config);

#endif /* CONFIG_H */
