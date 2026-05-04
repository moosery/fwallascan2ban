/* =============================================================================
 * config.c
 * Configuration file parser for fwallascan2ban
 *
 * Parses the fwallascan2ban.conf INI-style configuration file and populates
 * a Config struct. See config.h for full documentation.
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"

/* -----------------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------------- */

/* Current section being parsed */
typedef enum {
    SECTION_NONE,
    SECTION_MSP,
    SECTION_TARGETLIST,
    SECTION_RULE,
    SECTION_MONITOR,
    SECTION_RECONCILIATION,
    SECTION_FILTERS,
    SECTION_LOG         /* [Log:name] — per-source log config */
} Section;

/*
 * trim - Remove leading and trailing whitespace from a string in place.
 * Returns pointer to the trimmed string (points into the original buffer).
 */
static char *trim(char *s)
{
    /* Trim leading whitespace */
    while (isspace((unsigned char)*s))
        s++;

    if (*s == '\0')
        return s;

    /* Trim trailing whitespace */
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    *(end + 1) = '\0';

    return s;
}

/*
 * expand_env - Expand ${VAR_NAME} references in a string.
 *
 * Scans src for ${...} patterns, looks up each variable via getenv(),
 * and writes the expanded result into dst (up to dst_len bytes).
 *
 * Returns 0 on success, -1 if dst buffer would overflow or var not found
 * (missing vars are replaced with empty string, not an error).
 */
static int expand_env(const char *src, char *dst, size_t dst_len)
{
    size_t  di = 0;     /* dst index     */
    size_t  si = 0;     /* src index     */
    size_t  src_len = strlen(src);

    while (si < src_len) {
        /* Look for ${ */
        if (src[si] == '$' && src[si + 1] == '{') {
            si += 2; /* skip ${ */

            /* Find closing } */
            size_t var_start = si;
            while (si < src_len && src[si] != '}')
                si++;

            if (si >= src_len) {
                fprintf(stderr, "config: unterminated ${} in value\n");
                return -1;
            }

            /* Extract variable name */
            char var_name[256];
            size_t var_len = si - var_start;
            if (var_len >= sizeof(var_name)) {
                fprintf(stderr, "config: variable name too long\n");
                return -1;
            }
            strncpy(var_name, src + var_start, var_len);
            var_name[var_len] = '\0';
            si++; /* skip } */

            /* Look up the environment variable */
            const char *val = getenv(var_name);
            if (val == NULL) {
                fprintf(stderr, "config: warning: environment variable "
                        "${%s} is not set\n", var_name);
                val = "";
            }

            /* Copy value into dst */
            size_t val_len = strlen(val);
            if (di + val_len >= dst_len) {
                fprintf(stderr, "config: expanded value too long\n");
                return -1;
            }
            memcpy(dst + di, val, val_len);
            di += val_len;

        } else {
            /* Regular character - copy directly */
            if (di + 1 >= dst_len) {
                fprintf(stderr, "config: value too long\n");
                return -1;
            }
            dst[di++] = src[si++];
        }
    }

    dst[di] = '\0';
    return 0;
}

/*
 * parse_section - Parse a [SectionName] line and return the Section enum.
 */
static Section parse_section(const char *line)
{
    if (strcasecmp(line, "[MSP]") == 0)             return SECTION_MSP;
    if (strcasecmp(line, "[TargetList]") == 0)      return SECTION_TARGETLIST;
    if (strcasecmp(line, "[Rule]") == 0)            return SECTION_RULE;
    if (strcasecmp(line, "[Monitor]") == 0)         return SECTION_MONITOR;
    if (strcasecmp(line, "[Reconciliation]") == 0)  return SECTION_RECONCILIATION;
    if (strcasecmp(line, "[Filters]") == 0)         return SECTION_FILTERS;
    fprintf(stderr, "config: unknown section: %s\n", line);
    return SECTION_NONE;
}

/*
 * parse_on_missing - Parse target_list_on_missing value.
 */
static OnMissing parse_on_missing(const char *val)
{
    if (strcasecmp(val, "create") == 0) return ON_MISSING_CREATE;
    if (strcasecmp(val, "error") == 0)  return ON_MISSING_ERROR;
    fprintf(stderr, "config: invalid target_list_on_missing value: %s "
            "(using 'create')\n", val);
    return ON_MISSING_CREATE;
}

/*
 * parse_on_duplicate - Parse on_duplicate_ip value.
 */
static OnDuplicate parse_on_duplicate(const char *val)
{
    if (strcasecmp(val, "remove") == 0) return ON_DUPLICATE_REMOVE;
    if (strcasecmp(val, "keep") == 0)   return ON_DUPLICATE_KEEP;
    if (strcasecmp(val, "error") == 0)  return ON_DUPLICATE_ERROR;
    fprintf(stderr, "config: invalid on_duplicate_ip value: %s "
            "(using 'remove')\n", val);
    return ON_DUPLICATE_REMOVE;
}

/*
 * parse_on_fw_not_db - Parse on_ip_in_firewalla_not_db value.
 */
static OnFwNotDb parse_on_fw_not_db(const char *val)
{
    if (strcasecmp(val, "add") == 0)    return ON_FW_NOT_DB_ADD;
    if (strcasecmp(val, "remove") == 0) return ON_FW_NOT_DB_REMOVE;
    if (strcasecmp(val, "error") == 0)  return ON_FW_NOT_DB_ERROR;
    fprintf(stderr, "config: invalid on_ip_in_firewalla_not_db value: %s "
            "(using 'add')\n", val);
    return ON_FW_NOT_DB_ADD;
}

/*
 * parse_on_db_not_fw - Parse on_ip_in_db_not_firewalla value.
 */
static OnDbNotFw parse_on_db_not_fw(const char *val)
{
    if (strcasecmp(val, "add") == 0)    return ON_DB_NOT_FW_ADD;
    if (strcasecmp(val, "remove") == 0) return ON_DB_NOT_FW_REMOVE;
    if (strcasecmp(val, "error") == 0)  return ON_DB_NOT_FW_ERROR;
    fprintf(stderr, "config: invalid on_ip_in_db_not_firewalla value: %s "
            "(using 'add')\n", val);
    return ON_DB_NOT_FW_ADD;
}

/*
 * parse_on_missing_rule - Parse on_missing_rule value.
 */
static OnMissingRule parse_on_missing_rule(const char *val)
{
    if (strcasecmp(val, "create") == 0) return ON_MISSING_RULE_CREATE;
    if (strcasecmp(val, "error") == 0)  return ON_MISSING_RULE_ERROR;
    fprintf(stderr, "config: invalid on_missing_rule value: %s "
            "(using 'create')\n", val);
    return ON_MISSING_RULE_CREATE;
}

/*
 * parse_on_consolidation - Parse on_list_consolidation value.
 */
static OnConsolidation parse_on_consolidation(const char *val)
{
    if (strcasecmp(val, "consolidate") == 0)    return ON_CONSOLIDATION_CONSOLIDATE;
    if (strcasecmp(val, "ignore") == 0)         return ON_CONSOLIDATION_IGNORE;
    if (strcasecmp(val, "error") == 0)          return ON_CONSOLIDATION_ERROR;
    fprintf(stderr, "config: invalid on_list_consolidation value: %s "
            "(using 'consolidate')\n", val);
    return ON_CONSOLIDATION_CONSOLIDATE;
}

/*
 * parse_rule_direction - Parse rule_direction value.
 */
static RuleDirection parse_rule_direction(const char *val)
{
    if (strcasecmp(val, "bidirection") == 0)    return RULE_DIRECTION_BIDIRECTION;
    if (strcasecmp(val, "inbound") == 0)        return RULE_DIRECTION_INBOUND;
    if (strcasecmp(val, "outbound") == 0)       return RULE_DIRECTION_OUTBOUND;
    fprintf(stderr, "config: invalid rule_direction value: %s "
            "(using 'bidirection')\n", val);
    return RULE_DIRECTION_BIDIRECTION;
}

/*
 * parse_rule_scope_type - Parse rule_scope_type value.
 */
static RuleScopeType parse_rule_scope_type(const char *val)
{
    if (strcasecmp(val, "network") == 0)    return RULE_SCOPE_NETWORK;
    if (strcasecmp(val, "device") == 0)     return RULE_SCOPE_DEVICE;
    if (strcasecmp(val, "none") == 0)       return RULE_SCOPE_NONE;
    fprintf(stderr, "config: invalid rule_scope_type value: %s "
            "(using 'none')\n", val);
    return RULE_SCOPE_NONE;
}

/*
 * set_defaults - Set default values for all optional config fields.
 */
static void set_defaults(Config *config)
{
    /* MSP - no defaults, all required */

    /* TargetList */
    strncpy(config->target_list.target_list_category, "malware",
            CONFIG_MAX_NAME - 1);
    strncpy(config->target_list.target_list_notes,
            "Blocked by fwallascan2ban", CONFIG_MAX_VALUE - 1);
    config->target_list.target_list_on_missing  = ON_MISSING_CREATE;
    config->target_list.max_targets             = CONFIG_DEFAULT_MAX_TARGETS;
    strncpy(config->target_list.placeholder_ip,
            CONFIG_DEFAULT_PLACEHOLDER_IP, 63);

    /* Rule */
    strncpy(config->rule.rule_action, CONFIG_DEFAULT_RULE_ACTION,
            CONFIG_MAX_NAME - 1);
    config->rule.rule_direction     = RULE_DIRECTION_BIDIRECTION;
    strncpy(config->rule.rule_notes, "Blocked by fwallascan2ban",
            CONFIG_MAX_VALUE - 1);
    config->rule.rule_auto_create   = true;
    config->rule.rule_scope_type    = RULE_SCOPE_NONE;

    /* Monitor */
    config->monitor.maxretry            = CONFIG_DEFAULT_MAXRETRY;
    config->monitor.log_scan_interval   = CONFIG_DEFAULT_LOG_SCAN_INTERVAL;

    /* Reconciliation */
    config->reconciliation.reconcile_interval       = CONFIG_DEFAULT_RECONCILE_INTERVAL;
    config->reconciliation.on_duplicate_ip          = ON_DUPLICATE_REMOVE;
    config->reconciliation.on_ip_in_firewalla_not_db = ON_FW_NOT_DB_ADD;
    config->reconciliation.on_ip_in_db_not_firewalla = ON_DB_NOT_FW_ADD;
    config->reconciliation.on_missing_rule          = ON_MISSING_RULE_CREATE;
    config->reconciliation.on_list_consolidation    = ON_CONSOLIDATION_CONSOLIDATE;
}

/*
 * is_continuation - Returns true if the line starts with whitespace,
 * indicating it is a continuation of a multi-line value (failregex etc.)
 */
static bool is_continuation(const char *line)
{
    return (line[0] == ' ' || line[0] == '\t');
}

/*
 * append_pattern - Append a failregex or ignoreregex pattern to the config.
 */
static int append_failregex(Config *config, const char *pattern)
{
    if (config->filters.failregex_count >= CONFIG_MAX_PATTERNS) {
        fprintf(stderr, "config: too many failregex patterns (max %d)\n",
                CONFIG_MAX_PATTERNS);
        return -1;
    }
    strncpy(config->filters.failregex[config->filters.failregex_count],
            pattern, CONFIG_MAX_VALUE - 1);
    config->filters.failregex_count++;
    return 0;
}

static int append_ignoreregex(Config *config, const char *entry)
{
    if (config->filters.ignoreregex_count >= CONFIG_MAX_IGNORE) {
        fprintf(stderr, "config: too many ignoreregex entries (max %d)\n",
                CONFIG_MAX_IGNORE);
        return -1;
    }
    strncpy(config->filters.ignoreregex[config->filters.ignoreregex_count],
            entry, 63);
    config->filters.ignoreregex_count++;
    return 0;
}

/* -----------------------------------------------------------------------------
 * Key/value handlers per section
 * ----------------------------------------------------------------------------- */

static int handle_msp(Config *config, const char *key, const char *val)
{
    if (strcmp(key, "msp_domain") == 0) {
        strncpy(config->msp.msp_domain, val, CONFIG_MAX_VALUE - 1);
    } else if (strcmp(key, "msp_token") == 0) {
        strncpy(config->msp.msp_token, val, CONFIG_MAX_VALUE - 1);
    } else if (strcmp(key, "box_name") == 0) {
        strncpy(config->msp.box_name, val, CONFIG_MAX_NAME - 1);
    } else {
        fprintf(stderr, "config: unknown key in [MSP]: %s\n", key);
    }
    return 0;
}

static int handle_targetlist(Config *config, const char *key, const char *val)
{
    if (strcmp(key, "target_list_name") == 0) {
        strncpy(config->target_list.target_list_name, val, CONFIG_MAX_NAME - 1);
    } else if (strcmp(key, "target_list_category") == 0) {
        strncpy(config->target_list.target_list_category, val, CONFIG_MAX_NAME - 1);
    } else if (strcmp(key, "target_list_notes") == 0) {
        strncpy(config->target_list.target_list_notes, val, CONFIG_MAX_VALUE - 1);
    } else if (strcmp(key, "target_list_on_missing") == 0) {
        config->target_list.target_list_on_missing = parse_on_missing(val);
    } else if (strcmp(key, "max_targets") == 0) {
        config->target_list.max_targets = atoi(val);
        if (config->target_list.max_targets < 1) {
            fprintf(stderr, "config: max_targets must be >= 1 (using 1000)\n");
            config->target_list.max_targets = CONFIG_DEFAULT_MAX_TARGETS;
        }
    } else if (strcmp(key, "placeholder_ip") == 0) {
        strncpy(config->target_list.placeholder_ip, val, 63);
    } else {
        fprintf(stderr, "config: unknown key in [TargetList]: %s\n", key);
    }
    return 0;
}

static int handle_rule(Config *config, const char *key, const char *val)
{
    if (strcmp(key, "rule_name") == 0) {
        strncpy(config->rule.rule_name, val, CONFIG_MAX_NAME - 1);
    } else if (strcmp(key, "rule_action") == 0) {
        strncpy(config->rule.rule_action, val, CONFIG_MAX_NAME - 1);
    } else if (strcmp(key, "rule_direction") == 0) {
        config->rule.rule_direction = parse_rule_direction(val);
    } else if (strcmp(key, "rule_notes") == 0) {
        strncpy(config->rule.rule_notes, val, CONFIG_MAX_VALUE - 1);
    } else if (strcmp(key, "rule_auto_create") == 0) {
        config->rule.rule_auto_create =
            (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
    } else if (strcmp(key, "rule_scope_type") == 0) {
        config->rule.rule_scope_type = parse_rule_scope_type(val);
    } else if (strcmp(key, "rule_scope_value") == 0) {
        strncpy(config->rule.rule_scope_value, val, CONFIG_MAX_NAME - 1);
    } else {
        fprintf(stderr, "config: unknown key in [Rule]: %s\n", key);
    }
    return 0;
}

static int handle_monitor(Config *config, const char *key, const char *val)
{
    if (strcmp(key, "log_pattern") == 0) {
        strncpy(config->monitor.log_pattern, val, CONFIG_MAX_PATH - 1);
    } else if (strcmp(key, "maxretry") == 0) {
        config->monitor.maxretry = atoi(val);
        if (config->monitor.maxretry < 1) {
            fprintf(stderr, "config: maxretry must be >= 1 (using 3)\n");
            config->monitor.maxretry = CONFIG_DEFAULT_MAXRETRY;
        }
    } else if (strcmp(key, "log_scan_interval") == 0) {
        config->monitor.log_scan_interval = atoi(val);
        if (config->monitor.log_scan_interval < 0) {
            fprintf(stderr, "config: log_scan_interval must be >= 0 (using 60)\n");
            config->monitor.log_scan_interval = CONFIG_DEFAULT_LOG_SCAN_INTERVAL;
        }
    } else {
        fprintf(stderr, "config: unknown key in [Monitor]: %s\n", key);
    }
    return 0;
}

static int handle_reconciliation(Config *config, const char *key,
                                 const char *val)
{
    if (strcmp(key, "reconcile_interval") == 0) {
        config->reconciliation.reconcile_interval = atoi(val);
    } else if (strcmp(key, "on_duplicate_ip") == 0) {
        config->reconciliation.on_duplicate_ip = parse_on_duplicate(val);
    } else if (strcmp(key, "on_ip_in_firewalla_not_db") == 0) {
        config->reconciliation.on_ip_in_firewalla_not_db =
            parse_on_fw_not_db(val);
    } else if (strcmp(key, "on_ip_in_db_not_firewalla") == 0) {
        config->reconciliation.on_ip_in_db_not_firewalla =
            parse_on_db_not_fw(val);
    } else if (strcmp(key, "on_missing_rule") == 0) {
        config->reconciliation.on_missing_rule = parse_on_missing_rule(val);
    } else if (strcmp(key, "on_list_consolidation") == 0) {
        config->reconciliation.on_list_consolidation =
            parse_on_consolidation(val);
    } else {
        fprintf(stderr, "config: unknown key in [Reconciliation]: %s\n", key);
    }
    return 0;
}

/*
 * handle_filters - Handle a key in [Filters].
 *
 * For failregex and ignoreregex, the first line after the key= is the
 * first pattern. Subsequent indented lines are continuation patterns
 * handled separately in the main parse loop.
 *
 * last_filter_key is set so the continuation handler knows which list
 * to append to.
 */
static int handle_filters(Config *config, const char *key, const char *val,
                           char *last_filter_key, size_t lk_size)
{
    strncpy(last_filter_key, key, lk_size - 1);

    if (strcmp(key, "failregex") == 0) {
        return append_failregex(config, val);
    } else if (strcmp(key, "ignoreregex") == 0) {
        return append_ignoreregex(config, val);
    } else {
        fprintf(stderr, "config: unknown key in [Filters]: %s\n", key);
    }
    return 0;
}

static int handle_log_source(Config *config, int src_idx, const char *key,
                              const char *val, char *last_filter_key,
                              size_t lk_size)
{
    ConfigLogSource *src = &config->log_sources[src_idx];

    if (strcmp(key, "log_pattern") == 0 || strcmp(key, "path") == 0) {
        strncpy(src->log_pattern, val, CONFIG_MAX_PATH - 1);
    } else if (strcmp(key, "maxretry") == 0) {
        src->maxretry = atoi(val);
        if (src->maxretry < 1) {
            fprintf(stderr, "config: [Log:%s] maxretry must be >= 1 (using 3)\n",
                    src->name);
            src->maxretry = CONFIG_DEFAULT_MAXRETRY;
        }
    } else if (strcmp(key, "log_scan_interval") == 0) {
        src->log_scan_interval = atoi(val);
        if (src->log_scan_interval < 0) {
            fprintf(stderr, "config: [Log:%s] log_scan_interval must be >= 0 "
                    "(using 60)\n", src->name);
            src->log_scan_interval = CONFIG_DEFAULT_LOG_SCAN_INTERVAL;
        }
    } else if (strcmp(key, "failregex") == 0) {
        strncpy(last_filter_key, key, lk_size - 1);
        if (src->failregex_count >= CONFIG_MAX_PATTERNS) {
            fprintf(stderr, "config: [Log:%s] too many failregex patterns "
                    "(max %d)\n", src->name, CONFIG_MAX_PATTERNS);
            return -1;
        }
        strncpy(src->failregex[src->failregex_count], val, CONFIG_MAX_VALUE - 1);
        src->failregex_count++;
    } else {
        fprintf(stderr, "config: unknown key in [Log:%s]: %s\n",
                src->name, key);
    }
    return 0;
}

/* -----------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------------- */

int config_load(const char *path, Config *config)
{
    FILE *fp;
    char  line_buf[CONFIG_MAX_LINE];
    char  expanded[CONFIG_MAX_VALUE];
    int   line_num = 0;
    int   rc = 0;

    /* Zero the config struct and set defaults */
    memset(config, 0, sizeof(Config));
    set_defaults(config);
    strncpy(config->config_path, path, CONFIG_MAX_PATH - 1);

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "config: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    Section current_section      = SECTION_NONE;
    char    last_filter_key[64]  = "";
    int     current_log_src_idx  = -1;

    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        line_num++;

        /* Strip trailing newline */
        size_t len = strlen(line_buf);
        if (len > 0 && line_buf[len - 1] == '\n')
            line_buf[len - 1] = '\0';

        /* Handle multi-line continuation for [Filters] and [Log:name] */
        if ((current_section == SECTION_FILTERS ||
             current_section == SECTION_LOG) &&
            is_continuation(line_buf) &&
            last_filter_key[0] != '\0')
        {
            char *trimmed = trim(line_buf);
            if (*trimmed == '\0' || *trimmed == '#')
                continue;

            if (current_section == SECTION_FILTERS) {
                if (strcmp(last_filter_key, "failregex") == 0) {
                    rc = append_failregex(config, trimmed);
                } else if (strcmp(last_filter_key, "ignoreregex") == 0) {
                    rc = append_ignoreregex(config, trimmed);
                }
            } else { /* SECTION_LOG */
                if (strcmp(last_filter_key, "failregex") == 0 &&
                    current_log_src_idx >= 0)
                {
                    ConfigLogSource *src =
                        &config->log_sources[current_log_src_idx];
                    if (src->failregex_count < CONFIG_MAX_PATTERNS) {
                        strncpy(src->failregex[src->failregex_count],
                                trimmed, CONFIG_MAX_VALUE - 1);
                        src->failregex_count++;
                    }
                }
            }
            if (rc != 0) goto done;
            continue;
        }

        /* Trim the line */
        char *line = trim(line_buf);

        /* Skip empty lines and comments */
        if (*line == '\0' || *line == '#')
            continue;

        /* Section header */
        if (line[0] == '[') {
            last_filter_key[0] = '\0';

            /* Check for [Log:name] before regular sections */
            if (strncasecmp(line, "[Log:", 5) == 0) {
                char *start = line + 5;
                char *end   = strchr(start, ']');
                if (end != NULL && end > start) {
                    int new_idx = config->log_source_count;
                    if (new_idx >= CONFIG_MAX_LOG_SOURCES) {
                        fprintf(stderr, "config: too many [Log:*] sections "
                                "(max %d)\n", CONFIG_MAX_LOG_SOURCES);
                    } else {
                        ConfigLogSource *src = &config->log_sources[new_idx];
                        size_t nlen = (size_t)(end - start);
                        if (nlen >= sizeof(src->name))
                            nlen = sizeof(src->name) - 1;
                        strncpy(src->name, start, nlen);
                        src->name[nlen] = '\0';
                        /* Set per-source defaults */
                        src->maxretry          = CONFIG_DEFAULT_MAXRETRY;
                        src->log_scan_interval = CONFIG_DEFAULT_LOG_SCAN_INTERVAL;
                        config->log_source_count++;
                        current_log_src_idx = new_idx;
                        current_section = SECTION_LOG;
                    }
                } else {
                    fprintf(stderr, "config: malformed section header: %s\n",
                            line);
                    current_section = SECTION_NONE;
                }
                continue;
            }

            current_section     = parse_section(line);
            current_log_src_idx = -1;
            continue;
        }

        /* Key = value pair */
        char *eq = strchr(line, '=');
        if (eq == NULL) {
            fprintf(stderr, "config: line %d: no '=' found: %s\n",
                    line_num, line);
            continue;
        }

        /* Split into key and value */
        *eq = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);

        /* Expand environment variables in value */
        if (expand_env(val, expanded, sizeof(expanded)) != 0) {
            fprintf(stderr, "config: line %d: env expansion failed\n",
                    line_num);
            rc = -1;
            goto done;
        }
        val = expanded;

        /* Skip empty values */
        if (*val == '\0')
            continue;

        /* Dispatch to section handler */
        switch (current_section) {
            case SECTION_MSP:
                rc = handle_msp(config, key, val);
                break;
            case SECTION_TARGETLIST:
                rc = handle_targetlist(config, key, val);
                break;
            case SECTION_RULE:
                rc = handle_rule(config, key, val);
                break;
            case SECTION_MONITOR:
                rc = handle_monitor(config, key, val);
                break;
            case SECTION_RECONCILIATION:
                rc = handle_reconciliation(config, key, val);
                break;
            case SECTION_FILTERS:
                rc = handle_filters(config, key, val,
                                    last_filter_key,
                                    sizeof(last_filter_key));
                break;
            case SECTION_LOG:
                rc = handle_log_source(config, current_log_src_idx, key, val,
                                       last_filter_key, sizeof(last_filter_key));
                break;
            case SECTION_NONE:
                fprintf(stderr, "config: line %d: key outside section: %s\n",
                        line_num, key);
                break;
        }

        if (rc != 0)
            goto done;
    }

    /* Synthesize a single log source from legacy [Monitor]+[Filters] if no
     * [Log:name] sections were found. This ensures backward compatibility. */
    if (rc == 0 && config->log_source_count == 0 &&
        config->monitor.log_pattern[0] != '\0')
    {
        ConfigLogSource *src = &config->log_sources[0];
        strncpy(src->name, "default", sizeof(src->name) - 1);
        strncpy(src->log_pattern, config->monitor.log_pattern,
                CONFIG_MAX_PATH - 1);
        src->maxretry          = config->monitor.maxretry;
        src->log_scan_interval = config->monitor.log_scan_interval;
        src->failregex_count   = config->filters.failregex_count;
        for (int i = 0; i < config->filters.failregex_count; i++)
            strncpy(src->failregex[i], config->filters.failregex[i],
                    CONFIG_MAX_VALUE - 1);
        config->log_source_count   = 1;
        config->using_legacy_config = true;
    }

done:
    fclose(fp);
    return rc;
}

void config_free(Config *config)
{
    /* All fields are fixed-size arrays - nothing to free */
    (void)config;
}

int config_validate(const Config *config)
{
    int rc = 0;

    /* [MSP] - all three fields required */
    if (config->msp.msp_domain[0] == '\0') {
        fprintf(stderr, "config: [MSP] msp_domain is required\n");
        rc = -1;
    }
    if (config->msp.msp_token[0] == '\0') {
        fprintf(stderr, "config: [MSP] msp_token is required\n");
        rc = -1;
    }
    if (config->msp.box_name[0] == '\0') {
        fprintf(stderr, "config: [MSP] box_name is required\n");
        rc = -1;
    }

    /* [TargetList] */
    if (config->target_list.target_list_name[0] == '\0') {
        fprintf(stderr, "config: [TargetList] target_list_name is required\n");
        rc = -1;
    }
    if (config->target_list.placeholder_ip[0] == '\0') {
        fprintf(stderr, "config: [TargetList] placeholder_ip is required\n");
        rc = -1;
    }

    /* [Rule] */
    if (config->rule.rule_name[0] == '\0') {
        fprintf(stderr, "config: [Rule] rule_name is required\n");
        rc = -1;
    }
    if (config->rule.rule_scope_type != RULE_SCOPE_NONE &&
        config->rule.rule_scope_value[0] == '\0') {
        fprintf(stderr, "config: [Rule] rule_scope_value is required "
                "when rule_scope_type is set\n");
        rc = -1;
    }

    /* Log sources (either from [Log:name] sections or synthesized from legacy
     * [Monitor]+[Filters]) */
    if (config->log_source_count == 0) {
        fprintf(stderr, "config: no log sources configured — add [Log:name] "
                "sections or legacy [Monitor]+[Filters] sections\n");
        rc = -1;
    } else {
        for (int i = 0; i < config->log_source_count; i++) {
            const ConfigLogSource *src = &config->log_sources[i];
            if (src->log_pattern[0] == '\0') {
                fprintf(stderr, "config: [Log:%s] log_pattern is required\n",
                        src->name);
                rc = -1;
            }
            if (src->failregex_count == 0) {
                fprintf(stderr, "config: [Log:%s] at least one failregex "
                        "is required\n", src->name);
                rc = -1;
            }
            if (src->maxretry < 1) {
                fprintf(stderr, "config: [Log:%s] maxretry must be >= 1\n",
                        src->name);
                rc = -1;
            }
        }
    }

    return rc;
}

void config_dump(const Config *config)
{
    printf("=== fwallascan2ban configuration ===\n");
    printf("[MSP]\n");
    printf("  msp_domain : %s\n", config->msp.msp_domain);
    printf("  msp_token  : %s\n",
           config->msp.msp_token[0] ? "***set***" : "(not set)");
    printf("  box_name   : %s\n", config->msp.box_name);

    printf("[TargetList]\n");
    printf("  name       : %s\n", config->target_list.target_list_name);
    printf("  category   : %s\n", config->target_list.target_list_category);
    printf("  notes      : %s\n", config->target_list.target_list_notes);
    printf("  on_missing : %s\n",
           config->target_list.target_list_on_missing == ON_MISSING_CREATE
           ? "create" : "error");
    printf("  max_targets: %d\n", config->target_list.max_targets);
    printf("  placeholder: %s\n", config->target_list.placeholder_ip);

    printf("[Rule]\n");
    printf("  name       : %s\n", config->rule.rule_name);
    printf("  action     : %s\n", config->rule.rule_action);
    printf("  direction  : %d\n", config->rule.rule_direction);
    printf("  notes      : %s\n", config->rule.rule_notes);
    printf("  auto_create: %s\n", config->rule.rule_auto_create ? "true" : "false");
    printf("  scope_type : %d\n", config->rule.rule_scope_type);
    printf("  scope_value: %s\n", config->rule.rule_scope_value);

    printf("[Monitor]\n");
    printf("  log_pattern: %s\n", config->monitor.log_pattern);
    printf("  maxretry   : %d\n", config->monitor.maxretry);
    printf("  scan_intvl : %d\n", config->monitor.log_scan_interval);

    printf("[Reconciliation]\n");
    printf("  interval   : %d\n", config->reconciliation.reconcile_interval);
    printf("  on_dup_ip  : %d\n", config->reconciliation.on_duplicate_ip);
    printf("  on_fw_not_db:%d\n", config->reconciliation.on_ip_in_firewalla_not_db);
    printf("  on_db_not_fw:%d\n", config->reconciliation.on_ip_in_db_not_firewalla);
    printf("  on_miss_rule:%d\n", config->reconciliation.on_missing_rule);
    printf("  on_consolid:%d\n",  config->reconciliation.on_list_consolidation);

    printf("[Filters] (legacy)\n");
    printf("  failregex count  : %d\n", config->filters.failregex_count);
    for (int i = 0; i < config->filters.failregex_count; i++)
        printf("    [%d] %s\n", i, config->filters.failregex[i]);
    printf("  ignoreregex count: %d\n", config->filters.ignoreregex_count);
    for (int i = 0; i < config->filters.ignoreregex_count; i++)
        printf("    [%d] %s\n", i, config->filters.ignoreregex[i]);

    printf("Log sources: %d (legacy=%s)\n",
           config->log_source_count,
           config->using_legacy_config ? "yes" : "no");
    for (int i = 0; i < config->log_source_count; i++) {
        const ConfigLogSource *src = &config->log_sources[i];
        printf("  [Log:%s]\n", src->name);
        printf("    log_pattern  : %s\n", src->log_pattern);
        printf("    maxretry     : %d\n", src->maxretry);
        printf("    scan_interval: %d\n", src->log_scan_interval);
        printf("    failregex cnt: %d\n", src->failregex_count);
        for (int j = 0; j < src->failregex_count; j++)
            printf("      [%d] %s\n", j, src->failregex[j]);
    }

    printf("=====================================\n");
}
