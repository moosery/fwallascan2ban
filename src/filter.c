/* =============================================================================
 * filter.c
 * Log line pattern matching and IP hit counter for fwallascan2ban
 *
 * Manages the failregex patterns and per-IP hit counter hash table.
 * See filter.h for full documentation.
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"
#include "ignore.h"

/* -----------------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------------- */

/*
 * expand_host_token - Replace <HOST> in a failregex pattern with the
 * IPv4/IPv6 capture group pattern.
 *
 * Returns 0 on success, -1 if the output buffer is too small or
 * <HOST> is not found.
 */
static int expand_host_token(const char *pattern, char *out, size_t out_len)
{
    const char *host_token    = "<HOST>";
    size_t      token_len     = strlen(host_token);
    const char *host_pattern  = FILTER_HOST_PATTERN;
    size_t      host_pat_len  = strlen(host_pattern);

    const char *pos = strstr(pattern, host_token);
    if (pos == NULL) {
        fprintf(stderr, "filter: pattern missing <HOST> token: %s\n", pattern);
        return -1;
    }

    size_t prefix_len = (size_t)(pos - pattern);
    size_t suffix_len = strlen(pos + token_len);
    size_t total_len  = prefix_len + host_pat_len + suffix_len + 1;

    if (total_len > out_len) {
        fprintf(stderr, "filter: expanded pattern too long\n");
        return -1;
    }

    /* Build: prefix + host_pattern + suffix */
    memcpy(out, pattern, prefix_len);
    memcpy(out + prefix_len, host_pattern, host_pat_len);
    memcpy(out + prefix_len + host_pat_len, pos + token_len, suffix_len);
    out[total_len - 1] = '\0';

    return 0;
}

/*
 * find_host_group - Find which capture group index corresponds to <HOST>.
 *
 * We wrap the host pattern in a capture group and count any capture groups
 * that appear before it in the pattern string. Returns the 1-based group index.
 *
 * Since our patterns are of the form:
 *   ^<HOST> - - \[.*\] "..."
 * The host group is always group 1 in our patterns.
 * We default to 1 for simplicity.
 */
static int find_host_group(const char *pattern)
{
    /* Count opening parentheses before the host pattern to determine
     * which group captures the host. In our failregex patterns the
     * host is always the first capture group. */
    int group = 1;
    const char *host_pat = FILTER_HOST_PATTERN;
    const char *pos = strstr(pattern, host_pat);
    if (pos == NULL)
        return 1;

    /* Count unescaped '(' before the host pattern */
    for (const char *p = pattern; p < pos; p++) {
        if (*p == '\\') {
            p++; /* skip escaped character */
            continue;
        }
        if (*p == '(')
            group++;
    }
    return 1; /* Host is always group 1 in our patterns */
}

/*
 * hash_ip - Simple hash function for IP address strings.
 * Returns an index into the hit table.
 */
static unsigned int hash_ip(const char *ip)
{
    unsigned int hash = 5381;
    int c;
    while ((c = (unsigned char)*ip++) != 0)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash & (FILTER_HIT_TABLE_SIZE - 1);
}

/*
 * hit_find - Find an existing HitEntry for an IP in the hash table.
 * Returns pointer to entry or NULL if not found.
 */
static HitEntry *hit_find(FilterEngine *engine, const char *ip)
{
    unsigned int idx = hash_ip(ip);
    HitEntry *entry = engine->hit_table[idx];
    while (entry != NULL) {
        if (strcmp(entry->ip, ip) == 0)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

/*
 * hit_get_or_create - Find or create a HitEntry for an IP.
 * Returns pointer to entry or NULL on allocation failure.
 */
static HitEntry *hit_get_or_create(FilterEngine *engine, const char *ip)
{
    HitEntry *entry = hit_find(engine, ip);
    if (entry != NULL)
        return entry;

    /* Create new entry */
    entry = calloc(1, sizeof(HitEntry));
    if (entry == NULL) {
        fprintf(stderr, "filter: out of memory allocating hit entry\n");
        return NULL;
    }

    strncpy(entry->ip, ip, FILTER_MAX_IP_LEN - 1);
    entry->hits   = 0;
    entry->banned = false;

    /* Insert at head of chain */
    unsigned int idx = hash_ip(ip);
    entry->next = engine->hit_table[idx];
    engine->hit_table[idx] = entry;
    engine->total_ips_seen++;

    return entry;
}

/* -----------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------------- */

int filter_init(FilterEngine *engine, const ConfigLogSource *src)
{
    memset(engine, 0, sizeof(FilterEngine));
    engine->maxretry = src->maxretry;

    for (int i = 0; i < src->failregex_count; i++) {
        const char *raw = src->failregex[i];
        FilterPattern *pat = &engine->patterns[engine->pattern_count];

        /* Save raw pattern */
        strncpy(pat->raw, raw, CONFIG_MAX_VALUE - 1);

        /* Expand <HOST> token */
        char expanded[CONFIG_MAX_VALUE * 2];
        if (expand_host_token(raw, expanded, sizeof(expanded)) != 0) {
            fprintf(stderr, "filter: failed to expand pattern %d: %s\n",
                    i, raw);
            return -1;
        }

        /* Find which capture group is <HOST> */
        pat->host_group = find_host_group(expanded);

        /* Compile the regex */
        int errcode;
        PCRE2_SIZE erroffset;
        pat->compiled = pcre2_compile((PCRE2_SPTR)expanded,
                                      PCRE2_ZERO_TERMINATED,
                                      0, &errcode, &erroffset, NULL);
        if (pat->compiled == NULL) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            fprintf(stderr, "filter: failed to compile pattern %d: %s\n"
                    "  pattern: %s\n", i, (char *)errbuf, expanded);
            return -1;
        }

        engine->pattern_count++;
    }

    printf("filter: loaded %d failregex patterns\n", engine->pattern_count);
    return 0;
}

void filter_free(FilterEngine *engine)
{
    /* Free compiled regex patterns */
    for (int i = 0; i < engine->pattern_count; i++)
        pcre2_code_free(engine->patterns[i].compiled);

    /* Free hit table entries */
    for (int i = 0; i < FILTER_HIT_TABLE_SIZE; i++) {
        HitEntry *entry = engine->hit_table[i];
        while (entry != NULL) {
            HitEntry *next = entry->next;
            free(entry);
            entry = next;
        }
        engine->hit_table[i] = NULL;
    }
}

int filter_process_line(FilterEngine *engine, const IgnoreList *ignore,
                        const char *line, FilterResult *result)
{
    memset(result, 0, sizeof(FilterResult));

    /* Try each pattern in order */
    for (int i = 0; i < engine->pattern_count; i++) {
        FilterPattern *pat = &engine->patterns[i];

        /* Run the match */
        pcre2_match_data *match_data =
            pcre2_match_data_create_from_pattern(pat->compiled, NULL);
        if (match_data == NULL) {
            fprintf(stderr, "filter: out of memory creating match data\n");
            return -1;
        }

        int rc = pcre2_match(pat->compiled, (PCRE2_SPTR)line,
                             PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
        if (rc == PCRE2_ERROR_NOMATCH) {
            pcre2_match_data_free(match_data);
            continue;
        }
        if (rc < 0) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(rc, errbuf, sizeof(errbuf));
            fprintf(stderr, "filter: match error: %s\n", (char *)errbuf);
            pcre2_match_data_free(match_data);
            return -1;
        }

        /* Pattern matched - extract the IP from the host capture group */
        PCRE2_SIZE *ov  = pcre2_get_ovector_pointer(match_data);
        int         grp = pat->host_group;  /* always 1 */
        if (ov[2 * grp] == PCRE2_UNSET) {
            fprintf(stderr, "filter: host group %d not captured in: %s\n",
                    grp, line);
            pcre2_match_data_free(match_data);
            continue;
        }

        size_t ip_len = ov[2 * grp + 1] - ov[2 * grp];
        if (ip_len >= FILTER_MAX_IP_LEN)
            ip_len = FILTER_MAX_IP_LEN - 1;

        strncpy(result->ip, line + ov[2 * grp], ip_len);
        result->ip[ip_len] = '\0';
        pcre2_match_data_free(match_data);

        result->matched       = true;
        result->pattern_index = i;
        engine->total_hits++;

        /* Check ignore list */
        if (ignore_check(ignore, result->ip)) {
            result->ignored = true;
            return 0;
        }

        /* Get or create hit entry for this IP */
        HitEntry *entry = hit_get_or_create(engine, result->ip);
        if (entry == NULL)
            return -1;

        /* Already banned - no further action needed */
        if (entry->banned) {
            result->already_banned = true;
            result->hit_count      = entry->hits;
            return 0;
        }

        /* Increment hit counter */
        entry->hits++;
        result->hit_count = entry->hits;

        /* Check if ban threshold reached */
        if (entry->hits >= engine->maxretry) {
            result->ban_triggered = true;
            engine->total_banned++;
        }

        return 0;
    }

    /* No pattern matched */
    result->matched = false;
    return 0;
}

void filter_mark_banned(FilterEngine *engine, const char *ip)
{
    HitEntry *entry = hit_get_or_create(engine, ip);
    if (entry != NULL)
        entry->banned = true;
}

void filter_mark_banned_bulk(FilterEngine *engine, const char **ips, int count)
{
    for (int i = 0; i < count; i++)
        filter_mark_banned(engine, ips[i]);
}

int filter_get_pending(const FilterEngine *engine, PendingIP *pending, int max)
{
    int found = 0;

    for (int i = 0; i < FILTER_HIT_TABLE_SIZE && found < max; i++) {
        HitEntry *entry = engine->hit_table[i];
        while (entry != NULL && found < max) {
            if (!entry->banned && entry->hits > 0 &&
                entry->hits < engine->maxretry)
            {
                strncpy(pending[found].ip, entry->ip,
                        FILTER_MAX_IP_LEN - 1);
                pending[found].hits     = entry->hits;
                pending[found].maxretry = engine->maxretry;
                found++;
            }
            entry = entry->next;
        }
    }

    return found;
}

void filter_dump(const FilterEngine *engine)
{
    printf("=== Filter engine ===\n");
    printf("  patterns    : %d\n", engine->pattern_count);
    printf("  maxretry    : %d\n", engine->maxretry);
    printf("  total_hits  : %d\n", engine->total_hits);
    printf("  ips_seen    : %d\n", engine->total_ips_seen);
    printf("  total_banned: %d\n", engine->total_banned);
    printf("  Hit table:\n");
    for (int i = 0; i < FILTER_HIT_TABLE_SIZE; i++) {
        HitEntry *entry = engine->hit_table[i];
        while (entry != NULL) {
            printf("    %s hits=%d banned=%s\n",
                   entry->ip, entry->hits,
                   entry->banned ? "yes" : "no");
            entry = entry->next;
        }
    }
    printf("=====================\n");
}