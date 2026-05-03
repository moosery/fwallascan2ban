/* =============================================================================
 * firewalla.c
 * Firewalla MSP API client for fwallascan2ban
 *
 * Handles all communication with the Firewalla MSP REST API via libcurl.
 * JSON responses are parsed manually without external dependencies.
 * See firewalla.h for full documentation.
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <curl/curl.h>

#include "firewalla.h"
#include "config.h"

/* -----------------------------------------------------------------------------
 * Internal types
 * ----------------------------------------------------------------------------- */

/* Dynamic buffer for accumulating curl response data */
typedef struct {
    char   *data;
    size_t  size;
    size_t  capacity;
} CurlBuf;

/* -----------------------------------------------------------------------------
 * Internal helpers - curl
 * ----------------------------------------------------------------------------- */

/*
 * curl_write_cb - libcurl write callback. Appends received data to a CurlBuf.
 */
static size_t curl_write_cb(void *contents, size_t size, size_t nmemb,
                             void *userdata)
{
    size_t   bytes  = size * nmemb;
    CurlBuf *buf    = (CurlBuf *)userdata;

    /* Grow buffer if needed */
    if (buf->size + bytes + 1 > buf->capacity) {
        size_t new_cap = buf->capacity + bytes + 4096;
        char  *new_data = realloc(buf->data, new_cap);
        if (new_data == NULL) {
            fprintf(stderr, "firewalla: out of memory in write callback\n");
            return 0;
        }
        buf->data     = new_data;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->size, contents, bytes);
    buf->size += bytes;
    buf->data[buf->size] = '\0';

    return bytes;
}

/*
 * curlbuf_init - Initialize a CurlBuf with an initial allocation.
 */
static int curlbuf_init(CurlBuf *buf)
{
    buf->data = malloc(4096);
    if (buf->data == NULL)
        return -1;
    buf->data[0] = '\0';
    buf->size     = 0;
    buf->capacity = 4096;
    return 0;
}

/*
 * curlbuf_free - Free a CurlBuf.
 */
static void curlbuf_free(CurlBuf *buf)
{
    free(buf->data);
    buf->data     = NULL;
    buf->size     = 0;
    buf->capacity = 0;
}

/*
 * fw_request - Perform an HTTP request to the Firewalla MSP API.
 *
 * Parameters:
 *   client      - Initialized FwClient
 *   method      - HTTP method string ("GET", "POST", "PATCH")
 *   endpoint    - API endpoint path (e.g. "/v2/boxes")
 *   body        - Request body JSON string (NULL for GET)
 *   response    - CurlBuf to receive response body
 *   status_code - Pointer to receive HTTP status code
 *
 * Returns 0 on success, -1 on curl error.
 */
static int fw_request(FwClient *client, const char *method,
                      const char *endpoint, const char *body,
                      CurlBuf *response, long *status_code)
{
    CURL   *curl = (CURL *)client->curl_handle;
    CURLcode res;
    char    url[CONFIG_MAX_VALUE + 64];
    struct curl_slist *headers = NULL;
    char    auth_header[CONFIG_MAX_VALUE + 32];

    /* Build URL */
    snprintf(url, sizeof(url), "https://%s%s",
             client->msp_domain, endpoint);

    /* Build auth header */
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: Token %s", client->msp_token);

    /* Set headers */
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    /* Configure curl */
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)FW_API_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* Set method and body */
    if (strcmp(method, "GET") == 0) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body != NULL) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
        } else {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
        }
    } else if (strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (body != NULL) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
        }
    }

    /* Perform request */
    res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        fprintf(stderr, "firewalla: curl error on %s %s: %s\n",
                method, url, curl_easy_strerror(res));
        return -1;
    }

    if (status_code != NULL)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status_code);

    return 0;
}

/* -----------------------------------------------------------------------------
 * Internal helpers - JSON parsing
 *
 * We parse Firewalla API JSON responses without an external library.
 * These are intentionally simple extractors that handle the specific
 * response formats we expect.
 * ----------------------------------------------------------------------------- */

/*
 * json_find_key - Find the value portion of a JSON key in a string.
 * Returns pointer to the start of the value (after the colon), or NULL.
 *
 * Example: json_find_key(json, "\"gid\"") returns pointer to value after
 * the colon following "gid".
 */
static const char *json_find_key(const char *json, const char *key)
{
    const char *pos = strstr(json, key);
    if (pos == NULL)
        return NULL;

    pos += strlen(key);

    /* Skip whitespace and colon */
    while (*pos == ' ' || *pos == '\t' || *pos == ':' || *pos == ' ')
        pos++;

    return pos;
}

/*
 * json_extract_string - Extract a quoted string value from JSON.
 *
 * pos should point to the opening quote of the value.
 * Writes the unquoted string into out (up to out_len bytes).
 * Returns 0 on success, -1 on error.
 */
static int json_extract_string(const char *pos, char *out, size_t out_len)
{
    if (*pos != '"')
        return -1;

    pos++; /* skip opening quote */
    size_t i = 0;

    while (*pos != '\0' && *pos != '"' && i < out_len - 1) {
        if (*pos == '\\') {
            pos++; /* skip escape char */
            if (*pos == '\0')
                break;
        }
        out[i++] = *pos++;
    }

    out[i] = '\0';
    return (*pos == '"') ? 0 : -1;
}

/*
 * json_get_string - Find a key and extract its string value.
 * Returns 0 on success, -1 if key not found or value not a string.
 */
static int json_get_string(const char *json, const char *key,
                            char *out, size_t out_len)
{
    /* Build the quoted key */
    char quoted_key[256];
    snprintf(quoted_key, sizeof(quoted_key), "\"%s\"", key);

    const char *val = json_find_key(json, quoted_key);
    if (val == NULL)
        return -1;

    return json_extract_string(val, out, out_len);
}

/*
 * json_extract_array_strings - Extract all quoted string values from a
 * JSON array. The pos should point to the opening '['.
 *
 * Writes up to max strings into out array.
 * Returns number of strings extracted.
 */
static int json_extract_array_strings(const char *pos, char out[][FW_MAX_IP_LEN],
                                      int max)
{
    if (*pos != '[')
        return 0;

    pos++; /* skip '[' */
    int count = 0;

    while (*pos != '\0' && *pos != ']' && count < max) {
        /* Skip whitespace and commas */
        while (*pos == ' ' || *pos == '\t' ||
               *pos == '\n' || *pos == ',')
            pos++;

        if (*pos == ']' || *pos == '\0')
            break;

        if (*pos == '"') {
            if (json_extract_string(pos, out[count],
                                    FW_MAX_IP_LEN) == 0) {
                count++;
            }
            /* Advance past this string */
            pos++;
            while (*pos != '"' && *pos != '\0')
                pos++;
            if (*pos == '"')
                pos++;
        } else {
            pos++;
        }
    }

    return count;
}

/*
 * build_targets_json - Build the JSON targets array string from an
 * FwTargetList's IP list.
 *
 * Example output: ["1.2.3.4","5.6.7.8"]
 */
static int build_targets_json(const FwTargetList *list,
                               char *out, size_t out_len)
{
    size_t pos = 0;
    int    rc;

    rc = snprintf(out + pos, out_len - pos, "[");
    if (rc < 0 || (size_t)rc >= out_len - pos) return -1;
    pos += (size_t)rc;

    for (int i = 0; i < list->ip_count; i++) {
        if (i > 0) {
            rc = snprintf(out + pos, out_len - pos, ",");
            if (rc < 0 || (size_t)rc >= out_len - pos) return -1;
            pos += (size_t)rc;
        }
        rc = snprintf(out + pos, out_len - pos, "\"%s\"", list->ips[i].ip);
        if (rc < 0 || (size_t)rc >= out_len - pos) return -1;
        pos += (size_t)rc;
    }

    rc = snprintf(out + pos, out_len - pos, "]");
    if (rc < 0 || (size_t)rc >= out_len - pos) return -1;

    return 0;
}

/*
 * list_name_for_number - Build the target list name for a given sequence number.
 * Number 1 = base name, 2+ = base name + "-N"
 */
static void list_name_for_number(const Config *config, int number,
                                  char *out, size_t out_len)
{
    if (number == 1) {
        strncpy(out, config->target_list.target_list_name, out_len - 1);
    } else {
        snprintf(out, out_len, "%s-%d",
                 config->target_list.target_list_name, number);
    }
}

/*
 * rule_name_for_number - Build the rule name for a given sequence number.
 */
static void rule_name_for_number(const Config *config, int number,
                                  char *out, size_t out_len)
{
    if (number == 1) {
        strncpy(out, config->rule.rule_name, out_len - 1);
    } else {
        snprintf(out, out_len, "%s-%d", config->rule.rule_name, number);
    }
}

/*
 * find_list_with_ip - Find which managed list contains a given IP.
 * Returns pointer to FwManagedList or NULL if not found.
 */
static FwManagedList *find_list_with_ip(FwClient *client, const char *ip)
{
    for (int i = 0; i < client->list_count; i++) {
        FwTargetList *list = &client->lists[i].list;
        for (int j = 0; j < list->ip_count; j++) {
            if (strcmp(list->ips[j].ip, ip) == 0)
                return &client->lists[i];
        }
    }
    return NULL;
}

/*
 * find_list_with_space - Find the first managed list with available capacity.
 * Returns pointer to FwManagedList or NULL if all lists are full.
 */
static FwManagedList *find_list_with_space(FwClient *client,
                                            const Config *config)
{
    for (int i = 0; i < client->list_count; i++) {
        if (client->lists[i].list.ip_count < config->target_list.max_targets)
            return &client->lists[i];
    }
    return NULL;
}

/*
 * ip_in_list - Returns true if the IP is in the given target list.
 */
static bool ip_in_list(const FwTargetList *list, const char *ip)
{
    for (int i = 0; i < list->ip_count; i++) {
        if (strcmp(list->ips[i].ip, ip) == 0)
            return true;
    }
    return false;
}

/*
 * remove_ip_from_list - Remove an IP from a target list in memory.
 * Returns true if removed, false if not found.
 */
static bool remove_ip_from_list(FwTargetList *list, const char *ip)
{
    for (int i = 0; i < list->ip_count; i++) {
        if (strcmp(list->ips[i].ip, ip) == 0) {
            /* Shift remaining entries down */
            for (int j = i; j < list->ip_count - 1; j++)
                list->ips[j] = list->ips[j + 1];
            list->ip_count--;
            return true;
        }
    }
    return false;
}

/*
 * add_ip_to_list - Add an IP to a target list in memory.
 * Returns true on success, false if list is full.
 */
static bool add_ip_to_list(FwTargetList *list, const char *ip)
{
    if (list->ip_count >= FW_MAX_IPS_PER_LIST)
        return false;
    strncpy(list->ips[list->ip_count].ip, ip, FW_MAX_IP_LEN - 1);
    list->ip_count++;
    return true;
}

/*
 * compare_ips - qsort comparator for FwIP entries by numeric IPv4 value.
 */
static int compare_ips(const void *a, const void *b)
{
    const FwIP *ia = (const FwIP *)a;
    const FwIP *ib = (const FwIP *)b;
    unsigned int a1, a2, a3, a4, b1, b2, b3, b4;

    if (sscanf(ia->ip, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4 ||
        sscanf(ib->ip, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4)
        return strcmp(ia->ip, ib->ip);

    if (a1 != b1) return (int)a1 - (int)b1;
    if (a2 != b2) return (int)a2 - (int)b2;
    if (a3 != b3) return (int)a3 - (int)b3;
    return (int)a4 - (int)b4;
}

/*
 * patch_target_list - PATCH the current in-memory state of a target list
 * back to Firewalla.
 */
static int patch_target_list(FwClient *client, FwTargetList *list)
{
    /* Sort IPs numerically before sending */
    qsort(list->ips, (size_t)list->ip_count, sizeof(FwIP), compare_ips);

    /* Build targets JSON array — static to avoid large stack allocation */
    static char targets_json[FW_MAX_IPS_PER_LIST * (FW_MAX_IP_LEN + 4)];
    if (build_targets_json(list, targets_json, sizeof(targets_json)) != 0) {
        fprintf(stderr, "firewalla: failed to build targets JSON\n");
        return -1;
    }

    /* Build full PATCH body */
    static char body[FW_MAX_IPS_PER_LIST * (FW_MAX_IP_LEN + 4) + 256];
    snprintf(body, sizeof(body),
             "{\"targets\": %s}", targets_json);

    /* Build endpoint */
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/v2/target-lists/%s", list->id);

    CurlBuf  response;
    long     status_code = 0;

    if (curlbuf_init(&response) != 0)
        return -1;

    int rc = fw_request(client, "PATCH", endpoint, body,
                        &response, &status_code);

    curlbuf_free(&response);

    if (rc != 0 || (status_code != 200 && status_code != 204)) {
        fprintf(stderr, "firewalla: PATCH target list '%s' failed "
                "(status %ld)\n", list->id, status_code);
        return -1;
    }

    return 0;
}

/* -----------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------------- */

int fw_init(FwClient *client, const Config *config)
{
    memset(client, 0, sizeof(FwClient));

    strncpy(client->msp_domain, config->msp.msp_domain,
            CONFIG_MAX_VALUE - 1);
    strncpy(client->msp_token, config->msp.msp_token,
            CONFIG_MAX_VALUE - 1);

    /* Initialize libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    client->curl_handle = curl_easy_init();
    if (client->curl_handle == NULL) {
        fprintf(stderr, "firewalla: curl_easy_init failed\n");
        return -1;
    }

    /* Resolve box GID from box_name */
    CurlBuf  response;
    long     status_code = 0;

    if (curlbuf_init(&response) != 0)
        return -1;

    if (fw_request(client, "GET", "/v2/boxes", NULL,
                   &response, &status_code) != 0 || status_code != 200) {
        fprintf(stderr, "firewalla: GET /v2/boxes failed (status %ld)\n",
                status_code);
        curlbuf_free(&response);
        return -1;
    }

    /* Find the box matching box_name and extract its GID */
    const char *search = response.data;
    bool found = false;

    while ((search = strstr(search, "\"name\"")) != NULL) {
        char name[FW_MAX_NAME_LEN];
        const char *val = json_find_key(search, "\"name\"");
        if (val && json_extract_string(val, name, sizeof(name)) == 0) {
            if (strcmp(name, config->msp.box_name) == 0) {
                /* Found our box - now find its gid in the same object */
                /* Search backwards a bit for the gid field */
                char gid[FW_MAX_ID_LEN];
                if (json_get_string(search - 200 < response.data
                                    ? response.data : search - 200,
                                    "gid", gid, sizeof(gid)) == 0) {
                    strncpy(client->box_gid, gid, FW_MAX_ID_LEN - 1);
                    found = true;
                    break;
                }
            }
        }
        search++;
    }

    curlbuf_free(&response);

    if (!found) {
        fprintf(stderr, "firewalla: box '%s' not found in MSP\n",
                config->msp.box_name);
        return -1;
    }

    printf("firewalla: resolved box '%s' -> GID %s\n",
           config->msp.box_name, client->box_gid);

    /* Resolve scope if configured */
    if (config->rule.rule_scope_type != RULE_SCOPE_NONE) {
        if (curlbuf_init(&response) != 0)
            return -1;

        if (fw_request(client, "GET", "/v2/devices", NULL,
                       &response, &status_code) != 0 || status_code != 200) {
            fprintf(stderr, "firewalla: GET /v2/devices failed\n");
            curlbuf_free(&response);
            return -1;
        }

        const char *scope_val = config->rule.rule_scope_value;
        bool scope_found = false;
        search = response.data;

        if (config->rule.rule_scope_type == RULE_SCOPE_NETWORK) {
            /* Look for network name match */
            while ((search = strstr(search, "\"name\"")) != NULL) {
                char net_name[FW_MAX_NAME_LEN];
                const char *val = json_find_key(search, "\"name\"");
                if (val && json_extract_string(val, net_name,
                                               sizeof(net_name)) == 0) {
                    if (strcmp(net_name, scope_val) == 0) {
                        /* Extract network id */
                        char net_id[FW_MAX_ID_LEN];
                        if (json_get_string(search, "id", net_id,
                                            sizeof(net_id)) == 0) {
                            strncpy(client->scope_id, net_id,
                                    FW_MAX_ID_LEN - 1);
                            strncpy(client->scope_type, "network",
                                    FW_MAX_NAME_LEN - 1);
                            scope_found = true;
                            break;
                        }
                    }
                }
                search++;
            }
        } else if (config->rule.rule_scope_type == RULE_SCOPE_DEVICE) {
            /* Look for device name match - extract MAC address */
            while ((search = strstr(search, "\"name\"")) != NULL) {
                char dev_name[FW_MAX_NAME_LEN];
                const char *val = json_find_key(search, "\"name\"");
                if (val && json_extract_string(val, dev_name,
                                               sizeof(dev_name)) == 0) {
                    if (strcmp(dev_name, scope_val) == 0) {
                        char mac[FW_MAX_ID_LEN];
                        if (json_get_string(search, "mac", mac,
                                            sizeof(mac)) == 0) {
                            strncpy(client->scope_id, mac,
                                    FW_MAX_ID_LEN - 1);
                            strncpy(client->scope_type, "device",
                                    FW_MAX_NAME_LEN - 1);
                            scope_found = true;
                            printf("firewalla: resolved scope device "
                                   "'%s' -> MAC %s\n", scope_val, mac);
                            break;
                        }
                    }
                }
                search++;
            }
        }

        curlbuf_free(&response);

        if (!scope_found) {
            fprintf(stderr, "firewalla: scope '%s' not found\n", scope_val);
            return -1;
        }
    }

    return 0;
}

void fw_free(FwClient *client)
{
    if (client->curl_handle != NULL) {
        curl_easy_cleanup((CURL *)client->curl_handle);
        client->curl_handle = NULL;
    }
    curl_global_cleanup();
}

int fw_create_target_list(FwClient *client, const Config *config,
                           int number, FwTargetList *out_list)
{
    char name[FW_MAX_NAME_LEN];
    list_name_for_number(config, number, name, sizeof(name));

    /* Build POST body with placeholder IP */
    char body[CONFIG_MAX_VALUE * 2 + 256];
    snprintf(body, sizeof(body),
             "{"
             "\"name\": \"%s\","
             "\"category\": \"%s\","
             "\"notes\": \"%s\","
             "\"owner\": \"global\","
             "\"targets\": [\"%s\"]"
             "}",
             name,
             config->target_list.target_list_category,
             config->target_list.target_list_notes,
             config->target_list.placeholder_ip);

    CurlBuf  response;
    long     status_code = 0;

    if (curlbuf_init(&response) != 0)
        return -1;

    int rc = fw_request(client, "POST", "/v2/target-lists", body,
                        &response, &status_code);

    if (rc != 0 || status_code != 200) {
        fprintf(stderr, "firewalla: POST /v2/target-lists failed "
                "(status %ld): %s\n", status_code,
                response.data ? response.data : "");
        curlbuf_free(&response);
        return -1;
    }

    /* Parse response to get new list ID */
    memset(out_list, 0, sizeof(FwTargetList));
    json_get_string(response.data, "id", out_list->id, FW_MAX_ID_LEN);
    strncpy(out_list->name, name, FW_MAX_NAME_LEN - 1);
    strncpy(out_list->category, config->target_list.target_list_category,
            FW_MAX_NAME_LEN - 1);
    strncpy(out_list->notes, config->target_list.target_list_notes,
            CONFIG_MAX_VALUE - 1);
    out_list->number = number;

    /* Add placeholder to in-memory list */
    strncpy(out_list->ips[0].ip, config->target_list.placeholder_ip,
            FW_MAX_IP_LEN - 1);
    out_list->ip_count = 1;

    curlbuf_free(&response);

    printf("firewalla: created target list '%s' (id: %s)\n",
           name, out_list->id);
    return 0;
}

int fw_create_rule(FwClient *client, const Config *config,
                   const FwTargetList *list, int number, FwRule *out_rule)
{
    char rule_name[FW_MAX_NAME_LEN];
    rule_name_for_number(config, number, rule_name, sizeof(rule_name));

    /* Build direction string */
    const char *direction;
    switch (config->rule.rule_direction) {
        case RULE_DIRECTION_INBOUND:    direction = "inbound";    break;
        case RULE_DIRECTION_OUTBOUND:   direction = "outbound";   break;
        default:                        direction = "bidirection"; break;
    }

    /* Build scope JSON fragment */
    char scope_json[FW_MAX_NAME_LEN + FW_MAX_ID_LEN + 64] = "";
    if (client->scope_type[0] != '\0') {
        snprintf(scope_json, sizeof(scope_json),
                 ",\"scope\": {\"type\": \"%s\", \"value\": \"%s\"}",
                 client->scope_type, client->scope_id);
    }

    /* Build POST body - sized for worst case of all string fields */
    char body[CONFIG_MAX_VALUE * 2 + FW_MAX_ID_LEN * 2 +
              FW_MAX_NAME_LEN * 2 + 512];
    snprintf(body, sizeof(body),
             "{"
             "\"action\": \"%s\","
             "\"direction\": \"%s\","
             "\"gid\": \"%s\","
             "\"notes\": \"%s\","
             "\"target\": {"
             "\"type\": \"targetlist\","
             "\"value\": \"%s\""
             "}"
             "%s"
             "}",
             config->rule.rule_action,
             direction,
             client->box_gid,
             config->rule.rule_notes,
             list->id,
             scope_json);

    CurlBuf  response;
    long     status_code = 0;

    if (curlbuf_init(&response) != 0)
        return -1;

    int rc = fw_request(client, "POST", "/v2/rules", body,
                        &response, &status_code);

    if (rc != 0 || status_code != 200) {
        fprintf(stderr, "firewalla: POST /v2/rules failed "
                "(status %ld): %s\n", status_code,
                response.data ? response.data : "");
        curlbuf_free(&response);
        return -1;
    }

    /* Parse response */
    memset(out_rule, 0, sizeof(FwRule));
    json_get_string(response.data, "id", out_rule->id, FW_MAX_ID_LEN);
    strncpy(out_rule->name, rule_name, FW_MAX_NAME_LEN - 1);
    strncpy(out_rule->target_list_id, list->id, FW_MAX_ID_LEN - 1);
    out_rule->active = true;

    curlbuf_free(&response);

    printf("firewalla: created rule '%s' for list '%s' (rule id: %s)\n",
           rule_name, list->name, out_rule->id);
    return 0;
}

int fw_reconcile(FwClient *client, const Config *config,
                 const char **db_ips, int db_count,
                 FwReconcileReport *report)
{
    memset(report, 0, sizeof(FwReconcileReport));

    printf("firewalla: starting reconciliation...\n");

    /* -------------------------------------------------------------------------
     * Step 1: Fetch all target lists from Firewalla
     * --------------------------------------------------------------------- */
    CurlBuf  response;
    long     status_code = 0;

    if (curlbuf_init(&response) != 0)
        return -1;

    if (fw_request(client, "GET", "/v2/target-lists", NULL,
                   &response, &status_code) != 0 || status_code != 200) {
        fprintf(stderr, "firewalla: GET /v2/target-lists failed "
                "(status %ld)\n", status_code);
        curlbuf_free(&response);
        return -1;
    }

    /* Parse target lists matching our base name */
    client->list_count = 0;
    client->total_ips  = 0;

    const char *search = response.data;
    char base_name[FW_MAX_NAME_LEN];
    strncpy(base_name, config->target_list.target_list_name,
            FW_MAX_NAME_LEN - 1);

    /* Find each list object in the JSON array */
    while ((search = strstr(search, "\"id\"")) != NULL &&
           client->list_count < FW_MAX_TARGET_LISTS)
    {
        char list_id[FW_MAX_ID_LEN];
        const char *val = json_find_key(search, "\"id\"");
        if (val == NULL) { search++; continue; }
        if (json_extract_string(val, list_id, sizeof(list_id)) != 0) {
            search++; continue;
        }

        /* Only process TL- prefixed IDs */
        if (strncmp(list_id, "TL-", 3) != 0) { search++; continue; }

        /* Extract name */
        char list_name[FW_MAX_NAME_LEN];
        const char *name_pos = strstr(search, "\"name\"");
        if (name_pos == NULL) { search++; continue; }
        val = json_find_key(name_pos, "\"name\"");
        if (val == NULL || json_extract_string(val, list_name,
                                               sizeof(list_name)) != 0) {
            search++; continue;
        }

        /* Check if this list matches our base name pattern */
        bool matches = (strcmp(list_name, base_name) == 0);
        if (!matches) {
            /* Check for numbered suffix: base_name-N */
            size_t base_len = strlen(base_name);
            if (strncmp(list_name, base_name, base_len) == 0 &&
                list_name[base_len] == '-' &&
                list_name[base_len + 1] >= '2' &&
                list_name[base_len + 1] <= '9') {
                matches = true;
            }
        }

        if (!matches) { search++; continue; }

        /* Fetch the full target list to get its IPs */
        char endpoint[256];
        snprintf(endpoint, sizeof(endpoint), "/v2/target-lists/%s", list_id);

        CurlBuf list_response;
        if (curlbuf_init(&list_response) != 0) {
            curlbuf_free(&response);
            return -1;
        }

        long list_status = 0;
        if (fw_request(client, "GET", endpoint, NULL,
                       &list_response, &list_status) != 0 ||
            list_status != 200) {
            fprintf(stderr, "firewalla: GET %s failed\n", endpoint);
            curlbuf_free(&list_response);
            search++;
            continue;
        }

        /* Populate FwManagedList */
        FwManagedList *ml = &client->lists[client->list_count];
        memset(ml, 0, sizeof(FwManagedList));

        strncpy(ml->list.id, list_id, FW_MAX_ID_LEN - 1);
        strncpy(ml->list.name, list_name, FW_MAX_NAME_LEN - 1);

        /* Determine sequence number */
        if (strcmp(list_name, base_name) == 0) {
            ml->list.number = 1;
        } else {
            ml->list.number = atoi(list_name + strlen(base_name) + 1);
        }

        /* Extract targets array */
        const char *targets_pos = strstr(list_response.data, "\"targets\"");
        if (targets_pos != NULL) {
            const char *arr = json_find_key(targets_pos, "\"targets\"");
            if (arr != NULL) {
                char extracted[FW_MAX_IPS_PER_LIST][FW_MAX_IP_LEN];
                int n = json_extract_array_strings(arr, extracted,
                                                   FW_MAX_IPS_PER_LIST);
                for (int i = 0; i < n; i++) {
                    strncpy(ml->list.ips[ml->list.ip_count].ip,
                            extracted[i], FW_MAX_IP_LEN - 1);
                    ml->list.ip_count++;
                }
            }
        }

        ml->is_full = (ml->list.ip_count >= config->target_list.max_targets);
        client->total_ips += ml->list.ip_count;
        client->list_count++;
        report->lists_found++;

        curlbuf_free(&list_response);
        search++;
    }

    curlbuf_free(&response);

    report->total_ips_found = client->total_ips;
    printf("firewalla: found %d matching target list(s) with %d total IPs\n",
           client->list_count, client->total_ips);

    /* -------------------------------------------------------------------------
     * Step 2: Handle missing target list
     * --------------------------------------------------------------------- */
    if (client->list_count == 0) {
        if (config->target_list.target_list_on_missing == ON_MISSING_ERROR) {
            fprintf(stderr, "firewalla: target list '%s' not found "
                    "and on_missing=error\n",
                    config->target_list.target_list_name);
            return -1;
        }

        printf("firewalla: target list not found, creating...\n");
        FwManagedList *ml = &client->lists[0];
        memset(ml, 0, sizeof(FwManagedList));

        if (fw_create_target_list(client, config, 1, &ml->list) != 0)
            return -1;

        if (config->rule.rule_auto_create) {
            if (fw_create_rule(client, config, &ml->list, 1,
                               &ml->rule) != 0)
                return -1;
            ml->has_rule = true;
        }

        client->list_count = 1;
        client->total_ips  = ml->list.ip_count;
    }

    /* -------------------------------------------------------------------------
     * Step 3: Deduplicate IPs across lists
     * --------------------------------------------------------------------- */
    if (config->reconciliation.on_duplicate_ip != ON_DUPLICATE_KEEP) {
        /* Build a seen-IP set using simple array scan */
        char seen[FW_MAX_TARGET_LISTS * FW_MAX_IPS_PER_LIST][FW_MAX_IP_LEN];
        int  seen_count = 0;

        for (int li = 0; li < client->list_count; li++) {
            FwTargetList *list = &client->lists[li].list;
            bool list_modified = false;

            for (int ii = list->ip_count - 1; ii >= 0; ii--) {
                const char *ip = list->ips[ii].ip;
                bool already_seen = false;

                for (int si = 0; si < seen_count; si++) {
                    if (strcmp(seen[si], ip) == 0) {
                        already_seen = true;
                        break;
                    }
                }

                if (already_seen) {
                    report->duplicates_found++;
                    if (config->reconciliation.on_duplicate_ip ==
                        ON_DUPLICATE_ERROR) {
                        fprintf(stderr, "firewalla: duplicate IP %s found "
                                "and on_duplicate_ip=error\n", ip);
                        return -1;
                    }
                    /* Remove duplicate */
                    remove_ip_from_list(list, ip);
                    report->duplicates_action++;
                    list_modified = true;
                } else {
                    if (seen_count <
                        (int)(sizeof(seen) / sizeof(seen[0]))) {
                        strncpy(seen[seen_count], ip, FW_MAX_IP_LEN - 1);
                        seen_count++;
                    }
                }
            }

            /* If list is now empty add placeholder */
            if (list_modified && list->ip_count == 0) {
                add_ip_to_list(list, config->target_list.placeholder_ip);
            }

            /* PATCH list if modified */
            if (list_modified)
                patch_target_list(client, list);
        }
    }

    /* -------------------------------------------------------------------------
     * Step 4: Reconcile against local db
     * --------------------------------------------------------------------- */

    /* Check IPs in Firewalla but not in db */
    for (int li = 0; li < client->list_count; li++) {
        FwTargetList *list = &client->lists[li].list;
        bool list_modified = false;

        for (int ii = list->ip_count - 1; ii >= 0; ii--) {
            const char *ip = list->ips[ii].ip;

            /* Skip placeholder */
            if (strcmp(ip, config->target_list.placeholder_ip) == 0)
                continue;

            bool in_db = false;
            for (int di = 0; di < db_count; di++) {
                if (strcmp(db_ips[di], ip) == 0) {
                    in_db = true;
                    break;
                }
            }

            if (!in_db) {
                report->in_fw_not_db++;
                switch (config->reconciliation.on_ip_in_firewalla_not_db) {
                    case ON_FW_NOT_DB_ADD:
                        /* Caller handles adding to db - just count */
                        report->in_fw_not_db_action++;
                        break;
                    case ON_FW_NOT_DB_REMOVE:
                        remove_ip_from_list(list, ip);
                        report->in_fw_not_db_action++;
                        list_modified = true;
                        break;
                    case ON_FW_NOT_DB_ERROR:
                        fprintf(stderr, "firewalla: IP %s in Firewalla "
                                "but not in db\n", ip);
                        return -1;
                }
            }
        }

        if (list_modified) {
            if (list->ip_count == 0)
                add_ip_to_list(list, config->target_list.placeholder_ip);
            patch_target_list(client, list);
        }
    }

    /* Check IPs in db but not in Firewalla */
    for (int di = 0; di < db_count; di++) {
        const char *ip = db_ips[di];
        bool in_fw = fw_ip_is_banned(client, ip);

        if (!in_fw) {
            report->in_db_not_fw++;
            switch (config->reconciliation.on_ip_in_db_not_firewalla) {
                case ON_DB_NOT_FW_ADD: {
                    /* Re-add to Firewalla */
                    FwBanResult ban_result;
                    fw_ban_ip(client, config, ip, &ban_result);
                    report->in_db_not_fw_action++;
                    break;
                }
                case ON_DB_NOT_FW_REMOVE:
                    /* Caller handles removing from db */
                    report->in_db_not_fw_action++;
                    break;
                case ON_DB_NOT_FW_ERROR:
                    fprintf(stderr, "firewalla: IP %s in db but not "
                            "in Firewalla\n", ip);
                    return -1;
            }
        }
    }

    /* -------------------------------------------------------------------------
     * Step 5: Verify block rules
     * --------------------------------------------------------------------- */

    /* Fetch all rules */
    if (curlbuf_init(&response) != 0)
        return -1;

    if (fw_request(client, "GET", "/v2/rules", NULL,
                   &response, &status_code) == 0 && status_code == 200) {

        for (int li = 0; li < client->list_count; li++) {
            FwManagedList *ml = &client->lists[li];
            ml->has_rule = false;

            /* Search rules response for a rule targeting this list */
            const char *rsearch = response.data;
            while ((rsearch = strstr(rsearch, ml->list.id)) != NULL) {
                /* Found reference to this list ID in rules */
                /* Extract the rule ID */
                const char *id_pos = rsearch;
                while (id_pos > response.data &&
                       strncmp(id_pos, "\"id\"", 4) != 0)
                    id_pos--;

                char rule_id[FW_MAX_ID_LEN];
                if (json_get_string(id_pos, "id", rule_id,
                                    sizeof(rule_id)) == 0) {
                    strncpy(ml->rule.id, rule_id, FW_MAX_ID_LEN - 1);
                    strncpy(ml->rule.target_list_id, ml->list.id,
                            FW_MAX_ID_LEN - 1);
                    ml->rule.active  = true;
                    ml->has_rule     = true;
                    break;
                }
                rsearch++;
            }

            if (!ml->has_rule) {
                report->missing_rules++;
                if (config->reconciliation.on_missing_rule ==
                    ON_MISSING_RULE_ERROR) {
                    fprintf(stderr, "firewalla: no rule for list '%s' "
                            "and on_missing_rule=error\n", ml->list.name);
                    curlbuf_free(&response);
                    return -1;
                }
                if (config->rule.rule_auto_create) {
                    if (fw_create_rule(client, config, &ml->list,
                                       ml->list.number, &ml->rule) == 0) {
                        ml->has_rule = true;
                        report->missing_rules_created++;
                    }
                }
            }
        }
    }

    /* -------------------------------------------------------------------------
     * Step 5b: Find individual Firewalla IP block rules
     * For any IP already in our target lists, remove it — Firewalla owns the
     * block at a higher level. Track all such IPs in client->individual_rule_ips
     * so the daemon can seed the filter engine and update the db.
     * --------------------------------------------------------------------- */
    client->individual_rule_ip_count = 0;
    const char *iscan = response.data;

    while (iscan != NULL) {
        /* Find next target block with type "ip" */
        const char *type_pos = strstr(iscan, "\"type\":\"ip\"");
        if (type_pos == NULL)
            type_pos = strstr(iscan, "\"type\": \"ip\"");
        if (type_pos == NULL)
            break;

        /* Extract the IP value from this target block */
        char fw_ip[FW_MAX_IP_LEN] = {0};
        if (json_get_string(type_pos, "value", fw_ip, sizeof(fw_ip)) != 0) {
            iscan = type_pos + 1;
            continue;
        }

        /* Validate it looks like an IPv4 address */
        unsigned int a, b, c, d;
        if (sscanf(fw_ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            iscan = type_pos + 1;
            continue;
        }

        /* Check the enclosing rule has action=block and status=active by
         * looking back up to 512 bytes for the surrounding rule context */
        size_t lookback = (size_t)(type_pos - response.data);
        if (lookback > 512) lookback = 512;
        char ctx[513];
        memcpy(ctx, type_pos - lookback, lookback);
        ctx[lookback] = '\0';
        if (strstr(ctx, "\"block\"") == NULL ||
            strstr(ctx, "\"active\"") == NULL) {
            iscan = type_pos + 1;
            continue;
        }

        /* Skip placeholder */
        if (strcmp(fw_ip, config->target_list.placeholder_ip) == 0) {
            iscan = type_pos + 1;
            continue;
        }

        /* Store in individual rule IP list */
        if (client->individual_rule_ip_count < FW_MAX_INDIVIDUAL_RULES) {
            strncpy(client->individual_rule_ips[client->individual_rule_ip_count],
                    fw_ip, FW_MAX_IP_LEN - 1);
            client->individual_rule_ip_count++;
            report->fw_rule_found++;
        }

        /* Remove from our managed target lists if present — Firewalla owns it */
        for (int li = 0; li < client->list_count; li++) {
            FwTargetList *list = &client->lists[li].list;
            if (!ip_in_list(list, fw_ip))
                continue;
            remove_ip_from_list(list, fw_ip);
            if (list->ip_count == 0)
                add_ip_to_list(list, config->target_list.placeholder_ip);
            patch_target_list(client, list);
            report->fw_rule_removed++;
            printf("firewalla: removed %s from '%s' "
                   "(covered by Firewalla individual rule)\n",
                   fw_ip, list->name);
            break;
        }

        iscan = type_pos + 1;
    }

    curlbuf_free(&response);

    /* -------------------------------------------------------------------------
     * Step 6: Consolidate lists if configured
     * --------------------------------------------------------------------- */
    if (config->reconciliation.on_list_consolidation ==
        ON_CONSOLIDATION_CONSOLIDATE && client->list_count > 1)
    {
        /* Simple consolidation: try to fill earlier lists from later ones */
        for (int li = 0; li < client->list_count - 1; li++) {
            FwTargetList *dst = &client->lists[li].list;
            int available = config->target_list.max_targets - dst->ip_count;

            /* Subtract placeholder from available if present */
            if (ip_in_list(dst, config->target_list.placeholder_ip))
                available++;

            if (available <= 0)
                continue;

            /* Pull from the next list */
            FwManagedList *src_ml = &client->lists[li + 1];
            FwTargetList  *src    = &src_ml->list;
            bool dst_modified     = false;
            bool src_modified     = false;

            for (int ii = src->ip_count - 1;
                 ii >= 0 && available > 0; ii--)
            {
                const char *ip = src->ips[ii].ip;
                if (strcmp(ip, config->target_list.placeholder_ip) == 0)
                    continue;

                /* Remove placeholder from dst if present before adding */
                if (dst->ip_count == 1 &&
                    ip_in_list(dst, config->target_list.placeholder_ip)) {
                    remove_ip_from_list(dst,
                                        config->target_list.placeholder_ip);
                }

                if (add_ip_to_list(dst, ip)) {
                    remove_ip_from_list(src, ip);
                    available--;
                    dst_modified = true;
                    src_modified = true;
                    report->lists_consolidated++;
                }
            }

            if (dst_modified) patch_target_list(client, dst);

            if (src_modified) {
                if (src->ip_count == 0) {
                    /* List is empty - add placeholder before PATCH */
                    add_ip_to_list(src, config->target_list.placeholder_ip);
                    patch_target_list(client, src);
                    /* We could delete this list but leave that for
                     * a future enhancement to avoid complexity */
                } else {
                    patch_target_list(client, src);
                }
            }
        }
    }

    /* -------------------------------------------------------------------------
     * Step 7: Sort any lists that are out of order
     * --------------------------------------------------------------------- */
    for (int li = 0; li < client->list_count; li++) {
        FwTargetList *list = &client->lists[li].list;
        bool sorted = true;
        for (int ii = 1; ii < list->ip_count; ii++) {
            if (compare_ips(&list->ips[ii - 1], &list->ips[ii]) > 0) {
                sorted = false;
                break;
            }
        }
        if (!sorted)
            patch_target_list(client, list);
    }

    /* -------------------------------------------------------------------------
     * Step 8: Update total IP count
     * --------------------------------------------------------------------- */
    client->total_ips = 0;
    for (int li = 0; li < client->list_count; li++)
        client->total_ips += client->lists[li].list.ip_count;

    printf("firewalla: reconciliation complete:\n");
    printf("  lists found:          %d\n", report->lists_found);
    printf("  total IPs:            %d\n", report->total_ips_found);
    printf("  duplicates found:     %d (acted on: %d)\n",
           report->duplicates_found, report->duplicates_action);
    printf("  in FW not db:         %d (acted on: %d)\n",
           report->in_fw_not_db, report->in_fw_not_db_action);
    printf("  in db not FW:         %d (acted on: %d)\n",
           report->in_db_not_fw, report->in_db_not_fw_action);
    printf("  missing rules:        %d (created: %d)\n",
           report->missing_rules, report->missing_rules_created);
    printf("  IPs consolidated:     %d\n", report->lists_consolidated);
    printf("  FW individual rules:  %d found, %d removed from our lists\n",
           report->fw_rule_found, report->fw_rule_removed);

    return 0;
}

int fw_ban_ip(FwClient *client, const Config *config,
              const char *ip, FwBanResult *result)
{
    memset(result, 0, sizeof(FwBanResult));

    /* Check if already banned */
    if (fw_ip_is_banned(client, ip)) {
        result->already_banned = true;
        result->success        = true;
        return 0;
    }

    /* Find a list with space */
    FwManagedList *ml = find_list_with_space(client, config);

    if (ml == NULL) {
        /* All lists full - create overflow list */
        if (client->list_count >= FW_MAX_TARGET_LISTS) {
            fprintf(stderr, "firewalla: maximum target lists reached\n");
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Maximum target lists (%d) reached", FW_MAX_TARGET_LISTS);
            return -1;
        }

        int new_number = client->list_count + 1;
        ml = &client->lists[client->list_count];
        memset(ml, 0, sizeof(FwManagedList));

        if (fw_create_target_list(client, config, new_number,
                                   &ml->list) != 0) {
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Failed to create overflow target list");
            return -1;
        }

        result->new_list_created = true;
        client->list_count++;

        if (config->rule.rule_auto_create) {
            if (fw_create_rule(client, config, &ml->list,
                               new_number, &ml->rule) == 0) {
                ml->has_rule = true;
                result->new_rule_created = true;
            }
        }
    }

    /* Remove placeholder if present */
    if (ip_in_list(&ml->list, config->target_list.placeholder_ip)) {
        remove_ip_from_list(&ml->list, config->target_list.placeholder_ip);
        result->placeholder_removed = true;
    }

    /* Add the IP */
    if (!add_ip_to_list(&ml->list, ip)) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to add IP to list (list full in memory)");
        return -1;
    }

    /* Update is_full flag */
    ml->is_full = (ml->list.ip_count >= config->target_list.max_targets);

    /* PATCH to Firewalla */
    if (patch_target_list(client, &ml->list) != 0) {
        /* Rollback in-memory change */
        remove_ip_from_list(&ml->list, ip);
        if (result->placeholder_removed)
            add_ip_to_list(&ml->list, config->target_list.placeholder_ip);
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "PATCH to Firewalla failed");
        return -1;
    }

    client->total_ips++;
    result->success = true;
    strncpy(result->list_id,   ml->list.id,   FW_MAX_ID_LEN - 1);
    strncpy(result->list_name, ml->list.name, FW_MAX_NAME_LEN - 1);

    return 0;
}

int fw_unban_ip(FwClient *client, const Config *config,
                const char *ip, FwUnbanResult *result)
{
    memset(result, 0, sizeof(FwUnbanResult));

    /* Find the list containing this IP */
    FwManagedList *ml = find_list_with_ip(client, ip);
    if (ml == NULL) {
        result->not_found = true;
        result->success   = true; /* Not an error - IP wasn't banned */
        return 0;
    }

    strncpy(result->list_id,   ml->list.id,   FW_MAX_ID_LEN - 1);
    strncpy(result->list_name, ml->list.name, FW_MAX_NAME_LEN - 1);

    /* Remove the IP */
    remove_ip_from_list(&ml->list, ip);
    ml->is_full = false;
    client->total_ips--;

    /* If list is now empty, add placeholder */
    if (ml->list.ip_count == 0) {
        add_ip_to_list(&ml->list, config->target_list.placeholder_ip);
        result->placeholder_added = true;
        client->total_ips++;
    }

    /* PATCH to Firewalla */
    if (patch_target_list(client, &ml->list) != 0) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "PATCH to Firewalla failed");
        return -1;
    }

    result->success = true;

    /* Trigger consolidation if configured */
    if (config->reconciliation.on_list_consolidation ==
        ON_CONSOLIDATION_CONSOLIDATE && client->list_count > 1)
    {
        /* Simple: just flag that consolidation may be needed.
         * Full consolidation runs during reconcile(). */
        result->list_consolidated = true;
    }

    return 0;
}

bool fw_ip_is_banned(const FwClient *client, const char *ip)
{
    return (find_list_with_ip((FwClient *)client, ip) != NULL);
}

int fw_get_all_banned_ips(const FwClient *client, FwIP *ips, int max,
                           char list_ids[][FW_MAX_ID_LEN])
{
    int count = 0;

    for (int li = 0; li < client->list_count && count < max; li++) {
        const FwTargetList *list = &client->lists[li].list;
        for (int ii = 0; ii < list->ip_count && count < max; ii++) {
            strncpy(ips[count].ip, list->ips[ii].ip, FW_MAX_IP_LEN - 1);
            strncpy(list_ids[count], list->id, FW_MAX_ID_LEN - 1);
            count++;
        }
    }

    return count;
}

void fw_dump(const FwClient *client)
{
    printf("=== Firewalla client ===\n");
    printf("  domain     : %s\n", client->msp_domain);
    printf("  box_gid    : %s\n", client->box_gid);
    printf("  scope_type : %s\n", client->scope_type);
    printf("  scope_id   : %s\n", client->scope_id);
    printf("  list_count : %d\n", client->list_count);
    printf("  total_ips  : %d\n", client->total_ips);
    for (int i = 0; i < client->list_count; i++) {
        const FwManagedList *ml = &client->lists[i];
        printf("  List[%d]: %s (id=%s, ips=%d, has_rule=%s)\n",
               i, ml->list.name, ml->list.id, ml->list.ip_count,
               ml->has_rule ? "yes" : "no");
    }
    printf("========================\n");
}