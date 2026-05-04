/* =============================================================================
 * logmon.c
 * Log file monitor for fwallascan2ban
 *
 * Monitors a web server log file in real time using Linux inotify.
 * Handles log rotation by scanning the log directory for the newest
 * matching file. See logmon.h for full documentation.
 * ============================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/stat.h>

#include "logmon.h"

/* -----------------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------------- */

/*
 * extract_dir - Extract the directory portion of a file path.
 */
static void extract_dir(const char *path, char *out, size_t out_len)
{
    strncpy(out, path, out_len - 1);
    out[out_len - 1] = '\0';

    char *slash = strrchr(out, '/');
    if (slash != NULL) {
        *slash = '\0';
    } else {
        strncpy(out, ".", out_len - 1);
    }
}

/*
 * extract_prefix_suffix - Extract the filename prefix and suffix from a
 * strftime pattern for use in directory scanning.
 *
 * Example:
 *   pattern: /var/log/tomcat10/localhost_access_log.%Y-%m-%d.txt
 *   prefix:  localhost_access_log.
 *   suffix:  .txt
 */
static void extract_prefix_suffix(const char *pattern,
                                   char *prefix, size_t prefix_len,
                                   char *suffix, size_t suffix_len)
{
    /* Get just the filename portion */
    const char *filename = strrchr(pattern, '/');
    if (filename != NULL)
        filename++;
    else
        filename = pattern;

    /* Prefix: everything before the first % */
    const char *pct = strchr(filename, '%');
    if (pct != NULL) {
        size_t len = (size_t)(pct - filename);
        if (len >= prefix_len) len = prefix_len - 1;
        strncpy(prefix, filename, len);
        prefix[len] = '\0';
    } else {
        strncpy(prefix, filename, prefix_len - 1);
        prefix[prefix_len - 1] = '\0';
        suffix[0] = '\0';
        return;
    }

    /* Suffix: last '.' after all strftime codes */
    const char *dot = strrchr(pct, '.');
    if (dot != NULL && dot > pct) {
        strncpy(suffix, dot, suffix_len - 1);
        suffix[suffix_len - 1] = '\0';
    } else {
        suffix[0] = '\0';
    }
}

/*
 * open_log_file - Open the log file.
 * If from_beginning is true, seek to start. Otherwise seek to end.
 */
static int open_log_file(LogmonState *state, const char *path,
                          bool from_beginning)
{
    if (state->log_fp != NULL) {
        fclose(state->log_fp);
        state->log_fp = NULL;
    }

    state->log_fp = fopen(path, "r");
    if (state->log_fp == NULL) {
        fprintf(stderr, "logmon: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    if (from_beginning) {
        state->file_offset = 0;
        fseek(state->log_fp, 0, SEEK_SET);
        printf("logmon: reading '%s' from beginning\n", path);
    } else {
        fseek(state->log_fp, 0, SEEK_END);
        state->file_offset = ftell(state->log_fp);
        printf("logmon: monitoring '%s' (seeking to end)\n", path);
    }

    strncpy(state->current_path, path, CONFIG_MAX_PATH - 1);

    /* Update inotify watch for new file */
    if (state->file_watch_fd >= 0) {
        inotify_rm_watch(state->inotify_fd, state->file_watch_fd);
        state->file_watch_fd = -1;
    }

    state->file_watch_fd = inotify_add_watch(state->inotify_fd, path,
                                              IN_MODIFY | IN_CLOSE_WRITE);
    if (state->file_watch_fd < 0) {
        fprintf(stderr, "logmon: inotify_add_watch failed on '%s': %s\n",
                path, strerror(errno));
        /* Non-fatal */
    }

    return 0;
}

/*
 * read_new_lines - Read any new lines from the log file and invoke callback.
 */
static int read_new_lines(LogmonState *state)
{
    if (state->log_fp == NULL)
        return 0;

    int lines_read = 0;

    fseek(state->log_fp, state->file_offset, SEEK_SET);

    while (fgets(state->line_buf, sizeof(state->line_buf),
                 state->log_fp) != NULL)
    {
        size_t len = strlen(state->line_buf);
        if (len > 0 && state->line_buf[len - 1] == '\n') {
            state->line_buf[len - 1] = '\0';
            len--;
        }

        if (len == 0)
            continue;

        if (state->callback != NULL)
            state->callback(state->line_buf, state->userdata);

        state->lines_processed++;
        lines_read++;
    }

    state->file_offset = ftell(state->log_fp);
    clearerr(state->log_fp);

    return lines_read;
}

/* -----------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------------- */

int logmon_find_newest(const LogmonState *state, char *out, size_t out_len)
{
    DIR *dir = opendir(state->watch_dir);
    if (dir == NULL) {
        fprintf(stderr, "logmon: cannot open directory '%s': %s\n",
                state->watch_dir, strerror(errno));
        return -1;
    }

    char        best_path[CONFIG_MAX_PATH] = "";
    time_t      best_mtime = 0;
    struct dirent *entry;

    size_t prefix_len = strlen(state->file_prefix);
    size_t suffix_len = strlen(state->file_suffix);

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t name_len  = strlen(name);

        /* Must start with our prefix */
        if (strncmp(name, state->file_prefix, prefix_len) != 0)
            continue;

        /* Skip .gz files explicitly */
        if (name_len >= 3 &&
            strcmp(name + name_len - 3, ".gz") == 0)
            continue;

        /* Must end with our suffix */
        if (suffix_len > 0) {
            if (name_len < suffix_len)
                continue;
            if (strcmp(name + name_len - suffix_len,
                       state->file_suffix) != 0)
                continue;
        }

        /* Build full path */
        char full_path[LOGMON_DIR_MAX + 256 + 2];
        snprintf(full_path, sizeof(full_path), "%s/%s",
                 state->watch_dir, name);

        /* Get modification time */
        struct stat st;
        if (stat(full_path, &st) != 0)
            continue;

        if (st.st_mtime > best_mtime) {
            best_mtime = st.st_mtime;
            strncpy(best_path, full_path, CONFIG_MAX_PATH - 1);
        }
    }

    closedir(dir);

    if (best_path[0] == '\0')
        return -1;

    strncpy(out, best_path, out_len - 1);
    out[out_len - 1] = '\0';
    return 0;
}

int logmon_rescan(LogmonState *state, bool from_beginning)
{
    char newest[CONFIG_MAX_PATH];

    if (logmon_find_newest(state, newest, sizeof(newest)) != 0) {
        fprintf(stderr, "logmon: no matching log file found in '%s'\n",
                state->watch_dir);
        return -1;
    }

    /* If same file and not from_beginning, just continue silently */
    if (strcmp(newest, state->current_path) == 0 && !from_beginning)
        return 0;

    printf("logmon: rescan switching to '%s'\n", newest);

    /* Drain remaining lines from current file first */
    if (state->log_fp != NULL)
        read_new_lines(state);

    /* Switch to newest file */
    return open_log_file(state, newest, from_beginning);
}

void logmon_request_rescan(LogmonState *state, bool from_beginning)
{
    state->rescan_requested = true;
    state->from_beginning   = from_beginning;
}

int logmon_resolve_pattern(const char *pattern, char *out, size_t out_len,
                           const struct tm *when)
{
    struct tm   now_tm;
    struct tm  *tm_ptr;

    if (when != NULL) {
        tm_ptr = (struct tm *)when;
    } else {
        time_t now = time(NULL);
        localtime_r(&now, &now_tm);
        tm_ptr = &now_tm;
    }

    size_t rc = strftime(out, out_len, pattern, tm_ptr);
    if (rc == 0) {
        fprintf(stderr, "logmon: strftime failed for pattern '%s'\n",
                pattern);
        return -1;
    }

    return 0;
}

int logmon_init(LogmonState *state, const ConfigLogSource *src,
                LogmonLineCallback callback, void *userdata)
{
    memset(state, 0, sizeof(LogmonState));

    state->inotify_fd    = -1;
    state->dir_watch_fd  = -1;
    state->file_watch_fd = -1;
    state->log_fp        = NULL;
    state->callback      = callback;
    state->userdata      = userdata;
    state->started_at    = time(NULL);
    state->scan_interval = src->log_scan_interval;
    state->last_scan     = time(NULL);

    strncpy(state->pattern, src->log_pattern, CONFIG_MAX_PATH - 1);

    /* Extract directory from pattern */
    char pattern_copy[CONFIG_MAX_PATH];
    strncpy(pattern_copy, src->log_pattern, CONFIG_MAX_PATH - 1);
    extract_dir(pattern_copy, state->watch_dir, sizeof(state->watch_dir));

    /* Extract prefix and suffix for directory scanning */
    extract_prefix_suffix(src->log_pattern,
                           state->file_prefix, sizeof(state->file_prefix),
                           state->file_suffix, sizeof(state->file_suffix));

    printf("logmon: watch dir:   '%s'\n", state->watch_dir);
    printf("logmon: file prefix: '%s'\n", state->file_prefix);
    printf("logmon: file suffix: '%s'\n", state->file_suffix);
    printf("logmon: scan interval: %d seconds\n", state->scan_interval);

    /* Set up inotify */
    state->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (state->inotify_fd < 0) {
        fprintf(stderr, "logmon: inotify_init1 failed: %s\n",
                strerror(errno));
        return -1;
    }

    /* Watch log directory for new file creation */
    state->dir_watch_fd = inotify_add_watch(state->inotify_fd,
                                             state->watch_dir,
                                             IN_CREATE | IN_MOVED_TO);
    if (state->dir_watch_fd < 0) {
        fprintf(stderr, "logmon: cannot watch directory '%s': %s\n",
                state->watch_dir, strerror(errno));
        close(state->inotify_fd);
        state->inotify_fd = -1;
        return -1;
    }

    /* Find and open the newest matching log file */
    char newest[CONFIG_MAX_PATH];
    if (logmon_find_newest(state, newest, sizeof(newest)) == 0) {
        open_log_file(state, newest, false);
    } else {
        fprintf(stderr, "logmon: warning: no log file found yet in '%s', "
                "will detect when created\n", state->watch_dir);
    }

    state->running = true;
    return 0;
}

void logmon_free(LogmonState *state)
{
    state->running = false;

    if (state->log_fp != NULL) {
        fclose(state->log_fp);
        state->log_fp = NULL;
    }

    if (state->inotify_fd >= 0) {
        if (state->dir_watch_fd >= 0)
            inotify_rm_watch(state->inotify_fd, state->dir_watch_fd);
        if (state->file_watch_fd >= 0)
            inotify_rm_watch(state->inotify_fd, state->file_watch_fd);
        close(state->inotify_fd);
        state->inotify_fd    = -1;
        state->dir_watch_fd  = -1;
        state->file_watch_fd = -1;
    }
}

int logmon_rotate(LogmonState *state)
{
    return logmon_rescan(state, false);
}

int logmon_poll(LogmonState *state, int timeout_ms)
{
    if (!state->running)
        return -1;

    int total_lines = 0;

    /* Handle pending rescan request */
    if (state->rescan_requested) {
        state->rescan_requested = false;
        logmon_rescan(state, state->from_beginning);
        state->from_beginning = false;
    }

    /* Check periodic directory scan */
    if (state->scan_interval > 0) {
        time_t now = time(NULL);
        if (now - state->last_scan >= (time_t)state->scan_interval) {
            logmon_rescan(state, false);
            state->last_scan = now;
        }
    }

    /* Use select() to wait for inotify events */
    if (state->inotify_fd >= 0) {
        fd_set          read_fds;
        struct timeval  tv;
        struct timeval *tvp = NULL;

        FD_ZERO(&read_fds);
        FD_SET(state->inotify_fd, &read_fds);

        if (timeout_ms >= 0) {
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            tvp = &tv;
        }

        int ready = select(state->inotify_fd + 1, &read_fds,
                           NULL, NULL, tvp);
        if (ready < 0) {
            if (errno == EINTR)
                return 0;
            fprintf(stderr, "logmon: select error: %s\n", strerror(errno));
            return -1;
        }

        if (ready > 0 && FD_ISSET(state->inotify_fd, &read_fds)) {
            char    event_buf[4096]
                    __attribute__((aligned(
                        __alignof__(struct inotify_event))));
            ssize_t nbytes = read(state->inotify_fd, event_buf,
                                  sizeof(event_buf));

            if (nbytes > 0) {
                ssize_t offset = 0;
                while (offset < nbytes) {
                    struct inotify_event *ev =
                        (struct inotify_event *)(event_buf + offset);

                    if (ev->wd == state->dir_watch_fd) {
                        /* New file in directory - rescan */
                        printf("logmon: directory event, rescanning...\n");
                        logmon_rescan(state, false);
                        state->last_scan = time(NULL);
                    } else if (ev->wd == state->file_watch_fd) {
                        /* Log file modified - read new lines */
                        total_lines += read_new_lines(state);
                    }

                    offset += (ssize_t)(sizeof(struct inotify_event) +
                                        ev->len);
                }
            }
        }
    }

    /* Always do a read attempt in case we missed events */
    total_lines += read_new_lines(state);

    return total_lines;
}

void logmon_get_status(const LogmonState *state, LogmonStatus *status)
{
    strncpy(status->current_path, state->current_path,
            CONFIG_MAX_PATH - 1);
    status->lines_processed = state->lines_processed;
    status->started_at      = state->started_at;
    status->running         = state->running;
    status->file_offset     = state->file_offset;
}
