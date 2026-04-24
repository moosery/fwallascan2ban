#ifndef LOGMON_H
#define LOGMON_H

/* =============================================================================
 * logmon.h
 * Log file monitor for fwallascan2ban
 *
 * Monitors a web server log file in real time, delivering new lines to the
 * filter engine as they are written. Handles log rotation automatically by
 * watching for the appearance of a new file matching the configured pattern.
 *
 * Implementation uses Linux inotify for efficient event-driven file watching.
 * Falls back to polling if inotify is unavailable.
 *
 * Log rotation handling:
 *   Tomcat (and most web servers) rotate logs by closing the current file
 *   and opening a new one with a date-stamped name. logmon detects this by:
 *     1. Watching the log directory for IN_CREATE events
 *     2. Evaluating the log_pattern with the current date
 *     3. When a new file matching the pattern appears, switching to it
 *     4. Reading any remaining lines from the old file before switching
 *
 * The caller provides a callback function that is invoked for each new
 * line read from the log file.
 * ============================================================================= */

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "config.h"

/* -----------------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------------- */

#define LOGMON_MAX_LINE         8192    /* Maximum log line length              */
#define LOGMON_POLL_INTERVAL_MS 1000    /* Polling interval in milliseconds     */
#define LOGMON_DIR_MAX          1024    /* Maximum directory path length        */

/* -----------------------------------------------------------------------------
 * Callback type
 * ----------------------------------------------------------------------------- */

/*
 * LogmonLineCallback - Called for each new line read from the log file.
 *
 * Parameters:
 *   line     - Null-terminated log line string (newline stripped)
 *   userdata - Caller-provided pointer passed through from logmon_start()
 */
typedef void (*LogmonLineCallback)(const char *line, void *userdata);

/* -----------------------------------------------------------------------------
 * Structs
 * ----------------------------------------------------------------------------- */

/* Internal state of the log monitor */
typedef struct {
    char                pattern[CONFIG_MAX_PATH];      /* Log file pattern (strftime)  */
    char                current_path[CONFIG_MAX_PATH]; /* Currently open file path     */
    char                watch_dir[LOGMON_DIR_MAX];     /* Directory being watched      */
    char                file_prefix[CONFIG_MAX_PATH];  /* Prefix for directory scan    */
    char                file_suffix[32];               /* Suffix for directory scan    */
    int                 inotify_fd;                    /* inotify file descriptor      */
    int                 dir_watch_fd;                  /* inotify watch for directory  */
    int                 file_watch_fd;                 /* inotify watch for log file   */
    FILE               *log_fp;                        /* Open log file handle         */
    long                file_offset;                   /* Current read position        */
    bool                running;                       /* true while monitor is active */
    bool                rescan_requested;              /* true if rescan requested     */
    bool                from_beginning;                /* true if reading from start   */
    int                 scan_interval;                 /* Directory scan interval secs */
    time_t              last_scan;                     /* Last directory scan time     */
    LogmonLineCallback  callback;                      /* Line callback function       */
    void               *userdata;                      /* Caller data for callback     */
    unsigned long       lines_processed;               /* Total lines processed        */
    time_t              started_at;                    /* Timestamp monitor started    */
    char                line_buf[LOGMON_MAX_LINE];     /* Line assembly buffer         */
} LogmonState;

/* Snapshot of monitor status - used by client status command */
typedef struct {
    char            current_path[CONFIG_MAX_PATH];  /* Currently monitored file     */
    unsigned long   lines_processed;                /* Total lines processed        */
    time_t          started_at;                     /* When monitoring started      */
    bool            running;                        /* true if monitor is active    */
    long            file_offset;                    /* Current position in log file */
} LogmonStatus;

/* -----------------------------------------------------------------------------
 * Function prototypes
 * ----------------------------------------------------------------------------- */

/*
 * logmon_init - Initialize the log monitor.
 *
 * Sets up inotify, resolves the initial log file path from the pattern,
 * opens the log file, and seeks to the end so only new lines are processed.
 *
 * Parameters:
 *   state    - Pointer to a LogmonState to initialize
 *   config   - Pointer to a loaded Config struct
 *   callback - Function to call for each new log line
 *   userdata - Caller data passed through to callback
 *
 * Returns:
 *   0 on success
 *  -1 on error (file not found, inotify failure)
 */
int logmon_init(LogmonState *state, const Config *config,
                LogmonLineCallback callback, void *userdata);

/*
 * logmon_free - Free all resources used by a LogmonState.
 *
 * Closes the log file, removes inotify watches, and closes the inotify fd.
 *
 * Parameters:
 *   state - Pointer to a LogmonState to free
 */
void logmon_free(LogmonState *state);

/*
 * logmon_poll - Check for new log lines and handle rotation.
 *
 * Should be called in the main daemon loop. Checks inotify for events,
 * reads any new lines from the log file, and invokes the callback for each.
 * Handles log rotation by detecting new files matching the pattern.
 *
 * Parameters:
 *   state      - Pointer to an initialized LogmonState
 *   timeout_ms - Maximum time to block waiting for events (milliseconds)
 *                Pass 0 for non-blocking, -1 to block indefinitely
 *
 * Returns:
 *   Number of lines processed (0 if none)
 *  -1 on error
 */
int logmon_poll(LogmonState *state, int timeout_ms);

/*
 * logmon_resolve_pattern - Resolve a strftime-style log pattern to an
 * actual file path using the current date/time.
 *
 * Parameters:
 *   pattern - Log file pattern string with strftime codes
 *   out     - Buffer to write the resolved path into
 *   out_len - Size of the output buffer
 *   when    - Time to use for pattern resolution (NULL = current time)
 *
 * Returns:
 *   0 on success
 *  -1 on error (buffer too small, strftime failure)
 */
int logmon_resolve_pattern(const char *pattern, char *out, size_t out_len,
                           const struct tm *when);

/*
 * logmon_get_status - Get a snapshot of the current monitor status.
 *
 * Used by the daemon to respond to client status requests.
 *
 * Parameters:
 *   state  - Pointer to an initialized LogmonState
 *   status - Pointer to a LogmonStatus to populate
 */
void logmon_get_status(const LogmonState *state, LogmonStatus *status);

/*
 * logmon_find_newest - Scan the log directory and find the newest log file
 * matching the pattern prefix and suffix.
 *
 * Scans the watch directory for files matching:
 *   <file_prefix>*<file_suffix>  (not .gz)
 * and returns the one with the most recent modification time.
 *
 * Parameters:
 *   state - Pointer to an initialized LogmonState
 *   out   - Buffer to write the resolved path into
 *   out_len - Size of the output buffer
 *
 * Returns:
 *   0 if a file was found (out is populated)
 *  -1 if no matching file found
 */
int logmon_find_newest(const LogmonState *state, char *out, size_t out_len);

/*
 * logmon_rescan - Force a directory rescan and switch to newest log file.
 *
 * Called when a rescan is requested via client command or periodic timer.
 * Finds the newest matching log file in the directory. If it differs from
 * the current file, drains remaining lines from the old file and switches.
 * If from_beginning is true, reads the new file from the start instead of
 * seeking to the end.
 *
 * Parameters:
 *   state          - Pointer to an initialized LogmonState
 *   from_beginning - If true, read new file from start (catch-up mode)
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int logmon_rescan(LogmonState *state, bool from_beginning);

/*
 * logmon_request_rescan - Signal the monitor to rescan on next poll.
 *
 * Thread-safe flag setter. The actual rescan happens in logmon_poll().
 *
 * Parameters:
 *   state          - Pointer to an initialized LogmonState
 *   from_beginning - If true, read from beginning of file
 */
void logmon_request_rescan(LogmonState *state, bool from_beginning);

/*
 * logmon_rotate - Manually trigger a log rotation check.
 *
 * Forces re-evaluation of the log pattern against the current date.
 * If the resolved path differs from the current file, drains remaining
 * lines from the old file and switches to the new one.
 *
 * Called automatically by logmon_poll() when inotify detects a new file
 * in the watched directory.
 *
 * Parameters:
 *   state - Pointer to an initialized LogmonState
 *
 * Returns:
 *   0 on success
 *  -1 on error
 */
int logmon_rotate(LogmonState *state);

#endif /* LOGMON_H */
