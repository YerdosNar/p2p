#ifndef LOGGER_H
#define LOGGER_H

/*
 * logger.h - leveled logger with optional ANSI colors.
 *
 * Levels (lower = more severe):
 *      LOG_ERROR       always shown unless silenced
 *      LOG_WARN        shown at WARN and above
 *      LOG_INFO        shown at INFO and above
 *      LOG_DEBUG       shown at DEBUG only
 *
 * The current threshold is process-global. Set it once at startup
 * (typically from a CLI flag) via logger_set_level().
 *
 * Output:
 *      ERROR / WARN -> stderr
 *      DEBUG / INFO -> stdout
 *
 * Colors are auto-detected: enabled if the relevant stream is a TTY.
 * Override with logger_set_color(LOGGER_COLOR_{AUTO,ON,OFF}) if needed.
 * (e.g. force-on inside a pipeline, force-off in CI).
 */

typedef enum {
        LOG_ERROR = 0,
        LOG_WARN  = 1,
        LOG_INFO  = 2,
        LOG_DEBUG = 3,
} LogLevel;

typedef enum {
        LOGGER_COLOR_AUTO = 0,
        LOGGER_COLOR_ON   = 1,
        LOGGER_COLOR_OFF  = 2,
} LoggerColorMode;

void     logger_set_color(LoggerColorMode mode);
void     logger_set_level(LogLevel level);
LogLevel logger_get_level(void);

/*
 * Parses a level string ("error", "warn", "info", "debug") into *out.
 * Case-insensitive. Returns true on success, false on unknown input.
 */
#include <stdbool.h>
bool logger_parse_level(const char *s, LogLevel *out);

void log_error(const char *fmt, ...);
void log_warn (const char *fmt, ...);
void log_info (const char *fmt, ...);
void log_debug(const char *fmt, ...);

#endif /* LOGGER_H */
