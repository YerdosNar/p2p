#include "../include/logger.h"

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>

#define C_RST "\033[0m"
#define C_RED "\033[41m"
#define C_YEL "\033[43m"
#define C_BLU "\033[44m"
#define C_GRY "\033[100m"

static LogLevel        g_level = LOG_INFO;
static LoggerColorMode g_color = LOGGER_COLOR_AUTO;

void logger_set_color(LoggerColorMode mode) { g_color = mode; }
void logger_set_level(LogLevel level)       { g_level = level; }
LogLevel logger_get_level(void)             { return g_level; }

bool logger_parse_level(const char *s, LogLevel *out)
{
        if (!s || !out) return false;
        if (!strcasecmp(s, "error")) { *out = LOG_ERROR; return true; }
        if (!strcasecmp(s, "warn"))  { *out = LOG_WARN;  return true; }
        if (!strcasecmp(s, "info"))  { *out = LOG_INFO;  return true; }
        if (!strcasecmp(s, "debug")) { *out = LOG_DEBUG; return true; }
        return false;
}

static bool use_color(FILE *stream)
{
        switch (g_color) {
        case LOGGER_COLOR_ON:  return true;
        case LOGGER_COLOR_OFF: return false;
        case LOGGER_COLOR_AUTO:
        default:               return (bool)isatty(fileno(stream));
        }
}

/*
 * Prints "[tag] " then the user message, with
 * color codes if appropriate. Always appends a newline so callers
 * don't have to remember "\n" - and so output stays line-aligned
 * even when a future caller forgets.
 *
 * ERROR/WARN go to stderr; INFO/DEBUG go to stdout. This means
 * `./rendezvous > log.txt` puts errors on the terminal where the user
 * can see them, and informational chatter in the file.
 */
static void emit(FILE *stream, const char *color, const char *tag,
                 const char *fmt, va_list ap)
{
        if (use_color(stream)) {
                fprintf(stream, "%s[%s]%s ", color, tag, C_RST);
        } else {
                fprintf(stream, "[%s] ", tag);
        }
        vfprintf(stream, fmt, ap);
        fputc('\n', stream);
        fflush(stream);
}

void log_error(const char *fmt, ...)
{
        if (g_level < LOG_ERROR) return; // kept for consistency
        va_list ap; va_start(ap, fmt);
        emit(stderr, C_RED, "x", fmt, ap);
        va_end(ap);
}

void log_warn(const char *fmt, ...)
{
        if (g_level < LOG_WARN) return;
        va_list ap; va_start(ap, fmt);
        emit(stderr, C_YEL, "!", fmt, ap);
        va_end(ap);
}

void log_info(const char *fmt, ...)
{
        if (g_level < LOG_INFO) return;
        va_list ap; va_start(ap, fmt);
        emit(stdout, C_BLU, "i", fmt, ap);
        va_end(ap);
}

void log_debug(const char *fmt, ...)
{
        if (g_level < LOG_DEBUG) return;
        va_list ap; va_start(ap, fmt);
        emit(stdout, C_GRY, "d", fmt, ap);
        va_end(ap);
}
