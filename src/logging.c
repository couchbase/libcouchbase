#include "settings.h"
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>

static hrtime_t start_time = 0;

/**
 * Return a string representation of the severity level
 */
static const char * level_to_string(int severity)
{
    switch (severity) {
    case LCB_LOG_TRACE:
        return "TRACE";
    case LCB_LOG_DEBUG:
        return "DEBUG";
    case LCB_LOG_INFO:
        return "INFO";
    case LCB_LOG_WARN:
        return "WARN";
    case LCB_LOG_ERROR:
        return "ERROR";
    case LCB_LOG_FATAL:
        return "FATAL";
    default:
        return "";
    }
}

/**
 * Default logging callback for the verbose logger.
 */
static void verbose_log(struct lcb_logprocs_st *procs,
                        const char *subsys,
                        int severity,
                        const char *srcfile,
                        int srcline,
                        const char *fmt,
                        va_list ap)
{

    hrtime_t now;
    if (!start_time) {
        start_time = gethrtime();
    }

    now = gethrtime();
    if (now == start_time) {
        now++;
    }

    fprintf(stderr, "%lums ", (unsigned long)(now - start_time) / 1000000);

    fprintf(stderr, "[%s] (%s - L:%d) ",
            level_to_string(severity),
            subsys,
            srcline);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    (void)procs;
    (void)srcfile;
}

struct lcb_logprocs_st lcb_verbose_logprocs = {
        0 /* version */,

        {
                {
                        verbose_log
                } /* v1 */
        } /*v*/
};


LCB_INTERNAL_API
void lcb_log(const struct lcb_settings_st *settings,
             const char *subsys,
             int severity,
             const char *srcfile,
             int srcline,
             const char *fmt,
             ...)
{
    va_list ap;
    lcb_logging_callback callback;

    if (!settings->logger) {
        return;
    }

    if (settings->logger->version != 0) {
        return;
    }

    callback = settings->logger->v.v0.callback;

    va_start(ap, fmt);
    callback(settings->logger, subsys, severity, srcfile, srcline, fmt, ap);
    va_end(ap);
}
