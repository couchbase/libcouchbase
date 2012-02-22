/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010, 2011 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * Internal functions for debugging
 *
 * XXX: The API contained herein is subject to change. Do not rely on
 * any of this to persist between versions yet. The main purpose for
 * the debugging modules is currently to test your own code, and it is
 * expected that they be removed when the code is confirmed working.
 *
 * @author M. Nunberg
 */

/**
 * The following preprocessor variables can be defined to control
 * various levels of developer logging
 *
 * LIBCOUCHBASE_DEBUG enables 'explicit' debugging functions, meaning
 * debug functions are fully qualified and must include an instance as
 * the first argument.  debugging is done via libcouchbase_<level>
 * where level is one of {trace,debug,info,warn,err,crit}
 *
 * LIBCOUCHBASE_DEBUG_NOCTX enables shorthand debugging
 * functions. These are intended for use by developers and
 * contributors wishing to debug changes and are not intended for
 * shipping with commited code. The calling convention assumes an
 * implicit global variable with extern linkage and strips the
 * libcouchbase_ namespace from the function, replacing it with log_
 *
 * Debugging output is prefixed with a title, which may be set in the
 * debug_st structure.  If the macro LIBCOUCHBASE_DEBUG_STATIC_CTX is
 * defined, then instead of using a global debug_st with extern
 * linkage, each participating file would be expected to have defined
 * an implicit file-scoped debug_st using the
 * LIBCOUCHBASE_DEBUG_STATIC_INIT(prefix,level) macro.
 *
 * By default none of these macros are enabled and all debugging
 * functions and/or symbols are noops
 */

#ifndef LIBCOUCHBASE_DEBUG_H
#define LIBCOUCHBASE_DEBUG_H

#include <memcached/protocol_binary.h>
#include <stdio.h>

/**
 * Enable access and declarations of our global identifiers. This cannot hurt
 */
typedef enum {
    LIBCOUCHBASE_LOGLVL_ALL = 0,
    LIBCOUCHBASE_LOGLVL_TRACE,
    LIBCOUCHBASE_LOGLVL_DEBUG,
    LIBCOUCHBASE_LOGLVL_INFO,
    LIBCOUCHBASE_LOGLVL_WARN,
    LIBCOUCHBASE_LOGLVL_ERROR,
    LIBCOUCHBASE_LOGLVL_CRIT,
    LIBCOUCHBASE_LOGLVL_NONE
} libcouchbase_loglevel_t;

#define LIBCOUCHBASE_LOGLVL_MAX LIBCOUCHBASE_LOGLVL_CRIT

typedef struct {
    /*The 'title'*/
    char *prefix;

    /*The minimum level allowable*/
    libcouchbase_loglevel_t level;

    /*Whether color is enabled*/
    int color;

    /*Output stream*/
    FILE *out;

    /*Set internally when this structure has been initialized*/
    int initialized;
} libcouchbase_debug_st;

/* Environment variables to control setting debug parameters */

/* If set to an integer, the integer is taken as the minimum allowable
 * output level.  If set to -1, then all levels are enabled
 */
#define LIBCOUCHBASE_DEBUG_ENV_ENABLE "LIBCOUCHBASE_DEBUG"

/*
 * Format log messages by color coding them according to their severity
 * using ANSI escape sequences
 */
#define LIBCOUCHBASE_DEBUG_ENV_COLOR_ENABLE "LIBCOUCHBASE_DEBUG_COLORS"

/*
 * Allow code to dump packet headers
 */
#define LIBCOUCHBASE_DEBUG_ENV_HEADERS_ENABLE "LIBCOUCHBASE_DUMP_HEADERS"

/*
 * Allow code to dump packet bodies
 */
#define LIBCOUCHBASE_DEBUG_ENV_PACKET_ENABLE "LIBCOUCHBASE_DUMP_PACKETS"


/**
 * Returns a string representation of the requested opcode, or NULL if
 * not found
 */
const char *libcouchbase_stropcode(libcouchbase_uint8_t opcode);

/**
 * Returns the string representation of a packet's  'magic' field, or NULL
 */
const char *libcouchbase_strmagic(libcouchbase_uint8_t magic);

/**
 * returns a string representation of the packet's response status, or NULL
 */
const char *libcouchbase_strstatus(libcouchbase_uint16_t status);


/**
 * Writes a textual representation of the packet (header)
 * stored in bytes, which is nbytes long into dst, which is ndst long.
 *
 * dst should be large enough to hold the textual representation,
 * including a terminating NULL byte.
 *
 * Returns the amount of bytes written to dst.
 */
libcouchbase_size_t libcouchbase_strpacket(char *dst,
                                           libcouchbase_size_t ndst,
                                           const void *bytes,
                                           libcouchbase_size_t nbytes);

#if defined LIBCOUCHBASE_DEBUG_NOCTX && !defined LIBCOUCHBASE_DEBUG
#define LIBCOUCHBASE_DEBUG
#endif /*LIBCOUCHBASE_DEBUG_NOCTX*/


#ifdef LIBCOUCHBASE_DEBUG


/**
 * this structure contains a nice title and optional level threshold.
 * do not instantiate or access explicitly. Use provided functions/macros
 */

/**
 * Core logging function
 */
void libcouchbase_logger(libcouchbase_debug_st *logparams,
                         libcouchbase_loglevel_t level,
                         int line,
                         const char *fn,
                         const char *fmt, ...);

/**
 * print a formatted description of a packet header
 */
void libcouchbase_dump_header(const void *data, libcouchbase_size_t nbytes);

/**
 * print a dump of the entire packet. If 'payload' is NULL, and nheader
 * is larger than header (and estimated to be the size of the entire packet)
 * then the header will be assumed to be the body itself.
 */
void libcouchbase_dump_packet(const void *header, libcouchbase_size_t nheader,
                              const void *payload, libcouchbase_size_t npayload);

/**
 * print a hex dump of data
 */
void libcouchbase_hex_dump(const void *data, libcouchbase_size_t nbytes);

#define LIBCOUCHBASE_LOG_IMPLICIT(debugp, lvl_base, fmt, ...) \
        libcouchbase_logger(debugp, LIBCOUCHBASE_LOGLVL_ ## lvl_base, \
                            __LINE__, __func__, \
                            fmt, ## __VA_ARGS__)


#define LIBCOUCHBASE_LOG_EXPLICIT(instance, lvl_base, fmt, ...) \
        LIBCOUCHBASE_LOG_IMPLICIT(instance->debug, lvl_base, fmt, ## __VA_ARGS__ )


/**
 * the following functions send a message of the specified level to
 * the debug logging system. These are noop if libcouchbase was not
 * compiled with debugging.
 */
#define libcouchbase_trace(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, TRACE, fmt,  ## __VA_ARGS__)

#define libcouchbase_info(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, INFO, fmt,  ## __VA_ARGS__)

#define libcouchbase_debug(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, DEBUG, fmt,  ## __VA_ARGS__)

#define libcouchbase_warn(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, WARN, fmt,  ## __VA_ARGS__)

#define libcouchbase_err(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, ERROR, fmt, ## __VA_ARGS__)

#define libcouchbase_crit(instance, fmt, ...) \
    LIBCOUCHBASE_LOG_EXPLICIT(instance, CRIT, fmt, ## __VA_ARGS__)


#ifdef LIBCOUCHBASE_DEBUG_NOCTX

/**
 * These define implicit per-binary and per-object names
 */

#define LIBCOUCHBASE_LOG_PRIV_NAME libcouchbase_log__Static_Debug_Params
#define LIBCOUCHBASE_LOG_GLOBAL_NAME libcouchbase_log__Global_Debug_Params

#ifdef LIBCOUCHBASE_DEBUG_STATIC_CTX
#define LIBCOUCHBASE_DEBUG_STATIC_INIT(prefix, lvl) \
    static libcouchbase_debug_st LIBCOUCHBASE_LOG_PRIV_NAME = \
        { prefix, lvl, -1, NULL, 0 };

#define LIBCOUCHBASE_LOG_IMPLICIT_NAME LIBCOUCHBASE_LOG_PRIV_NAME

#else

#define LIBCOUCHBASE_LOG_IMPLICIT_NAME LIBCOUCHBASE_LOG_GLOBAL_NAME
extern libcouchbase_debug_st LIBCOUCHBASE_LOG_IMPLICIT_NAME;
#define LIBCOUCHBASE_DEBUG_STATIC_INIT

#endif /*LIBCOUCHBASE_DEBUG_STATIC_CTX*/

#define log_trace(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, TRACE, fmt, ## __VA_ARGS__)

#define log_debug(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, DEBUG, fmt, ## __VA_ARGS__)

#define log_info(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, INFO, fmt, ## __VA_ARGS__)

#define log_warn(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, WARN, fmt, ## __VA_ARGS__)

#define log_err(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, ERROR, fmt, ## __VA_ARGS__)

#define log_crit(fmt, ...) \
    LIBCOUCHBASE_LOG_IMPLICIT(&LIBCOUCHBASE_LOG_GLOBAL_NAME, CRIT, fmt, ## __VA_ARGS__)

#endif /*LIBCOUCHBASE_DEBUG_NOCTX*/

#else

#define libcouchbase_logger
#define libcouchbase_dump_header
#define libcouchbase_dump_packet
#define libcouchbase_hex_dump

#define libcouchbase_info
#define libcouchbase_debug
#define libcouchbase_warn
#define libcouchbase_err
#define libcouchbase_crit
#endif /* LIBCOUCHBASE_DEBUG */


/**
 * If debugging is enabled, but implicit debugging is not, then supply
 * the noop macros
 */
#ifndef LIBCOUCHBASE_DEBUG_NOCTX
#define log_trace
#define log_debug
#define log_info
#define log_warn
#define log_err
#define log_crit
#endif /*LIBCOUCHBASE_DEBUG_NOCTX*/

#ifndef LIBCOUCHBASE_DEBUG_STATIC_INIT
#define LIBCOUCHBASE_DEBUG_STATIC_INIT
#endif /*LIBCOUCHBASE_DEBUG_STATIC_INIT*/

#endif /* LIBCOUCHBASE_DEBUG_H */
