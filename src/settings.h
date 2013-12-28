#ifndef LCB_SETTINGS_H
#define LCB_SETTINGS_H

#define LCB_DEFAULT_TIMEOUT 2500000
#define LCB_DEFAULT_CONFIGURATION_TIMEOUT 5000000
#define LCB_DEFAULT_VIEW_TIMEOUT 75000000
#define LCB_DEFAULT_RBUFSIZE 32768
#define LCB_DEFAULT_WBUFSIZE 32768
#define LCB_DEFAULT_DURABILITY_TIMEOUT 5000000
#define LCB_DEFAULT_DURABILITY_INTERVAL 100000
#define LCB_DEFAULT_HTTP_TIMEOUT 75000000
#define LCB_DEFAULT_CONFIG_MAXIMUM_REDIRECTS 3
#define LCB_DEFAULT_CONFIG_ERRORS_THRESHOLD 100

#include "config.h"
#include <libcouchbase/couchbase.h>

struct lcb_io_opt_st;
struct lcb_logprocs_st;
/**
 * Stateless setting structure.
 * Specifically this contains the 'environment' of the instance for things
 * which are intended to be passed around to other objects.
 */
typedef struct lcb_settings_st {
    struct lcb_io_opt_st *io;

    lcb_uint32_t views_timeout;
    lcb_uint32_t http_timeout;
    lcb_uint32_t durability_timeout;
    lcb_uint32_t durability_interval;
    lcb_uint32_t operation_timeout;
    lcb_uint32_t config_timeout;
    lcb_size_t rbufsize;
    lcb_size_t wbufsize;
    lcb_size_t weird_things_threshold;

    /** maximum redirect hops. -1 means infinite redirects */
    int max_redir;

    /** If we should randomize bootstrap nodes or not */
    int randomize_bootstrap_nodes;


    /* if non-zero, skip nodes in list that seems like not
     * configured or doesn't have the bucket needed */
    int bummer;

    /** Is IPv6 enabled */
    lcb_ipv6_t ipv6;

    char *username;
    char *password;
    char *bucket;
    char *sasl_mech_force;
    struct lcb_logprocs_st *logger;
} lcb_settings;

#endif
