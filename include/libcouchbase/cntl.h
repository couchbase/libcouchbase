/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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
 * Command codes for libcouchbase.
 * These codes may be passed to 'lcb_cntl'.
 *
 * Note that the constant values are also public API; thus allowing forwards
 * and backwards compatibility.
 */

#ifndef LCB_CNTL_H
#define LCB_CNTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define LCB_CNTL_SET 0x01
#define LCB_CNTL_GET 0x00

    /**
     * Get/Set. Operation timeout.
     * Arg: lcb_uint32_t* (microseconds)
     *
     *      lcb_uint32_t tmo = 3500000;
     *      lcb_cntl(instance, LCB_CNTL_SET, LCB_CNTL_OP_TIMEOUT, &tmo);
     */
#define LCB_CNTL_OP_TIMEOUT             0x00

    /**
     * Get/Set. View timeout.
     * Arg: lcb_uint32_t* (microseconds)
     */
#define LCB_CNTL_VIEW_TIMEOUT           0x01

    /**
     * Get/Set. Default read buffer size (this is not a socket option)
     * Arg: lcb_size_t*
     */
#define LCB_CNTL_RBUFSIZE               0x02

    /**
     * Get/Set. Default write buffer size (this is not a socket option)
     * Arg: lcb_size_t*
     */
#define LCB_CNTL_WBUFSIZE               0x03

    /**
     * Get the handle type.
     * Arg: lcb_type_t*
     */
#define LCB_CNTL_HANDLETYPE             0x04

    /**
     * Get the vBucket handle
     * Arg: VBUCKET_CONFIG_HANDLE*
     */
#define LCB_CNTL_VBCONFIG               0x05


    /**
     * Get the iops implementation instance
     * Arg: lcb_io_opt_t*
     */
#define LCB_CNTL_IOPS                   0x06

    typedef struct lcb_cntl_vbinfo_st lcb_cntl_vbinfo_t;
    struct lcb_cntl_vbinfo_st {
        int version;

        union {
            struct {
                /** Input parameters */
                const void *key;
                lcb_size_t nkey;
                /** Output */
                int vbucket;
                int server_index;
            } v0;
        } v;
    };
    /**
     * Get the vBucket ID for a given key, based on the current configuration
     * Arg: A lcb_cntl_vbinfo_t*. The 'vbucket' field in he structure will
     *      be modified
     */
#define LCB_CNTL_VBMAP                  0x07


    typedef struct lcb_cntl_server_st lcb_cntl_server_t;
    struct lcb_cntl_server_st {
        /** Structure version */
        int version;

        union {

            struct {
                /** Server index to query */
                int index;

                /** NUL-terminated string containing the address */
                const char *host;
                /** NUL-terminated string containing the port */
                const char *port;
                /** Whether the node is connected */
                int connected;

                /**
                 * Socket information. If a v0 IO plugin is being used, the sockfd
                 * is set to the socket descriptor. If a v1 plugin is being used, the
                 * sockptr is set to point to the appropriate structure.
                 *
                 * Note that you *MAY* perform various 'setsockopt' calls on the
                 * sockfd (though it is your responsibility to ensure those options
                 * are valid); however the actual socket descriptor may change
                 * in the case of a cluster configuration update.
                 */
                union {
                    lcb_socket_t sockfd;
                    lcb_sockdata_t *sockptr;
                } sock;
            } v0;
        } v;
    };

    /**
     * Get information about a memcached node.
     * Arg: A struct lcb_cntl_server_st*. Note that all fields in this structure
     *      are ready only and are only valid until one of the following happens:
     *          1) Another libcouchbase API function is called
     *          2) The IOPS loop regains control
     */
#define LCB_CNTL_MEMDNODE_INFO          0x08

    /**
     * Get information about the configuration node.
     * Arg: A struct lcb_cntl_server_st*. Semantics of MEMDNODE_INFO apply here
     *      as well.
     */
#define LCB_CNTL_CONFIGNODE_INFO        0x09

    /**
     * Get/Set the "syncmode" behavior
     * Arg: lcb_syncmode_t*
     */
#define LCB_CNTL_SYNCMODE               0x0a

    /**
     * Get/Set IPv4/IPv6 selection policy
     * Arg: lcb_ipv6_t*
     */
#define LCB_CNTL_IP6POLICY              0x0b

    /**
     * Get/Set the configuration error threshold. This number indicates how many
     * network/mapping/not-my-vbucket errors are received before a configuration
     * update is requested again.
     *
     * Arg: lcb_size_t*
     */
#define LCB_CNTL_CONFERRTHRESH          0x0c

    /**
     * Get/Set the default durability timeout. This is the time the client will
     * spend sending repeated probes to a given key's vBucket masters and replicas
     * before they are deemed not to have satisfied the durability requirements
     *
     * Arg: lcb_uint32_t*
     */
#define LCB_CNTL_DURABILITY_TIMEOUT     0x0d

    /**
     * Get/Set the default durability interval. This is the time the client will
     * wait between repeated probes to a given server. Note that this is usually
     * auto-estimated based on the servers' given 'ttp' and 'ttr' fields reported
     * with an OBSERVE response packet.
     *
     * Arg: lcb_uint32_t*
     */
#define LCB_CNTL_DURABILITY_INTERVAL    0x0e

    /**
     * Get/Set the default timeout for *non-view* HTTP requests.
     * Arg: lcb_uint32_t*
     */
#define LCB_CNTL_HTTP_TIMEOUT           0x0f

    struct lcb_cntl_iops_info_st {
        int version;
        union {
            struct {
                /**
                 * Pass here options, used to create IO structure with
                 * lcb_create_io_ops(3), to find out whether the library
                 * will override them in the current environment
                 */
                const struct lcb_create_io_ops_st *options;

                /**
                 * The default IO ops type. This is hard-coded into the library
                 * and is used if nothing else was specified in creation options
                 * or the environment
                 */
                lcb_io_ops_type_t os_default;

                /**
                 * The effective plugin type after reading environment variables.
                 * If this is set to 0, then a manual (non-builtin) plugin has been
                 * specified.
                 */
                lcb_io_ops_type_t effective;
            } v0;
        } v;
    };

    /**
     * Get the default IOPS types for this build. This provides a convenient
     * way to determine what libcouchbase will use for IO when not explicitly
     * specifying an iops structure to lcb_create()
     *
     * Arg: struct lcb_cntl_io_ops_info_st*
     * NOTE: Pass NULL to lcb_cntl for the 'instance' parameter, as this does not
     * read anything specific on the handle
     */
#define LCB_CNTL_IOPS_DEFAULT_TYPES      0x10

    /**
     * Get/Set the global setting (this is a static global) regarding whether to
     * print verbose information when trying to dynamically load an IO plugin.
     * The information printed can be useful in determining why a plugin failed
     * to load. This setting can also be controlled via the
     * "LIBCOUCHBASE_DLOPEN_DEBUG" environment variable (and if enabled from the
     * environment, will override the setting mentioned here).
     *
     * Arg: int*
     * NOTE: Pass NULL to lcb_cntl for the 'instance' parameter.
     */
#define LCB_CNTL_IOPS_DLOPEN_DEBUG       0x11

    /** This is not a command, but rather an indicator of the last item */
#define LCB_CNTL__MAX                    0x12


#ifdef __cplusplus
}
#endif
#endif /* LCB_CNTL_H */
