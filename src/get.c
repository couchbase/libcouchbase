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

#include "internal.h"

static libcouchbase_error_t libcouchbase_single_get(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    libcouchbase_size_t nhashkey,
                                                    const void *key,
                                                    const libcouchbase_size_t nkey,
                                                    const libcouchbase_time_t *exp,
                                                    int lock);

/**
 * libcouchbase_mget use the GETQ command followed by a NOOP command to avoid
 * transferring not-found responses. All of the not-found callbacks are
 * generated implicit by receiving a successful get or the NOOP.
 *
 * @author Trond Norbye
 * @todo improve the error handling
 */
LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_mget(libcouchbase_t instance,
                                       const void *command_cookie,
                                       libcouchbase_size_t num_keys,
                                       const void *const *keys,
                                       const libcouchbase_size_t *nkey,
                                       const libcouchbase_time_t *exp)
{
    return libcouchbase_mget_by_key(instance, command_cookie, NULL, 0, num_keys,
                                    keys, nkey, exp);
}

struct server_info_st {
    int vb;
    int idx;
};

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_mget_by_key(libcouchbase_t instance,
                                              const void *command_cookie,
                                              const void *hashkey,
                                              libcouchbase_size_t nhashkey,
                                              libcouchbase_size_t num_keys,
                                              const void *const *keys,
                                              const libcouchbase_size_t *nkey,
                                              const libcouchbase_time_t *exp)
{
    libcouchbase_server_t *server = NULL;
    protocol_binary_request_noop noop;
    libcouchbase_size_t ii, *affected_servers = NULL;
    int vb, idx;
    struct server_info_st *servers = NULL;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    if (num_keys == 1) {
        return libcouchbase_single_get(instance, command_cookie, hashkey,
                                       nhashkey, keys[0], nkey[0], exp, 0);
    }

    affected_servers = calloc(instance->nservers, sizeof(libcouchbase_size_t));
    if (affected_servers == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
    }
    if (nhashkey != 0) {
        (void)vbucket_map(instance->vbucket_config, hashkey, nhashkey, &vb, &idx);
        if (idx < 0 || idx > (int)instance->nservers) {
            /* the config says that there is no server yet at that position (-1) */
            return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
        }
        server = instance->servers + idx;
        affected_servers[idx]++;
    } else {
        servers = malloc(num_keys * sizeof(struct server_info_st));
        if (servers == NULL) {
            return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
        }
        for (ii = 0; ii < num_keys; ++ii) {
            (void)vbucket_map(instance->vbucket_config, keys[ii], nkey[ii], &servers[ii].vb, &servers[ii].idx);
            if (servers[ii].idx < 0 || servers[ii].idx > (int)instance->nservers) {
                /* the config says that there is no server yet at that position (-1) */
                free(servers);
                return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
            }
            affected_servers[servers[ii].idx]++;
        }
    }

    for (ii = 0; ii < num_keys; ++ii) {
        protocol_binary_request_gat req;
        if (nhashkey == 0) {
            server = instance->servers + servers[ii].idx;
            vb = servers[ii].vb;
        }

        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey[ii]);
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.vbucket = ntohs((libcouchbase_uint16_t)vb);
        req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey[ii]));
        req.message.header.request.opaque = ++instance->seqno;

        if (!exp) {
            req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;
            libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                             sizeof(req.bytes) - 4);
        } else {
            req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GATQ;
            req.message.header.request.extlen = 4;
            req.message.body.expiration = ntohl((libcouchbase_uint32_t)exp[ii]);
            req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey[ii]) + 4);
            libcouchbase_server_start_packet(server, command_cookie, req.bytes,
                                             sizeof(req.bytes));
        }
        libcouchbase_server_write_packet(server, keys[ii], nkey[ii]);
        libcouchbase_server_end_packet(server);
    }
    free(servers);

    memset(&noop, 0, sizeof(noop));
    noop.message.header.request.magic = PROTOCOL_BINARY_REQ;
    noop.message.header.request.opcode = PROTOCOL_BINARY_CMD_NOOP;
    noop.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;

    /*
     ** We don't know which server we sent the data to, so examine
     ** where to send the noop
     */
    for (ii = 0; ii < instance->nservers; ++ii) {
        if (affected_servers[ii]) {
            server = instance->servers + ii;
            noop.message.header.request.opaque = ++instance->seqno;
            libcouchbase_server_complete_packet(server, command_cookie,
                                                noop.bytes, sizeof(noop.bytes));
            libcouchbase_server_send_packets(server);
        }
    }
    free(affected_servers);

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_getl_by_key(libcouchbase_t instance,
                                              const void *command_cookie,
                                              const void *hashkey,
                                              libcouchbase_size_t nhashkey,
                                              const void *key,
                                              libcouchbase_size_t nkey,
                                              libcouchbase_time_t *exp)
{
    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    return libcouchbase_single_get(instance, command_cookie, hashkey,
                                   nhashkey, key, nkey, exp, 1);

}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_getl(libcouchbase_t instance,
                                       const void *command_cookie,
                                       const void *key,
                                       libcouchbase_size_t nkey,
                                       libcouchbase_time_t *exp)
{
    return libcouchbase_getl_by_key(instance, command_cookie, NULL, 0, key,
                                    nkey, exp);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_unlock_by_key(libcouchbase_t instance,
                                                const void *command_cookie,
                                                const void *hashkey,
                                                libcouchbase_size_t nhashkey,
                                                const void *key,
                                                libcouchbase_size_t nkey,
                                                libcouchbase_cas_t cas)
{
    libcouchbase_server_t *server;
    protocol_binary_request_no_extras req;
    int vb, idx;

    if (nhashkey == 0) {
        nhashkey = nkey;
        hashkey = key;
    }
    (void)vbucket_map(instance->vbucket_config, hashkey, nhashkey, &vb, &idx);
    if (idx < 0 || idx > (int)instance->nservers) {
        /* the config says that there is no server yet at that position (-1) */
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
    }
    server = instance->servers + idx;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.vbucket = ntohs((libcouchbase_uint16_t)vb);
    req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey));
    req.message.header.request.cas = cas;
    req.message.header.request.opaque = ++instance->seqno;
    req.message.header.request.opcode = CMD_UNLOCK_KEY;

    libcouchbase_server_start_packet(server, command_cookie, req.bytes, sizeof(req.bytes));
    libcouchbase_server_write_packet(server, key, nkey);
    libcouchbase_server_end_packet(server);
    libcouchbase_server_send_packets(server);

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_unlock(libcouchbase_t instance,
                                         const void *command_cookie,
                                         const void *key,
                                         libcouchbase_size_t nkey,
                                         libcouchbase_cas_t cas)
{
    return libcouchbase_unlock_by_key(instance, command_cookie, NULL, 0, key,
                                      nkey, cas);
}

static libcouchbase_error_t libcouchbase_single_get(libcouchbase_t instance,
                                                    const void *command_cookie,
                                                    const void *hashkey,
                                                    libcouchbase_size_t nhashkey,
                                                    const void *key,
                                                    const libcouchbase_size_t nkey,
                                                    const libcouchbase_time_t *exp,
                                                    int lock)
{
    libcouchbase_server_t *server;
    protocol_binary_request_gat req;
    int vb, idx, ii;
    libcouchbase_size_t nbytes;

    if (nhashkey == 0) {
        nhashkey = nkey;
        hashkey = key;
    }
    (void)vbucket_map(instance->vbucket_config, hashkey, nhashkey, &vb, &idx);
    if (idx < 0 || idx > (int)instance->nservers) {
        /* the config says that there is no server yet at that position (-1) */
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
    }
    server = instance->servers + idx;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.vbucket = ntohs((libcouchbase_uint16_t)vb);
    req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey));
    req.message.header.request.opaque = ++instance->seqno;

    if (!exp) {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;
        nbytes = sizeof(req.bytes) - 4;
    } else {
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_GAT;
        req.message.header.request.extlen = 4;
        req.message.body.expiration = ntohl((libcouchbase_uint32_t)exp[0]);
        req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(nkey) + 4);
        nbytes = sizeof(req.bytes);
    }
    if (lock) {
        /* the expiration is optional for GETL command */
        req.message.header.request.opcode = CMD_GET_LOCKED;
    }
    libcouchbase_server_start_packet(server, command_cookie, req.bytes, nbytes);
    libcouchbase_server_write_packet(server, key, nkey);
    libcouchbase_server_end_packet(server);
    libcouchbase_server_send_packets(server);

    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_get_replica_by_key(libcouchbase_t instance,
                                                     const void *command_cookie,
                                                     const void *hashkey,
                                                     libcouchbase_size_t nhashkey,
                                                     libcouchbase_size_t num_keys,
                                                     const void *const *keys,
                                                     const libcouchbase_size_t *nkey)
{
    libcouchbase_server_t *server;
    protocol_binary_request_get req;
    int vb, idx;
    libcouchbase_size_t ii, *affected_servers = NULL;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_ETMPFAIL);
    }

    affected_servers = calloc(instance->nservers, sizeof(libcouchbase_size_t));
    if (affected_servers == NULL) {
        return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_CLIENT_ENOMEM);
    }
    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.opcode = CMD_GET_REPLICA;
    for (ii = 0; ii < num_keys; ++ii) {
        if (nhashkey == 0) {
            nhashkey = nkey[ii];
            hashkey = keys[ii];
        }
        vb = vbucket_get_vbucket_by_key(instance->vbucket_config, hashkey, nhashkey);
        idx = vbucket_get_replica(instance->vbucket_config, vb, 0);
        if (idx < 0 || idx > (int)instance->nservers) {
            /* the config says that there is no server yet at that position (-1) */
            free(affected_servers);
            return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_NETWORK_ERROR);
        }
        affected_servers[idx]++;
        server = instance->servers + idx;
        req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey[ii]);
        req.message.header.request.vbucket = ntohs((libcouchbase_uint16_t)vb);
        req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)nkey[ii]);
        req.message.header.request.opaque = ++instance->seqno;
        libcouchbase_server_start_packet(server, command_cookie, req.bytes, sizeof(req.bytes));
        libcouchbase_server_write_packet(server, keys[ii], nkey[ii]);
        libcouchbase_server_end_packet(server);
    }

    for (ii = 0; ii < instance->nservers; ++ii) {
        if (affected_servers[ii]) {
            server = instance->servers + ii;
            libcouchbase_server_send_packets(server);
        }
    }

    free(affected_servers);
    return libcouchbase_synchandler_return(instance, LIBCOUCHBASE_SUCCESS);
}

LIBCOUCHBASE_API
libcouchbase_error_t libcouchbase_get_replica(libcouchbase_t instance,
                                              const void *command_cookie,
                                              libcouchbase_size_t num_keys,
                                              const void *const *keys,
                                              const libcouchbase_size_t *nkey)
{
    return libcouchbase_get_replica_by_key(instance, command_cookie,
                                           NULL, 0, num_keys, keys, nkey);
}
