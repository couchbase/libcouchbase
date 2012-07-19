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
 * This file contains the implementations of the callback handlers
 * fired when a packet is received on the wire.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

static libcouchbase_error_t map_error(protocol_binary_response_status in)
{
    switch (in) {
    case PROTOCOL_BINARY_RESPONSE_SUCCESS:
        return LIBCOUCHBASE_SUCCESS;
    case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
        return LIBCOUCHBASE_KEY_ENOENT;
    case PROTOCOL_BINARY_RESPONSE_E2BIG:
        return LIBCOUCHBASE_E2BIG;
    case PROTOCOL_BINARY_RESPONSE_ENOMEM:
        return LIBCOUCHBASE_ENOMEM;
    case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
        return LIBCOUCHBASE_KEY_EEXISTS;
    case PROTOCOL_BINARY_RESPONSE_EINVAL:
        return LIBCOUCHBASE_EINVAL;
    case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
        return LIBCOUCHBASE_NOT_STORED;
    case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
        return LIBCOUCHBASE_DELTA_BADVAL;
    case PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET:
        return LIBCOUCHBASE_NOT_MY_VBUCKET;
    case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
        return LIBCOUCHBASE_AUTH_ERROR;
    case PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE:
        return LIBCOUCHBASE_AUTH_CONTINUE;
    case PROTOCOL_BINARY_RESPONSE_ERANGE:
        return LIBCOUCHBASE_ERANGE;
    case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
        return LIBCOUCHBASE_UNKNOWN_COMMAND;
    case PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED:
        return LIBCOUCHBASE_NOT_SUPPORTED;
    case PROTOCOL_BINARY_RESPONSE_EINTERNAL:
        return LIBCOUCHBASE_EINTERNAL;
    case PROTOCOL_BINARY_RESPONSE_EBUSY:
        return LIBCOUCHBASE_EBUSY;
    case PROTOCOL_BINARY_RESPONSE_ETMPFAIL:
        return LIBCOUCHBASE_ETMPFAIL;
    default:
        return LIBCOUCHBASE_ERROR;

    }
}


static void dummy_request_handler(libcouchbase_server_t *server,
                                  struct libcouchbase_command_data_st *command_data,
                                  protocol_binary_request_header *req)
{
    (void)server;
    (void)req;
    (void)command_data;
#ifdef DEBUG
    fprintf(stderr, "Received request packet %02x\n", req->request.opcode);
#endif
}

static void dummy_response_handler(libcouchbase_server_t *server,
                                   struct libcouchbase_command_data_st *command_data,
                                   protocol_binary_response_header *res)
{
#ifdef DEBUG
    fprintf(stderr, "Received response packet %02x %04x\n",
            res->response.opcode, ntohs(res->response.status));
#endif
    (void)server;
    (void)res;
    (void)command_data;
}

/**
 * Get a pointer to the key. If the buffer isn't continous we need to
 * allocate a temporary chunk of memory and copy the packet over there.
 * packet will return the pointer to the newly allocated packet or
 * NULL if we didn't have to allocate anything.
 *
 * @param server the server owning the key
 * @param nkey the number of bytes in the key
 * @param packet where to store the result
 * @return pointer to the key
 */
static const char *get_key(libcouchbase_server_t *server, libcouchbase_uint16_t *nkey,
                           char **packet)
{
    protocol_binary_request_header req;
    libcouchbase_size_t nr = ringbuffer_peek(&server->cmd_log,
                                             req.bytes, sizeof(req));
    libcouchbase_size_t packetsize = ntohl(req.request.bodylen) + (libcouchbase_uint32_t)sizeof(req);
    char *keyptr;
    *packet = server->cmd_log.read_head;
    assert(nr == sizeof(req));

    *nkey = ntohs(req.request.keylen);
    keyptr = *packet + sizeof(req) + req.request.extlen;
    *packet = NULL;

    if (!ringbuffer_is_continous(&server->cmd_log,
                                 RINGBUFFER_READ,
                                 packetsize)) {
        *packet = malloc(packetsize);
        if (*packet == NULL) {
            libcouchbase_error_handler(server->instance, LIBCOUCHBASE_CLIENT_ENOMEM,
                                       NULL);
            return NULL;
        }

        nr = ringbuffer_peek(&server->cmd_log, *packet, packetsize);
        if (nr != packetsize) {
            libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                       NULL);
            free(*packet);
            return NULL;
        }
        keyptr = *packet + sizeof(req) + req.request.extlen;
    }

    return keyptr;
}

int libcouchbase_lookup_server_with_command(libcouchbase_t instance,
                                            libcouchbase_uint8_t opcode,
                                            libcouchbase_uint32_t opaque,
                                            libcouchbase_server_t *exc)
{
    protocol_binary_request_header cmd;
    libcouchbase_server_t *server;
    libcouchbase_size_t nr, ii;

    for (ii = 0; ii < instance->nservers; ++ii) {
        server = instance->servers + ii;
        nr = ringbuffer_peek(&server->cmd_log, cmd.bytes, sizeof(cmd));
        if (nr == sizeof(cmd) &&
                cmd.request.opcode == opcode &&
                cmd.request.opaque == opaque &&
                server != exc) {
            return (int)ii;
        }
    }
    return -1;
}

static void release_key(libcouchbase_server_t *server, char *packet)
{
    /*
     * Packet is a NIL pointer if we didn't allocate a temporary
     * object.
     */
    free(packet);
    (void)server;
}

static void getq_response_handler(libcouchbase_server_t *server,
                                  struct libcouchbase_command_data_st *command_data,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_response_getq *getq = (void *)res;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    libcouchbase_size_t nbytes = ntohl(res->response.bodylen);
    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    nbytes -= res->response.extlen;
    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        return;
    } else if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        const char *bytes = (const char *)res;
        bytes += sizeof(getq->bytes);
        root->callbacks.get(root, command_data->cookie, LIBCOUCHBASE_SUCCESS,
                            key, nkey, bytes, nbytes,
                            ntohl(getq->message.body.flags),
                            res->response.cas);
    } else {
        root->callbacks.get(root, command_data->cookie, map_error(status), key, nkey,
                            NULL, 0, 0, 0);
    }
    release_key(server, packet);
}

static void get_replica_response_handler(libcouchbase_server_t *server,
                                         struct libcouchbase_command_data_st *command_data,
                                         protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_response_get *get = (void *)res;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    libcouchbase_uint16_t nkey = ntohs(res->response.keylen);
    const char *key = (const char *)res;

    key += sizeof(get->bytes);
    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        return;
    } else if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        const char *bytes = key + nkey;
        libcouchbase_size_t nbytes = ntohl(res->response.bodylen) - nkey - res->response.extlen;
        root->callbacks.get(root, command_data->cookie, LIBCOUCHBASE_SUCCESS,
                            key, nkey, bytes, nbytes,
                            ntohl(get->message.body.flags),
                            res->response.cas);
    } else {
        if (status == PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET) {
            /* the config was updated, start from first replica */
            command_data->replica = 0;
        } else {
            command_data->replica++;
        }
        if (command_data->replica < root->nreplicas) {
            /* try next replica */
            protocol_binary_request_get req;
            int idx = vbucket_get_replica(root->vbucket_config, command_data->vbucket, 0);
            if (idx < 0 || idx > (int)root->nservers) {
                libcouchbase_error_handler(root, LIBCOUCHBASE_NETWORK_ERROR,
                                           "GET_REPLICA: missing server");
                return;
            }
            server = root->servers + idx;
            memset(&req, 0, sizeof(req));
            req.message.header.request.magic = PROTOCOL_BINARY_REQ;
            req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
            req.message.header.request.opcode = CMD_GET_REPLICA;
            req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)nkey);
            req.message.header.request.vbucket = ntohs(command_data->vbucket);
            req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)nkey);
            req.message.header.request.opaque = ++root->seqno;
            libcouchbase_server_retry_packet(server, &command_data,
                                             req.bytes, sizeof(req.bytes));
            libcouchbase_server_write_packet(server, key, nkey);
            libcouchbase_server_end_packet(server);
            libcouchbase_server_send_packets(server);
        } else {
            /* give up and report the error */
            root->callbacks.get(root, command_data->cookie,
                                map_error(status), key, nkey,
                                NULL, 0, 0, 0);
        }
    }
}

static void delete_response_handler(libcouchbase_server_t *server,
                                    struct libcouchbase_command_data_st *command_data,
                                    protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.remove(root, command_data->cookie, map_error(status),
                               key, nkey);
        release_key(server, packet);
    }
}

static void observe_response_handler(libcouchbase_server_t *server,
                                     struct libcouchbase_command_data_st *command_data,
                                     protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    libcouchbase_uint32_t ttp;
    libcouchbase_uint32_t ttr;
    VBUCKET_CONFIG_HANDLE config;
    const char *end, *ptr = (const char *)&res->response.cas;

    memcpy(&ttp, ptr, sizeof(ttp));
    ttp = ntohl(ttp);
    memcpy(&ttr, ptr + sizeof(ttp), sizeof(ttr));
    ttr = ntohl(ttr);

    ptr = (const char *)res + sizeof(res->bytes);
    end = ptr + ntohl(res->response.bodylen);
    config = root->vbucket_config;
    while (ptr < end) {
        libcouchbase_cas_t cas;
        libcouchbase_uint8_t obs;
        libcouchbase_uint16_t nkey, vb;
        const char *key;

        vb = ntohs(*((libcouchbase_uint16_t *)ptr));
        ptr += sizeof(vb);
        nkey = ntohs(*((libcouchbase_uint16_t *)ptr));
        ptr += sizeof(nkey);
        key = (const char *)ptr;
        ptr += nkey;
        obs = *((libcouchbase_uint8_t *)ptr);
        ptr += sizeof(obs);
        cas = *((libcouchbase_cas_t *)ptr);
        ptr += sizeof(cas);
        root->callbacks.observe(root, command_data->cookie, map_error(status),
                                obs, key, nkey, cas,
                                server->index == vbucket_get_master(config, vb),
                                ttp, ttr);
    }
    /* run callback with null-null-null to signal the end of transfer */
    if (libcouchbase_lookup_server_with_command(root, CMD_OBSERVE,
                                                res->response.opaque, server) < 0) {
        root->callbacks.observe(root, command_data->cookie, map_error(status),
                                0, NULL, 0, 0, 0, 0, 0);
    }
}

static void storage_response_handler(libcouchbase_server_t *server,
                                     struct libcouchbase_command_data_st *command_data,
                                     protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_storage_t op;

    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);


    libcouchbase_uint16_t status = ntohs(res->response.status);

    switch (res->response.opcode) {
    case PROTOCOL_BINARY_CMD_ADD:
        op = LIBCOUCHBASE_ADD;
        break;
    case PROTOCOL_BINARY_CMD_REPLACE:
        op = LIBCOUCHBASE_REPLACE;
        break;
    case PROTOCOL_BINARY_CMD_SET:
        op = LIBCOUCHBASE_SET;
        break;
    case PROTOCOL_BINARY_CMD_APPEND:
        op = LIBCOUCHBASE_APPEND;
        break;
    case PROTOCOL_BINARY_CMD_PREPEND:
        op = LIBCOUCHBASE_PREPEND;
        break;
    default:
        /*
        ** It is impossible to get here (since we're called from our
        ** lookup table... If we _DO_ get here, it must be a development
        ** version where the developer isn't done yet (and should be
        ** forced to think about what to do...)
        */
        libcouchbase_error_handler(root, LIBCOUCHBASE_EINTERNAL,
                                   "Internal error. Received an illegal command opcode");
        abort();
    }

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.storage(root, command_data->cookie, op, map_error(status),
                                key, nkey, res->response.cas);
        release_key(server, packet);
    }
}

static void arithmetic_response_handler(libcouchbase_server_t *server,
                                        struct libcouchbase_command_data_st *command_data,
                                        protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        return ;
    } else if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        libcouchbase_uint64_t value;
        memcpy(&value, res + 1, sizeof(value));
        value = ntohll(value);
        root->callbacks.arithmetic(root, command_data->cookie, LIBCOUCHBASE_SUCCESS,
                                   key, nkey, value, res->response.cas);
    } else {
        root->callbacks.arithmetic(root, command_data->cookie, map_error(status),
                                   key, nkey, 0, 0);
    }
    release_key(server, packet);
}

static void stat_response_handler(libcouchbase_server_t *server,
                                  struct libcouchbase_command_data_st *command_data,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    libcouchbase_uint16_t nkey;
    libcouchbase_uint32_t nvalue;
    const char *key, *value;

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        nkey = ntohs(res->response.keylen);
        if (nkey == 0) {
            if (libcouchbase_lookup_server_with_command(root, PROTOCOL_BINARY_CMD_STAT,
                                                        res->response.opaque, server) < 0) {
                /* notify client that data is ready */
                root->callbacks.stat(root, command_data->cookie, NULL,
                                     LIBCOUCHBASE_SUCCESS, NULL, 0, NULL, 0);
            }
            return;
        }
        key = (const char *)res + sizeof(res->bytes);
        nvalue = ntohl(res->response.bodylen) - nkey;
        value = key + nkey;
        root->callbacks.stat(root, command_data->cookie, server->authority,
                             map_error(status), key, nkey, value, nvalue);
    } else {
        root->callbacks.stat(root, command_data->cookie, server->authority,
                             map_error(status), NULL, 0, NULL, 0);

        /* run callback with null-null-null to signal the end of transfer */
        if (libcouchbase_lookup_server_with_command(root, PROTOCOL_BINARY_CMD_STAT,
                                                    res->response.opaque, server) < 0) {
            root->callbacks.stat(root, command_data->cookie, NULL,
                                 LIBCOUCHBASE_SUCCESS, NULL, 0, NULL, 0);
        }
    }
}

static void version_response_handler(libcouchbase_server_t *server,
                                     struct libcouchbase_command_data_st *command_data,
                                     protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    libcouchbase_uint32_t nvstring = ntohl(res->response.bodylen);
    const char *vstring;

    if (nvstring) {
        vstring = (const char *)res + sizeof(res->bytes);
    } else {
        vstring = NULL;
    }

    root->callbacks.version(root, command_data->cookie, server->authority, map_error(status),
                            vstring, nvstring);

    if (libcouchbase_lookup_server_with_command(root, PROTOCOL_BINARY_CMD_VERSION,
                                                res->response.opaque, server) < 0) {
        root->callbacks.version(root, command_data->cookie, NULL, LIBCOUCHBASE_SUCCESS, NULL, 0);
    }

}

static void tap_mutation_handler(libcouchbase_server_t *server,
                                 struct libcouchbase_command_data_st *command_data,
                                 protocol_binary_request_header *req)
{
    /* @todo verify that the size is correct! */
    char *packet = (char *)req;
    protocol_binary_request_tap_mutation *mutation = (void *)req;
    libcouchbase_uint32_t flags = mutation->message.body.item.flags;
    libcouchbase_time_t exp = (libcouchbase_time_t)ntohl(mutation->message.body.item.expiration);
    libcouchbase_uint16_t nkey = ntohs(req->request.keylen);

    char *es = packet + sizeof(mutation->bytes);
    libcouchbase_uint16_t nes = ntohs(mutation->message.body.tap.enginespecific_length);
    char *key = es + nes;
    void *data = key + nkey;
    libcouchbase_uint32_t nbytes = ntohl(req->request.bodylen) - req->request.extlen - nes - nkey;

    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t tap_flags = ntohs(mutation->message.body.tap.flags);

    if (tap_flags & TAP_FLAG_NETWORK_BYTE_ORDER) {
        flags = ntohl(flags);
    }

    root->callbacks.tap_mutation(root, command_data->cookie, key, nkey, data,
                                 nbytes, flags, exp, req->request.cas,
                                 ntohs(req->request.vbucket),
                                 es, nes);
}

static void tap_deletion_handler(libcouchbase_server_t *server,
                                 struct libcouchbase_command_data_st *command_data,
                                 protocol_binary_request_header *req)
{
    /* @todo verify that the size is correct! */
    char *packet = (char *)req;
    protocol_binary_request_tap_delete *deletion = (void *)req;
    libcouchbase_uint16_t nkey = ntohs(req->request.keylen);
    char *es = packet + sizeof(deletion->bytes);
    libcouchbase_uint16_t nes = ntohs(deletion->message.body.tap.enginespecific_length);
    char *key = es + nes;
    libcouchbase_t root = server->instance;
    root->callbacks.tap_deletion(root, command_data->cookie, key, nkey,
                                 req->request.cas,
                                 ntohs(req->request.vbucket), es, nes);
}

static void tap_flush_handler(libcouchbase_server_t *server,
                              struct libcouchbase_command_data_st *command_data,
                              protocol_binary_request_header *req)
{
    /* @todo verify that the size is correct! */
    char *packet = (char *)req;
    protocol_binary_request_tap_flush *flush = (void *)req;
    char *es = packet + sizeof(flush->bytes);
    libcouchbase_uint16_t nes = ntohs(flush->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_flush(root, command_data->cookie, es, nes);
}

static void tap_opaque_handler(libcouchbase_server_t *server,
                               struct libcouchbase_command_data_st *command_data,
                               protocol_binary_request_header *req)
{
    /* @todo verify that the size is correct! */
    char *packet = (char *)req;
    protocol_binary_request_tap_opaque *opaque = (void *)req;
    char *es = packet + sizeof(opaque->bytes);
    libcouchbase_uint16_t nes = ntohs(opaque->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_opaque(root, command_data->cookie, es, nes);
}

static void tap_vbucket_set_handler(libcouchbase_server_t *server,
                                    struct libcouchbase_command_data_st *command_data,
                                    protocol_binary_request_header *req)
{
    /* @todo verify that the size is correct! */
    libcouchbase_t root = server->instance;
    char *packet = (char *)req;
    protocol_binary_request_tap_vbucket_set *vbset = (void *)req;
    char *es = packet + sizeof(vbset->bytes);
    libcouchbase_uint16_t nes = ntohs(vbset->message.body.tap.enginespecific_length);
    libcouchbase_uint32_t state;
    memcpy(&state, es + nes, sizeof(state));
    state = ntohl(state);
    root->callbacks.tap_vbucket_set(root, command_data->cookie, ntohs(req->request.vbucket),
                                    (libcouchbase_vbucket_state_t)state, es, nes);
}

static void sasl_list_mech_response_handler(libcouchbase_server_t *server,
                                            struct libcouchbase_command_data_st *command_data,
                                            protocol_binary_response_header *res)
{
    const char *data;
    const char *chosenmech;
    char *mechlist;
    unsigned int len;
    protocol_binary_request_no_extras req;
    libcouchbase_size_t keylen;
    libcouchbase_size_t bodysize;

    assert(ntohs(res->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);
    bodysize = ntohl(res->response.bodylen);
    mechlist = calloc(bodysize + 1, sizeof(char));
    if (mechlist == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_CLIENT_ENOMEM, NULL);
        return;
    }
    memcpy(mechlist, (const char *)(res + 1), bodysize);
    if (sasl_client_start(server->sasl_conn, mechlist,
                          NULL, &data, &len, &chosenmech) != SASL_OK) {
        free(mechlist);
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_AUTH_ERROR,
                                   "Unable to start sasl client");
        return;
    }
    free(mechlist);

    keylen = strlen(chosenmech);
    bodysize = keylen + len;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    req.message.header.request.keylen = ntohs((libcouchbase_uint16_t)keylen);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = ntohl((libcouchbase_uint32_t)(bodysize));

    libcouchbase_server_buffer_start_packet(server, command_data->cookie, &server->output,
                                            &server->output_cookies,
                                            req.bytes, sizeof(req.bytes));
    libcouchbase_server_buffer_write_packet(server, &server->output,
                                            chosenmech, keylen);
    libcouchbase_server_buffer_write_packet(server, &server->output, data, len);
    libcouchbase_server_buffer_end_packet(server, &server->output);

    /* send the data and add a write handler */
    libcouchbase_server_event_handler(0, LIBCOUCHBASE_WRITE_EVENT, server);

    /* Make it known that this was a success. */
    libcouchbase_error_handler(server->instance, LIBCOUCHBASE_SUCCESS, NULL);
}

static void sasl_auth_response_handler(libcouchbase_server_t *server,
                                       struct libcouchbase_command_data_st *command_data,
                                       protocol_binary_response_header *res)
{
    libcouchbase_uint16_t ret = ntohs(res->response.status);
    if (ret == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
        libcouchbase_server_connected(server);
    } else if (ret == PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
        /* I don't know how to step yet ;-) */
        libcouchbase_error_handler(server->instance,
                                   LIBCOUCHBASE_NOT_SUPPORTED,
                                   "We don't support sasl authentication that requires \"SASL STEP\" yet");
    } else {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_AUTH_ERROR,
                                   "SASL authentication failed");
    }

    /* Make it known that this was a success. */
    libcouchbase_error_handler(server->instance, LIBCOUCHBASE_SUCCESS, NULL);
    (void)command_data;
}

static void sasl_step_response_handler(libcouchbase_server_t *server,
                                       struct libcouchbase_command_data_st *command_data,
                                       protocol_binary_response_header *res)
{
    (void)server;
    (void)res;
    (void)command_data;

    /* I don't have sasl step support yet ;-) */
    libcouchbase_error_handler(server->instance, LIBCOUCHBASE_NOT_SUPPORTED,
                               "SASL AUTH CONTINUE not supported yet");

#if 0
    // I should put the server to the notification!
    if (server->instance->vbucket_state_listener != NULL) {
        server->instance->vbucket_state_listener(server);
    }
#endif
}

static void touch_response_handler(libcouchbase_server_t *server,
                                   struct libcouchbase_command_data_st *command_data,
                                   protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);
    libcouchbase_uint16_t status = ntohs(res->response.status);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.touch(root, command_data->cookie, map_error(status),
                              key, nkey);
        release_key(server, packet);
    }
}

static void flush_response_handler(libcouchbase_server_t *server,
                                   struct libcouchbase_command_data_st *command_data,
                                   protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    root->callbacks.flush(root, command_data->cookie, server->authority,
                          map_error(status));
    if (libcouchbase_lookup_server_with_command(root, PROTOCOL_BINARY_CMD_FLUSH,
                                                res->response.opaque, server) < 0) {
        root->callbacks.flush(root, command_data->cookie, NULL,
                              LIBCOUCHBASE_SUCCESS);
    }
}

static void unlock_response_handler(libcouchbase_server_t *server,
                                    struct libcouchbase_command_data_st *command_data,
                                    protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_uint16_t status = ntohs(res->response.status);
    char *packet;
    libcouchbase_uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.unlock(root, command_data->cookie, map_error(status),
                               key, nkey);
        release_key(server, packet);
    }
}

static void dummy_tap_mutation_callback(libcouchbase_t instance,
                                        const void *cookie,
                                        const void *key,
                                        libcouchbase_size_t nkey,
                                        const void *data,
                                        libcouchbase_size_t nbytes,
                                        libcouchbase_uint32_t flags,
                                        libcouchbase_time_t exp,
                                        libcouchbase_cas_t cas,
                                        libcouchbase_vbucket_t vbucket,
                                        const void *es,
                                        libcouchbase_size_t nes)
{
    (void)instance;
    (void)cookie;
    (void)key;
    (void)nkey;
    (void)data;
    (void)nbytes;
    (void)flags;
    (void)cas;
    (void)vbucket;
    (void)exp;
    (void)es;
    (void)nes;
}

static void dummy_tap_deletion_callback(libcouchbase_t instance,
                                        const void *cookie,
                                        const void *key,
                                        libcouchbase_size_t nkey,
                                        libcouchbase_cas_t cas,
                                        libcouchbase_vbucket_t vbucket,
                                        const void *es,
                                        libcouchbase_size_t nes)
{
    (void)instance;
    (void)cookie;
    (void)key;
    (void)nkey;
    (void)cas;
    (void)vbucket;
    (void)es;
    (void)nes;
}

static void dummy_tap_flush_callback(libcouchbase_t instance,
                                     const void *cookie,
                                     const void *es,
                                     libcouchbase_size_t nes)
{
    (void)instance;
    (void)cookie;
    (void)es;
    (void)nes;
}

static void dummy_tap_opaque_callback(libcouchbase_t instance,
                                      const void *cookie,
                                      const void *es,
                                      libcouchbase_size_t nes)
{
    (void)instance;
    (void)cookie;
    (void)es;
    (void)nes;
}
static void dummy_tap_vbucket_set_callback(libcouchbase_t instance,
                                           const void *cookie,
                                           libcouchbase_vbucket_t vbid,
                                           libcouchbase_vbucket_state_t state,
                                           const void *es,
                                           libcouchbase_size_t nes)
{
    (void)instance;
    (void)cookie;
    (void)vbid;
    (void)state;
    (void)es;
    (void)nes;
}
static void dummy_error_callback(libcouchbase_t instance,
                                 libcouchbase_error_t error,
                                 const char *errinfo)
{
    (void)instance;
    (void)error;
    (void)errinfo;
}

static void dummy_stat_callback(libcouchbase_t instance,
                                const void *cookie,
                                const char *server_endpoint,
                                libcouchbase_error_t error,
                                const void *key,
                                libcouchbase_size_t nkey,
                                const void *value,
                                libcouchbase_size_t nvalue)
{
    (void)instance;
    (void)error;
    (void)cookie;
    (void)server_endpoint;
    (void)key;
    (void)nkey;
    (void)value;
    (void)nvalue;
}

static void dummy_version_callback(libcouchbase_t instance,
                                   const void *cookie,
                                   const char *server_endpoint,
                                   libcouchbase_error_t error,
                                   const char *vstring,
                                   libcouchbase_size_t nvstring)
{
    (void)instance;
    (void)cookie;
    (void)server_endpoint;
    (void)error;
    (void)vstring;
    (void)nvstring;
}

static void dummy_get_callback(libcouchbase_t instance,
                               const void *cookie,
                               libcouchbase_error_t error,
                               const void *key, libcouchbase_size_t nkey,
                               const void *bytes, libcouchbase_size_t nbytes,
                               libcouchbase_uint32_t flags, libcouchbase_cas_t cas)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)key;
    (void)nkey;
    (void)bytes;
    (void)nbytes;
    (void)flags;
    (void)cas;
}

static void dummy_storage_callback(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_storage_t operation,
                                   libcouchbase_error_t error,
                                   const void *key, libcouchbase_size_t nkey,
                                   libcouchbase_cas_t cas)
{
    (void)instance;
    (void)cookie;
    (void)operation, (void)error;
    (void)key;
    (void)nkey;
    (void)cas;
}

static void dummy_arithmetic_callback(libcouchbase_t instance,
                                      const void *cookie,
                                      libcouchbase_error_t error,
                                      const void *key, libcouchbase_size_t nkey,
                                      libcouchbase_uint64_t value, libcouchbase_cas_t cas)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)key;
    (void)nkey;
    (void)value;
    (void)cas;
}

static void dummy_remove_callback(libcouchbase_t instance,
                                  const void *cookie,
                                  libcouchbase_error_t error,
                                  const void *key, libcouchbase_size_t nkey)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)key;
    (void)nkey;
}

static void dummy_touch_callback(libcouchbase_t instance,
                                 const void *cookie,
                                 libcouchbase_error_t error,
                                 const void *key, libcouchbase_size_t nkey)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)key;
    (void)nkey;
}

static void dummy_flush_callback(libcouchbase_t instance,
                                 const void *cookie,
                                 const char *server_endpoint,
                                 libcouchbase_error_t error)
{
    (void)instance;
    (void)cookie;
    (void)server_endpoint;
    (void)error;
}

static void dummy_couch_complete_callback(libcouchbase_http_request_t request,
                                          libcouchbase_t instance,
                                          const void *cookie,
                                          libcouchbase_error_t error,
                                          libcouchbase_http_status_t status,
                                          const char *path, libcouchbase_size_t npath,
                                          const void *bytes, libcouchbase_size_t nbytes)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)path;
    (void)npath;
    (void)bytes;
    (void)nbytes;
    (void)status;
}

static void dummy_management_data_callback(libcouchbase_http_request_t request,
                                           libcouchbase_t instance,
                                           const void *cookie,
                                           libcouchbase_error_t error,
                                           libcouchbase_http_status_t status,
                                           const char *path, libcouchbase_size_t npath,
                                           const void *bytes, libcouchbase_size_t nbytes)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)path;
    (void)npath;
    (void)bytes;
    (void)nbytes;
    (void)status;
}

static void dummy_management_complete_callback(libcouchbase_http_request_t request,
                                               libcouchbase_t instance,
                                               const void *cookie,
                                               libcouchbase_error_t error,
                                               libcouchbase_http_status_t status,
                                               const char *path, libcouchbase_size_t npath,
                                               const void *bytes, libcouchbase_size_t nbytes)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)path;
    (void)npath;
    (void)bytes;
    (void)nbytes;
    (void)status;
}

static void dummy_couch_data_callback(libcouchbase_http_request_t request,
                                      libcouchbase_t instance,
                                      const void *cookie,
                                      libcouchbase_error_t error,
                                      libcouchbase_http_status_t status,
                                      const char *path, libcouchbase_size_t npath,
                                      const void *bytes, libcouchbase_size_t nbytes)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)path;
    (void)npath;
    (void)bytes;
    (void)nbytes;
    (void)status;
}

static void dummy_unlock_callback(libcouchbase_t instance,
                                  const void *cookie,
                                  libcouchbase_error_t error,
                                  const void *key, libcouchbase_size_t nkey)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)key;
    (void)nkey;
}

static void dummy_configuration_callback(libcouchbase_t instance,
                                         libcouchbase_configuration_t val)
{
    (void)instance;
    (void)val;
}

static void dummy_observe_callback(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_error_t error,
                                   libcouchbase_observe_t status,
                                   const void *key,
                                   libcouchbase_size_t nkey,
                                   libcouchbase_cas_t cas,
                                   int is_master,
                                   libcouchbase_time_t ttp,
                                   libcouchbase_time_t ttr)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)status;
    (void)key;
    (void)nkey;
    (void)cas;
    (void)is_master;
    (void)ttp;
    (void)ttr;
}

void libcouchbase_initialize_packet_handlers(libcouchbase_t instance)
{
    int ii;
    for (ii = 0; ii < 0x100; ++ii) {
        instance->request_handler[ii] = dummy_request_handler;
        instance->response_handler[ii] = dummy_response_handler;
    }

    instance->callbacks.tap_mutation = dummy_tap_mutation_callback;
    instance->callbacks.tap_deletion = dummy_tap_deletion_callback;
    instance->callbacks.tap_flush = dummy_tap_flush_callback;
    instance->callbacks.tap_opaque = dummy_tap_opaque_callback;
    instance->callbacks.tap_vbucket_set = dummy_tap_vbucket_set_callback;
    instance->callbacks.get = dummy_get_callback;
    instance->callbacks.storage = dummy_storage_callback;
    instance->callbacks.arithmetic = dummy_arithmetic_callback;
    instance->callbacks.remove = dummy_remove_callback;
    instance->callbacks.touch = dummy_touch_callback;
    instance->callbacks.error = dummy_error_callback;
    instance->callbacks.stat = dummy_stat_callback;
    instance->callbacks.version = dummy_version_callback;
    instance->callbacks.couch_complete = dummy_couch_complete_callback;
    instance->callbacks.couch_data = dummy_couch_data_callback;
    instance->callbacks.management_complete = dummy_management_complete_callback;
    instance->callbacks.management_data = dummy_management_data_callback;
    instance->callbacks.flush = dummy_flush_callback;
    instance->callbacks.unlock = dummy_unlock_callback;
    instance->callbacks.configuration = dummy_configuration_callback;
    instance->callbacks.observe = dummy_observe_callback;

    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_MUTATION] = tap_mutation_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_DELETE] = tap_deletion_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_FLUSH] = tap_flush_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_OPAQUE] = tap_opaque_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET] = tap_vbucket_set_handler;

    instance->response_handler[PROTOCOL_BINARY_CMD_FLUSH] = flush_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_GETQ] = getq_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_GATQ] = getq_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_GET] = getq_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_GAT] = getq_response_handler;
    instance->response_handler[CMD_GET_LOCKED] = getq_response_handler;
    instance->response_handler[CMD_GET_REPLICA] = get_replica_response_handler;
    instance->response_handler[CMD_UNLOCK_KEY] = unlock_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_ADD] = storage_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_DELETE] = delete_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_REPLACE] = storage_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_SET] = storage_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_APPEND] = storage_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_PREPEND] = storage_response_handler;

    instance->response_handler[PROTOCOL_BINARY_CMD_INCREMENT] = arithmetic_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_DECREMENT] = arithmetic_response_handler;

    instance->response_handler[PROTOCOL_BINARY_CMD_SASL_LIST_MECHS] = sasl_list_mech_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_SASL_AUTH] = sasl_auth_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_SASL_STEP] = sasl_step_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_TOUCH] = touch_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_STAT] = stat_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_VERSION] = version_response_handler;
    instance->response_handler[CMD_OBSERVE] = observe_response_handler;
}

LIBCOUCHBASE_API
libcouchbase_get_callback libcouchbase_set_get_callback(libcouchbase_t instance,
                                                        libcouchbase_get_callback cb)
{
    libcouchbase_get_callback ret = instance->callbacks.get;
    if (cb != NULL) {
        instance->callbacks.get = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_storage_callback libcouchbase_set_storage_callback(libcouchbase_t instance,
                                                                libcouchbase_storage_callback cb)
{
    libcouchbase_storage_callback ret = instance->callbacks.storage;
    if (cb != NULL) {
        instance->callbacks.storage = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_arithmetic_callback libcouchbase_set_arithmetic_callback(libcouchbase_t instance,
                                                                      libcouchbase_arithmetic_callback cb)
{
    libcouchbase_arithmetic_callback ret = instance->callbacks.arithmetic;
    if (cb != NULL) {
        instance->callbacks.arithmetic = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_observe_callback libcouchbase_set_observe_callback(libcouchbase_t instance,
                                                                libcouchbase_observe_callback cb)
{
    libcouchbase_observe_callback ret = instance->callbacks.observe;
    instance->callbacks.observe = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_remove_callback libcouchbase_set_remove_callback(libcouchbase_t instance,
                                                              libcouchbase_remove_callback cb)
{
    libcouchbase_remove_callback ret = instance->callbacks.remove;
    if (cb != NULL) {
        instance->callbacks.remove = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_touch_callback libcouchbase_set_touch_callback(libcouchbase_t instance,
                                                            libcouchbase_touch_callback cb)
{
    libcouchbase_touch_callback ret = instance->callbacks.touch;
    if (cb != NULL) {
        instance->callbacks.touch = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_mutation_callback libcouchbase_set_tap_mutation_callback(libcouchbase_t instance,
                                                                          libcouchbase_tap_mutation_callback cb)
{
    libcouchbase_tap_mutation_callback ret = instance->callbacks.tap_mutation;
    if (cb != NULL) {
        instance->callbacks.tap_mutation = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_deletion_callback libcouchbase_set_tap_deletion_callback(libcouchbase_t instance,
                                                                          libcouchbase_tap_deletion_callback cb)
{
    libcouchbase_tap_deletion_callback ret = instance->callbacks.tap_deletion;
    if (cb != NULL) {
        instance->callbacks.tap_deletion = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_flush_callback libcouchbase_set_tap_flush_callback(libcouchbase_t instance,
                                                                    libcouchbase_tap_flush_callback cb)
{
    libcouchbase_tap_flush_callback ret = instance->callbacks.tap_flush;
    if (cb != NULL) {
        instance->callbacks.tap_flush = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_opaque_callback libcouchbase_set_tap_opaque_callback(libcouchbase_t instance,
                                                                      libcouchbase_tap_opaque_callback cb)
{
    libcouchbase_tap_opaque_callback ret = instance->callbacks.tap_opaque;
    if (cb != NULL) {
        instance->callbacks.tap_opaque = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_vbucket_set_callback libcouchbase_set_tap_vbucket_set_callback(libcouchbase_t instance,
        libcouchbase_tap_vbucket_set_callback cb)
{
    libcouchbase_tap_vbucket_set_callback ret = instance->callbacks.tap_vbucket_set;
    if (cb != NULL) {
        instance->callbacks.tap_vbucket_set = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_stat_callback libcouchbase_set_stat_callback(libcouchbase_t instance,
                                                          libcouchbase_stat_callback cb)
{
    libcouchbase_stat_callback ret = instance->callbacks.stat;
    if (cb != NULL) {
        instance->callbacks.stat = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_version_callback libcouchbase_set_version_callback(libcouchbase_t instance,
                                                                libcouchbase_version_callback cb)
{
    libcouchbase_version_callback ret = instance->callbacks.version;
    if (cb != NULL) {
        instance->callbacks.version = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_error_callback libcouchbase_set_error_callback(libcouchbase_t instance,
                                                            libcouchbase_error_callback cb)
{
    libcouchbase_error_callback ret = instance->callbacks.error;
    if (cb != NULL) {
        instance->callbacks.error = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_flush_callback libcouchbase_set_flush_callback(libcouchbase_t instance,
                                                            libcouchbase_flush_callback cb)
{
    libcouchbase_flush_callback ret = instance->callbacks.flush;
    if (cb != NULL) {
        instance->callbacks.flush = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_http_complete_callback libcouchbase_set_couch_complete_callback(libcouchbase_t instance,
                                                                             libcouchbase_http_complete_callback cb)
{
    libcouchbase_http_complete_callback ret = instance->callbacks.couch_complete;
    if (cb != NULL) {
        instance->callbacks.couch_complete = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_http_data_callback libcouchbase_set_couch_data_callback(libcouchbase_t instance,
                                                                     libcouchbase_http_data_callback cb)
{
    libcouchbase_http_data_callback ret = instance->callbacks.couch_data;
    if (cb != NULL) {
        instance->callbacks.couch_data = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_http_complete_callback libcouchbase_set_management_complete_callback(libcouchbase_t instance,
                                                                                  libcouchbase_http_complete_callback cb)
{
    libcouchbase_http_complete_callback ret = instance->callbacks.management_complete;
    if (cb != NULL) {
        instance->callbacks.management_complete = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_http_data_callback libcouchbase_set_management_data_callback(libcouchbase_t instance,
                                                                          libcouchbase_http_data_callback cb)
{
    libcouchbase_http_data_callback ret = instance->callbacks.management_data;
    if (cb != NULL) {
        instance->callbacks.management_data = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_unlock_callback libcouchbase_set_unlock_callback(libcouchbase_t instance,
                                                              libcouchbase_unlock_callback cb)
{
    libcouchbase_unlock_callback ret = instance->callbacks.unlock;
    if (cb != NULL) {
        instance->callbacks.unlock = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_configuration_callback libcouchbase_set_configuration_callback(libcouchbase_t instance,
                                                                            libcouchbase_configuration_callback cb)
{
    libcouchbase_configuration_callback ret = instance->callbacks.configuration;
    if (cb != NULL) {
        instance->callbacks.configuration = cb;
    }
    return ret;
}
