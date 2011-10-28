/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc.
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

static libcouchbase_error_t map_error(protocol_binary_response_status in) {
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
                                  const void *command_cookie,
                                  protocol_binary_request_header *req)
{
    (void)server;
    (void)req;
    (void)command_cookie;
#ifdef DEBUG
    fprintf(stderr, "Received request packet %02x\n", req->request.opcode);
#endif
}

static void dummy_response_handler(libcouchbase_server_t *server,
                                   const void *command_cookie,
                                   protocol_binary_response_header *res)
{
#ifdef DEBUG
    fprintf(stderr, "Received response packet %02x %04x\n",
            res->response.opcode, ntohs(res->response.status));
#endif
    (void)server;
    (void)res;
    (void)command_cookie;
}


static const char *get_key(libcouchbase_server_t *server, uint16_t *nkey,
                           char **packet)
{
    protocol_binary_request_header req;
    size_t nr = libcouchbase_ringbuffer_peek(&server->cmd_log,
                                             req.bytes, sizeof(req));
    uint32_t packetsize = ntohl(req.request.bodylen) + (uint32_t)sizeof(req);
    char *keyptr;
    *packet = server->cmd_log.read_head;
    assert(nr == sizeof(req));

    if (!libcouchbase_ringbuffer_is_continous(&server->cmd_log,
                                              RINGBUFFER_READ,
                                              packetsize)) {
        *packet = malloc(packetsize);
        if (*packet == NULL) {
            libcouchbase_error_handler(server->instance, LIBCOUCHBASE_ENOMEM,
                                       NULL);
            return NULL;
        }

        nr = libcouchbase_ringbuffer_peek(&server->cmd_log, *packet, packetsize);
        if (nr != packetsize) {
            libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                       NULL);
            free(*packet);
            return NULL;
        }
    }

    *nkey = ntohs(req.request.keylen);
    keyptr = *packet + sizeof(req) + req.request.extlen;
    return keyptr;
}

static int lookup_server_with_command(libcouchbase_t instance,
                                      protocol_binary_command opcode,
                                      uint32_t opaque,
                                      libcouchbase_server_t *exc)
{
    protocol_binary_request_header cmd;
    libcouchbase_server_t *server;
    size_t nr, ii;

    for (ii = 0; ii < instance->nservers; ++ii) {
        server = instance->servers + ii;
        nr = libcouchbase_ringbuffer_peek(&server->cmd_log, &cmd, sizeof(cmd));
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
    if (packet != server->cmd_log.read_head) {
        free(packet);
    }
}

static void getq_response_handler(libcouchbase_server_t *server,
                                  const void *command_cookie,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_response_getq *getq = (void*)res;
    uint16_t status = ntohs(res->response.status);
    size_t nbytes = ntohl(res->response.bodylen);
    char *packet;
    uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    nbytes -= res->response.extlen;
    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        return;
    } else if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        const char *bytes = (const char *)res;
        bytes += sizeof(getq->bytes);
        root->callbacks.get(root, command_cookie, LIBCOUCHBASE_SUCCESS,
                            key, nkey, bytes, nbytes,
                            ntohl(getq->message.body.flags),
                            res->response.cas);
    } else {
        root->callbacks.get(root, command_cookie, map_error(status), key, nkey,
                            NULL, 0, 0, 0);
    }
    release_key(server, packet);
}

static void delete_response_handler(libcouchbase_server_t *server,
                                    const void *command_cookie,
                                    protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    uint16_t status = ntohs(res->response.status);
    char *packet;
    uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.remove(root, command_cookie, map_error(status),
                               key, nkey);
        release_key(server, packet);
    }
}

static void storage_response_handler(libcouchbase_server_t *server,
                                     const void *command_cookie,
                                     protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    libcouchbase_storage_t op;

    char *packet;
    uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);


    uint16_t status = ntohs(res->response.status);

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
        // It is impossible to get here (since we're called from our
        // lookup table... If we _DO_ get here, it must be a development
        // version where the developer isn't done yet (and should be
        // forced to think about what to do...)
        libcouchbase_error_handler(root, LIBCOUCHBASE_EINTERNAL,
                                   "Internal error. Received an illegal command opcode");
        abort();
    }

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
    } else {
        root->callbacks.storage(root, command_cookie, op, map_error(status),
                                key, nkey, res->response.cas);
        release_key(server, packet);
    }
}

static void arithmetic_response_handler(libcouchbase_server_t *server,
                                        const void *command_cookie,
                                        protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    uint16_t status = ntohs(res->response.status);
    char *packet;
    uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);

    if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
        return ;
    } else if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        uint64_t value;
        memcpy(&value, res + 1, sizeof(value));
        value = ntohll(value);
        root->callbacks.arithmetic(root, command_cookie, LIBCOUCHBASE_SUCCESS,
                                   key, nkey, value, res->response.cas);
    } else {
        root->callbacks.arithmetic(root,command_cookie, map_error(status),
                                   key, nkey, 0, 0);
    }
    release_key(server, packet);
}

static void stat_response_handler(libcouchbase_server_t *server,
                                  const void *command_cookie,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    uint16_t status = ntohs(res->response.status);
    uint16_t nkey;
    uint32_t nvalue;
    const char *key, *value;

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        nkey = ntohs(res->response.keylen);
        if (nkey == 0) {
            if (lookup_server_with_command(root, PROTOCOL_BINARY_CMD_STAT,
                                           res->response.opaque, server) < 0) {
                /* notify client that data is ready */
                root->callbacks.stat(root, command_cookie, NULL,
                                     LIBCOUCHBASE_SUCCESS, NULL, 0, NULL, 0);
            }
            return;
        }
        key = (const char *)res + sizeof(res->bytes);
        nvalue = ntohl(res->response.bodylen) - nkey;
        value = key + nkey;
        root->callbacks.stat(root, command_cookie, server->authority,
                             map_error(status), key, nkey, value, nvalue);
    } else {
        root->callbacks.stat(root, command_cookie, server->authority,
                             map_error(status), NULL, 0, NULL, 0);

        /* run callback with null-null-null to signal the end of transfer */
        if (lookup_server_with_command(root, PROTOCOL_BINARY_CMD_STAT,
                                       res->response.opaque, server) < 0) {
            root->callbacks.stat(root, command_cookie, NULL,
                                 LIBCOUCHBASE_SUCCESS, NULL, 0, NULL, 0);
        }
    }
}

static void tap_mutation_handler(libcouchbase_server_t *server,
                                 const void *command_cookie,
                                 protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_mutation *mutation = (void*)req;
    uint32_t flags = ntohl(mutation->message.body.item.flags);
    uint32_t exp = ntohl(mutation->message.body.item.expiration);
    uint16_t nkey = ntohs(req->request.keylen);

    char *es = packet + sizeof(mutation->bytes);
    uint16_t nes = ntohs(mutation->message.body.tap.enginespecific_length);
    char *key = es + nes;
    void *data = key + nkey;
    uint32_t nbytes = ntohl(req->request.bodylen) - req->request.extlen - nes - nkey;

    libcouchbase_t root = server->instance;
    root->callbacks.tap_mutation(root, command_cookie, key, nkey, data, nbytes,
                                 flags, exp, es, nes);
}

static void tap_deletion_handler(libcouchbase_server_t *server,
                                 const void *command_cookie,
                                 protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_delete *deletion = (void*)req;
    uint16_t nkey = ntohs(req->request.keylen);
    char *es = packet + sizeof(deletion->bytes);
    uint16_t nes = ntohs(deletion->message.body.tap.enginespecific_length);
    char *key = es + nes;
    libcouchbase_t root = server->instance;
    root->callbacks.tap_deletion(root, command_cookie, key, nkey, es, nes);
}

static void tap_flush_handler(libcouchbase_server_t *server,
                              const void *command_cookie,
                              protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_flush *flush = (void*)req;
    char *es = packet + sizeof(flush->bytes);
    uint16_t nes = ntohs(flush->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_flush(root, command_cookie, es, nes);
}

static void tap_opaque_handler(libcouchbase_server_t *server,
                               const void *command_cookie,
                               protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_opaque *opaque = (void*)req;
    char *es = packet + sizeof(opaque->bytes);
    uint16_t nes = ntohs(opaque->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_opaque(root, command_cookie, es, nes);
}

static void tap_vbucket_set_handler(libcouchbase_server_t *server,
                                    const void *command_cookie,
                                    protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    libcouchbase_t root = server->instance;
    char *packet = (char*)req;
    protocol_binary_request_tap_vbucket_set *vbset = (void*)req;
    char *es = packet + sizeof(vbset->bytes);
    uint16_t nes = ntohs(vbset->message.body.tap.enginespecific_length);
    uint32_t state;
    memcpy(&state, es + nes, sizeof(state));
    state = ntohl(state);
    root->callbacks.tap_vbucket_set(root, command_cookie, ntohs(req->request.vbucket),
                                    (vbucket_state_t)state, es, nes);
}

static void sasl_list_mech_response_handler(libcouchbase_server_t *server,
                                            const void *command_cookie,
                                            protocol_binary_response_header *res)
{
    const char *data;
    const char *chosenmech;
    unsigned int len;
    protocol_binary_request_no_extras req;
    size_t keylen;
    size_t bodysize;

    assert(ntohs(res->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);
    if (sasl_client_start(server->sasl_conn, (const char *)(res + 1),
                          NULL, &data, &len, &chosenmech) != SASL_OK) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_AUTH_ERROR,
                                   "Unable to start sasl client");
        return;
    }

    keylen = strlen(chosenmech);
    bodysize = keylen + len;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    req.message.header.request.keylen = ntohs((uint16_t)keylen);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = ntohl((uint32_t)(bodysize));

    libcouchbase_server_buffer_start_packet(server, command_cookie, &server->output,
                                            &server->output_cookies,
                                            req.bytes, sizeof(req.bytes));
    libcouchbase_server_buffer_write_packet(server, &server->output,
                                            chosenmech, keylen);
    libcouchbase_server_buffer_write_packet(server, &server->output, data, len);
    libcouchbase_server_buffer_end_packet(server, &server->output);

    // send the data and add a write handler
    libcouchbase_server_event_handler(0, LIBCOUCHBASE_WRITE_EVENT, server);

    // Make it known that this was a success.
    libcouchbase_error_handler(server->instance, LIBCOUCHBASE_SUCCESS, NULL);
}

static void sasl_auth_response_handler(libcouchbase_server_t *server,
                                       const void *command_cookie,
                                       protocol_binary_response_header *res)
{
    uint16_t ret = ntohs(res->response.status);
    if (ret == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
        libcouchbase_server_connected(server);
    } else if (ret == PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
        // I don't know how to step yet ;-)
        libcouchbase_error_handler(server->instance,
                                   LIBCOUCHBASE_NOT_SUPPORTED,
                                   "We don't support sasl authentication that requires \"SASL STEP\" yet");
    } else {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_AUTH_ERROR,
                                   "SASL authentication failed");
    }

    // Make it known that this was a success.
    libcouchbase_error_handler(server->instance, LIBCOUCHBASE_SUCCESS, NULL);
    (void)command_cookie;
}

static void sasl_step_response_handler(libcouchbase_server_t *server,
                                       const void *command_cookie,
                                       protocol_binary_response_header *res)
{
    (void)server;
    (void)res;
    (void)command_cookie;

    // I don't have sasl step support yet ;-)
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
                                   const void *command_cookie,
                                   protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    char *packet;
    uint16_t nkey;
    const char *key = get_key(server, &nkey, &packet);
    uint16_t status = ntohs(res->response.status);

   if (key == NULL) {
        libcouchbase_error_handler(server->instance, LIBCOUCHBASE_EINTERNAL,
                                   NULL);
   } else {
       root->callbacks.touch(root, command_cookie, map_error(status),
                             key, nkey);
       release_key(server, packet);
   }
}

static void flush_response_handler(libcouchbase_server_t *server,
                                  const void *command_cookie,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    uint16_t status = ntohs(res->response.status);
    root->callbacks.flush(root, command_cookie, map_error(status));
}

static void dummy_tap_mutation_callback(libcouchbase_t instance,
                                        const void *cookie,
                                        const void *key,
                                        size_t nkey,
                                        const void *data,
                                        size_t nbytes,
                                        uint32_t flags,
                                        uint32_t exp,
                                        const void *es,
                                        size_t nes)
{
    (void)instance; (void)cookie; (void)key; (void)nkey; (void)data;
    (void)nbytes; (void)flags; (void)exp; (void)es; (void)nes;
}

static void dummy_tap_deletion_callback(libcouchbase_t instance,
                                        const void *cookie,
                                        const void *key,
                                        size_t nkey,
                                        const void *es,
                                        size_t nes)
{
    (void)instance; (void)cookie; (void)key; (void)nkey; (void)es; (void)nes;

}

static void dummy_tap_flush_callback(libcouchbase_t instance,
                                     const void *cookie,
                                     const void *es,
                                     size_t nes)
{
    (void)instance; (void)cookie; (void)es; (void)nes;
}

static void dummy_tap_opaque_callback(libcouchbase_t instance,
                                      const void *cookie,
                                      const void *es,
                                      size_t nes)
{
    (void)instance; (void)cookie; (void)es; (void)nes;
}
static void dummy_tap_vbucket_set_callback(libcouchbase_t instance,
                                           const void *cookie,
                                           uint16_t vbid,
                                           vbucket_state_t state,
                                           const void *es,
                                           size_t nes)
{
    (void)instance; (void)cookie; (void)vbid; (void)state; (void)es; (void)nes;
}
static void dummy_error_callback(libcouchbase_t instance,
                                 libcouchbase_error_t error,
                                 const char *errinfo)
{
    (void)instance; (void)error; (void)errinfo;
}

static void dummy_stat_callback(libcouchbase_t instance,
                                const void* command_cookie,
                                const char* server_endpoint,
                                libcouchbase_error_t error,
                                const void* key,
                                size_t nkey,
                                const void* value,
                                size_t nvalue)
{
    (void)instance; (void)error; (void)command_cookie; (void)server_endpoint;
    (void)key; (void)nkey; (void)value; (void)nvalue;
}

static void dummy_get_callback(libcouchbase_t instance,
                               const void *cookie,
                               libcouchbase_error_t error,
                               const void *key, size_t nkey,
                               const void *bytes, size_t nbytes,
                               uint32_t flags, uint64_t cas)
{
    (void)instance; (void)cookie; (void)error; (void)key; (void)nkey;
    (void)bytes; (void)nbytes; (void)flags; (void)cas;
}

static void dummy_storage_callback(libcouchbase_t instance,
                                   const void *cookie,
                                   libcouchbase_storage_t operation,
                                   libcouchbase_error_t error,
                                   const void *key, size_t nkey,
                                   uint64_t cas)
{
    (void)instance; (void)cookie; (void)operation, (void)error; (void)key;
    (void)nkey; (void)cas;
}

static void dummy_arithmetic_callback(libcouchbase_t instance,
                                      const void *cookie,
                                      libcouchbase_error_t error,
                                      const void *key, size_t nkey,
                                      uint64_t value, uint64_t cas)
{
    (void)instance; (void)cookie; (void)error; (void)key; (void)nkey;
    (void)value; (void)cas;
}

static void dummy_remove_callback(libcouchbase_t instance,
                                  const void *cookie,
                                  libcouchbase_error_t error,
                                  const void *key, size_t nkey)
{
    (void)instance; (void)cookie; (void)error; (void)key; (void)nkey;
}

static void dummy_touch_callback(libcouchbase_t instance,
                                 const void *cookie,
                                 libcouchbase_error_t error,
                                 const void *key, size_t nkey)
{
    (void)instance; (void)cookie; (void)error; (void)key; (void)nkey;
}

static void dummy_view_complete_callback(libcouchbase_t instance,
                                         const void *cookie,
                                         libcouchbase_error_t error,
                                         const char *uri,
                                         const void *bytes, size_t nbytes)
{
    (void)instance; (void)cookie; (void)error; (void)uri;
    (void)bytes; (void)nbytes;
}

static void dummy_flush_callback(libcouchbase_t instance,
                                 const void *cookie,
                                 libcouchbase_error_t error)
{
    (void)instance;
    (void)cookie;
    (void)error;
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
    instance->callbacks.view_complete = dummy_view_complete_callback;
    instance->callbacks.view_data = NULL;
    instance->callbacks.flush = dummy_flush_callback;

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
}

LIBCOUCHBASE_API
libcouchbase_get_callback libcouchbase_set_get_callback(libcouchbase_t instance,
                                                        libcouchbase_get_callback cb)
{
    libcouchbase_get_callback ret = instance->callbacks.get;
    instance->callbacks.get = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_storage_callback libcouchbase_set_storage_callback(libcouchbase_t instance,
                                                                libcouchbase_storage_callback cb)
{
    libcouchbase_storage_callback ret = instance->callbacks.storage;
    instance->callbacks.storage = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_arithmetic_callback libcouchbase_set_arithmetic_callback(libcouchbase_t instance,
                                                                      libcouchbase_arithmetic_callback cb)
{
    libcouchbase_arithmetic_callback ret = instance->callbacks.arithmetic;
    instance->callbacks.arithmetic = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_remove_callback libcouchbase_set_remove_callback(libcouchbase_t instance,
                                                              libcouchbase_remove_callback cb)
{
    libcouchbase_remove_callback ret = instance->callbacks.remove;
    instance->callbacks.remove = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_touch_callback libcouchbase_set_touch_callback(libcouchbase_t instance,
                                                            libcouchbase_touch_callback cb)
{
    libcouchbase_touch_callback ret = instance->callbacks.touch;
    instance->callbacks.touch = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_mutation_callback libcouchbase_set_tap_mutation_callback(libcouchbase_t instance,
                                                                          libcouchbase_tap_mutation_callback cb)
{
    libcouchbase_tap_mutation_callback ret = instance->callbacks.tap_mutation;
    instance->callbacks.tap_mutation = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_deletion_callback libcouchbase_set_tap_deletion_callback(libcouchbase_t instance,
                                                                          libcouchbase_tap_deletion_callback cb)
{
    libcouchbase_tap_deletion_callback ret = instance->callbacks.tap_deletion;
    instance->callbacks.tap_deletion = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_flush_callback libcouchbase_set_tap_flush_callback(libcouchbase_t instance,
                                                                    libcouchbase_tap_flush_callback cb)
{
    libcouchbase_tap_flush_callback ret = instance->callbacks.tap_flush;
    instance->callbacks.tap_flush = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_opaque_callback libcouchbase_set_tap_opaque_callback(libcouchbase_t instance,
                                                                      libcouchbase_tap_opaque_callback cb)
{
    libcouchbase_tap_opaque_callback ret = instance->callbacks.tap_opaque;
    instance->callbacks.tap_opaque = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_tap_vbucket_set_callback libcouchbase_set_tap_vbucket_set_callback(libcouchbase_t instance,
                                                                                libcouchbase_tap_vbucket_set_callback cb)
{
    libcouchbase_tap_vbucket_set_callback ret = instance->callbacks.tap_vbucket_set;
    instance->callbacks.tap_vbucket_set = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_stat_callback libcouchbase_set_stat_callback(libcouchbase_t instance,
                                                          libcouchbase_stat_callback cb)
{
    libcouchbase_stat_callback ret = instance->callbacks.stat;
    instance->callbacks.stat = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_error_callback libcouchbase_set_error_callback(libcouchbase_t instance,
                                                            libcouchbase_error_callback cb)
{
    libcouchbase_error_callback ret = instance->callbacks.error;
    instance->callbacks.error = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_view_complete_callback libcouchbase_set_view_complete_callback(libcouchbase_t instance,
                                                                        libcouchbase_view_complete_callback cb)
{
    libcouchbase_view_complete_callback ret = instance->callbacks.view_complete;
    instance->callbacks.view_complete = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_view_data_callback libcouchbase_set_view_data_callback(libcouchbase_t instance,
                                                                     libcouchbase_view_data_callback cb)
{
    libcouchbase_view_data_callback ret = instance->callbacks.view_data;
    instance->callbacks.view_data = cb;
    return ret;
}

LIBCOUCHBASE_API
libcouchbase_flush_callback libcouchbase_set_flush_callback(libcouchbase_t instance,
                                                            libcouchbase_flush_callback cb)
{
    libcouchbase_flush_callback ret = instance->callbacks.flush;
    instance->callbacks.flush = cb;
    return ret;
}
