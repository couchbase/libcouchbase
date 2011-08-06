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
                                  protocol_binary_request_header *req)
{
    (void)server;
    (void)req;
#ifdef DEBUG
    fprintf(stderr, "Received request packet %02x\n", req->request.opcode);
#endif
}

static void dummy_response_handler(libcouchbase_server_t *server,
                                   protocol_binary_response_header *res)
{
#ifdef DEBUG
    fprintf(stderr, "Received response packet %02x %04x\n",
            res->response.opcode, ntohs(res->response.status));
#endif
    (void)server;
    (void)res;
}

static void getq_response_handler(libcouchbase_server_t *server,
                                  protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_response_getq *getq = (void*)res;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    const char *key = (const char *)(req + 1) + req->request.extlen;
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);
    size_t nbytes = ntohl(res->response.bodylen);
    nbytes -= res->response.extlen;
    assert(req->request.opaque == res->response.opaque);
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        const char *bytes = (const char *)res;
        bytes += sizeof(getq->bytes);
        root->callbacks.get(root, LIBCOUCHBASE_SUCCESS, key, nkey,
                            bytes, nbytes,
                            ntohl(getq->message.body.flags),
                            res->response.cas);
    } else {
        root->callbacks.get(root, LIBCOUCHBASE_KEY_ENOENT, key, nkey,
                            NULL, 0, 0, 0);
    }
}

static void delete_response_handler(libcouchbase_server_t *server,
                                    protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    const char *key = (const char *)(req + 1);
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);
    key += req->request.extlen;

    assert(req->request.opaque == res->response.opaque);
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        root->callbacks.remove(root, LIBCOUCHBASE_SUCCESS, key, nkey);
    } else {
        root->callbacks.remove(root, map_error(status), key, nkey);
    }
}

static void storage_response_handler(libcouchbase_server_t *server,
                                     protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;


    const char *key = (const char*)(req + 1);
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);
    key += req->request.extlen;

    assert(req->request.opaque == res->response.opaque);
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        root->callbacks.storage(root, LIBCOUCHBASE_SUCCESS, key, nkey,
                                res->response.cas);
    } else {
        root->callbacks.storage(root, map_error(status), key, nkey,
                                res->response.cas);
    }
}

static void arithmetic_response_handler(libcouchbase_server_t *server,
                                        protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    const char *key = (const char *)(req + 1);
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);
    key += req->request.extlen;

    assert(req->request.opaque == res->response.opaque);
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        uint64_t value;
        memcpy(&value, res + 1, sizeof(value));
        value = ntohll(value);
        root->callbacks.arithmetic(root, LIBCOUCHBASE_SUCCESS, key, nkey,
                                   value,
                                   res->response.cas);
    } else {
        root->callbacks.arithmetic(root, map_error(status), key, nkey,
                                   0, 0);
    }
}

static void tap_mutation_handler(libcouchbase_server_t *server,
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
    root->callbacks.tap_mutation(root, key, nkey, data, nbytes,
                                 flags, exp, es, nes);
}

static void tap_deletion_handler(libcouchbase_server_t *server,
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
    root->callbacks.tap_deletion(root, key, nkey, es, nes);
}

static void tap_flush_handler(libcouchbase_server_t *server,
                              protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_flush *flush = (void*)req;
    char *es = packet + sizeof(flush->bytes);
    uint16_t nes = ntohs(flush->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_flush(root, es, nes);
}

static void tap_opaque_handler(libcouchbase_server_t *server,
                               protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (char*)req;
    protocol_binary_request_tap_opaque *opaque = (void*)req;
    char *es = packet + sizeof(opaque->bytes);
    uint16_t nes = ntohs(opaque->message.body.tap.enginespecific_length);
    libcouchbase_t root = server->instance;
    root->callbacks.tap_opaque(root, es, nes);
}

static void tap_vbucket_set_handler(libcouchbase_server_t *server,
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
    root->callbacks.tap_vbucket_set(root, ntohs(req->request.vbucket),
                                    (vbucket_state_t)state, es, nes);
}

static void sasl_list_mech_response_handler(libcouchbase_server_t *server,
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
        // @fixme!
        abort();
    }

    keylen = strlen(chosenmech);
    bodysize = keylen + len;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    req.message.header.request.keylen = ntohs((uint16_t)keylen);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = ntohl((uint32_t)(bodysize));

    libcouchbase_server_buffer_start_packet(server, &server->output,
                                            req.bytes, sizeof(req.bytes));
    libcouchbase_server_buffer_write_packet(server, &server->output,
                                            chosenmech, keylen);
    libcouchbase_server_buffer_write_packet(server, &server->output, data, len);
    libcouchbase_server_buffer_end_packet(server, &server->output);

    // send the data and add it to libevent..
    libcouchbase_server_event_handler(0, EV_WRITE, server);
}

static void sasl_auth_response_handler(libcouchbase_server_t *server,
                                       protocol_binary_response_header *res)
{
    uint16_t ret = ntohs(res->response.status);
    if (ret == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
        libcouchbase_server_connected(server);
    } else if (ret == PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
        // I don't know how to step yet ;-)
        abort();
    } else {
        abort();
    }
}

static void sasl_step_response_handler(libcouchbase_server_t *server,
                                       protocol_binary_response_header *res)
{
    (void)server;
    (void)res;

    // I don't have sasl step support yet ;-)
    abort();
#if 0
    // I should put the server to the notification!
    if (server->instance->vbucket_state_listener != NULL) {
        server->instance->vbucket_state_listener(server);
    }
#endif
}

static void touch_response_handler(libcouchbase_server_t *server,
                                    protocol_binary_response_header *res)
{
    libcouchbase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    const char *key = (const char *)(req + 1);
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);
    key += req->request.extlen;

    assert(req->request.opaque == res->response.opaque);
    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        root->callbacks.touch(root, LIBCOUCHBASE_SUCCESS, key, nkey);
    } else {
        root->callbacks.touch(root, map_error(status), key, nkey);
    }
}

static void dummy_tap_mutation_callback(libcouchbase_t instance,
                                        const void *key,
                                        size_t nkey,
                                        const void *data,
                                        size_t nbytes,
                                        uint32_t flags,
                                        uint32_t exp,
                                        const void *es,
                                        size_t nes)
{
    (void)instance; (void)key; (void)nkey; (void)data; (void)nbytes;
    (void)flags; (void)exp; (void)es; (void)nes;
}

static void dummy_tap_deletion_callback(libcouchbase_t instance,
                                        const void *key,
                                        size_t nkey,
                                        const void *es,
                                        size_t nes)
{
    (void)instance; (void)key; (void)nkey; (void)es; (void)nes;

}

static void dummy_tap_flush_callback(libcouchbase_t instance,
                                     const void *es,
                                     size_t nes)
{
    (void)instance; (void)es; (void)nes;
}

static void dummy_tap_opaque_callback(libcouchbase_t instance,
                                      const void *es,
                                      size_t nes)
{
    (void)instance; (void)es; (void)nes;
}
static void dummy_tap_vbucket_set_callback(libcouchbase_t instance,
                                           uint16_t vbid,
                                           vbucket_state_t state,
                                           const void *es,
                                           size_t nes)
{
    (void)instance; (void)vbid; (void)state; (void)es; (void)nes;
}

static void dummy_get_callback(libcouchbase_t instance,
                               libcouchbase_error_t error,
                               const void *key, size_t nkey,
                               const void *bytes, size_t nbytes,
                               uint32_t flags, uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)bytes; (void)nbytes; (void)flags; (void)cas;
}

static void dummy_storage_callback(libcouchbase_t instance,
                                   libcouchbase_error_t error,
                                   const void *key, size_t nkey,
                                   uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)cas;
}

static void dummy_arithmetic_callback(libcouchbase_t instance,
                                      libcouchbase_error_t error,
                                      const void *key, size_t nkey,
                                      uint64_t value, uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)value; (void)cas;
}

static void dummy_remove_callback(libcouchbase_t instance,
                                  libcouchbase_error_t error,
                                  const void *key, size_t nkey)
{
    (void)instance; (void)error; (void)key; (void)nkey;
}

static void dummy_touch_callback(libcouchbase_t instance,
                                 libcouchbase_error_t error,
                                 const void *key, size_t nkey)
{
    (void)instance; (void)error; (void)key; (void)nkey;
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

    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_MUTATION] = tap_mutation_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_DELETE] = tap_deletion_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_FLUSH] = tap_flush_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_OPAQUE] = tap_opaque_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET] = tap_vbucket_set_handler;


    instance->response_handler[PROTOCOL_BINARY_CMD_GETQ] = getq_response_handler;
    instance->response_handler[PROTOCOL_BINARY_CMD_GATQ] = getq_response_handler;
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


