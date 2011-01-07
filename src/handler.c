/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Membase, Inc.
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

static void dummy_request_handler(libmembase_server_t *server,
                                 protocol_binary_request_header *req)
{
#ifdef DEBUG
    fprintf(stderr, "Received request packet %02x\n", req->request.opcode);
#endif
    (void)server;
    (void)req;
}

static void dummy_response_handler(libmembase_server_t *server,
                                   protocol_binary_response_header *res)
{
#ifdef DEBUG
    fprintf(stderr, "Received response packet %02x %04x\n",
            res->response.opcode, ntohs(res->response.status));
#endif
    (void)server;
    (void)res;
}

static void getq_response_handler(libmembase_server_t *server,
                                  protocol_binary_response_header *res)
{
    libmembase_t root = server->instance;
    protocol_binary_response_getq *getq = (void*)res;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;

    assert(req->request.opaque == res->response.opaque);
    const char *key = (void*)(req + 1);
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);

    size_t nbytes = ntohl(res->response.bodylen);
    nbytes -= nkey - res->response.extlen;

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        char *bytes = (void*)res;
        bytes += sizeof(getq->bytes);
        root->callbacks.get(root, LIBMEMBASE_SUCCESS, key, nkey,
                            bytes, nbytes,
                            ntohl(getq->message.body.flags),
                            res->response.cas);
    } else {
        root->callbacks.get(root, LIBMEMBASE_KEY_ENOENT, key, nkey,
                            NULL, 0, 0, 0);
    }
}

static void delete_response_handler(libmembase_server_t *server,
                                     protocol_binary_response_header *res)
{
    libmembase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    assert(req->request.opaque == res->response.opaque);

    const char *key = (void*)(req + 1);
    key += req->request.extlen;
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        root->callbacks.remove(root, LIBMEMBASE_SUCCESS, key, nkey);
    } else {
        root->callbacks.remove(root, LIBMEMBASE_ERROR, key, nkey);
    }
}

static void storage_response_handler(libmembase_server_t *server,
                                     protocol_binary_response_header *res)
{
    libmembase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;

    assert(req->request.opaque == res->response.opaque);

    const char *key = (void*)(req + 1);
    key += req->request.extlen;
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        root->callbacks.storage(root, LIBMEMBASE_SUCCESS, key, nkey,
                                res->response.cas);
    } else {
        root->callbacks.storage(root, LIBMEMBASE_ERROR, key, nkey,
                                res->response.cas);
    }
}

static void arithmetic_response_handler(libmembase_server_t *server,
                                        protocol_binary_response_header *res)
{
    libmembase_t root = server->instance;
    protocol_binary_request_header *req = (void*)server->cmd_log.data;
    assert(req->request.opaque == res->response.opaque);

    const char *key = (void*)(req + 1);
    key += req->request.extlen;
    size_t nkey = ntohs(req->request.keylen);
    uint16_t status = ntohs(res->response.status);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        uint64_t value;
        memcpy(&value, res + 1, sizeof(value));
        value = ntohll(value);
        root->callbacks.arithmetic(root, LIBMEMBASE_SUCCESS, key, nkey,
                                   value,
                                   res->response.cas);
    } else {
        root->callbacks.arithmetic(root, LIBMEMBASE_ERROR, key, nkey,
                                   0, 0);
    }
}

static void tap_mutation_handler(libmembase_server_t *server,
                                 protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (void*)req;
    protocol_binary_request_tap_mutation *mutation = (void*)req;
    uint32_t flags = ntohl(mutation->message.body.item.flags);
    uint32_t exp = ntohl(mutation->message.body.item.expiration);
    uint16_t nkey = ntohs(req->request.keylen);

    char *es = packet + sizeof(mutation->bytes);
    uint16_t nes = ntohs(mutation->message.body.tap.enginespecific_length);
    char *key = es + nes;
    void *data = key + nkey;
    uint32_t nbytes = ntohl(req->request.bodylen) - req->request.extlen - nes - nkey;

    libmembase_t root = server->instance;
    root->callbacks.tap_mutation(root, key, nkey, data, nbytes,
                                 flags, exp, es, nes);
}

static void tap_deletion_handler(libmembase_server_t *server,
                                 protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (void*)req;
    protocol_binary_request_tap_delete *deletion = (void*)req;
    uint16_t nkey = ntohs(req->request.keylen);
    char *es = packet + sizeof(deletion->bytes);
    uint16_t nes = ntohs(deletion->message.body.tap.enginespecific_length);
    char *key = es + nes;
    libmembase_t root = server->instance;
    root->callbacks.tap_deletion(root, key, nkey, es, nes);
}

static void tap_flush_handler(libmembase_server_t *server,
                              protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (void*)req;
    protocol_binary_request_tap_flush *flush = (void*)req;
    char *es = packet + sizeof(flush->bytes);
    uint16_t nes = ntohs(flush->message.body.tap.enginespecific_length);
    libmembase_t root = server->instance;
    root->callbacks.tap_flush(root, es, nes);
}

static void tap_opaque_handler(libmembase_server_t *server,
                               protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (void*)req;
    protocol_binary_request_tap_opaque *opaque = (void*)req;
    char *es = packet + sizeof(opaque->bytes);
    uint16_t nes = ntohs(opaque->message.body.tap.enginespecific_length);
    libmembase_t root = server->instance;
    root->callbacks.tap_opaque(root, es, nes);
}

static void tap_vbucket_set_handler(libmembase_server_t *server,
                                    protocol_binary_request_header *req)
{
    // @todo verify that the size is correct!
    char *packet = (void*)req;
    protocol_binary_request_tap_vbucket_set *vbset = (void*)req;
    char *es = packet + sizeof(vbset->bytes);
    uint16_t nes = ntohs(vbset->message.body.tap.enginespecific_length);
    uint32_t state;
    memcpy(&state, es + nes, sizeof(state));
    state = ntohl(state);
    libmembase_t root = server->instance;
    root->callbacks.tap_vbucket_set(root, ntohs(req->request.vbucket),
                                    state, es, nes);
}

static void sasl_list_mech_response_handler(libmembase_server_t *server,
                                            protocol_binary_response_header *res)
{
    assert(ntohs(res->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);


    const char *data;
    const char *chosenmech;
    unsigned int len;
    assert(sasl_client_start(server->sasl_conn, (const char *)(res + 1),
                             NULL, &data, &len, &chosenmech) == SASL_OK);

    size_t keylen = strlen(chosenmech);
    size_t bodysize = keylen + len;

    protocol_binary_request_no_extras req = {
        .message.header.request = {
            .magic = PROTOCOL_BINARY_REQ,
            .opcode = PROTOCOL_BINARY_CMD_SASL_AUTH,
            .keylen = ntohs((uint16_t)keylen),
            .datatype = PROTOCOL_BINARY_RAW_BYTES,
            .bodylen = ntohl((uint32_t)(bodysize))
        }
    };
    libmembase_server_buffer_start_packet(server, &server->output,
                                          req.bytes, sizeof(req.bytes));
    libmembase_server_buffer_write_packet(server, &server->output,
                                          chosenmech, keylen);
    libmembase_server_buffer_write_packet(server, &server->output, data, len);
    libmembase_server_buffer_end_packet(server, &server->output);

    // send the data and add it to libevent..
    libmembase_server_event_handler(0, EV_WRITE, server);
}

static void sasl_auth_response_handler(libmembase_server_t *server,
                                       protocol_binary_response_header *res)
{
    uint16_t ret = ntohs(res->response.status);
    if (ret == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
        libmembase_server_connected(server);
    } else if (ret == PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE) {
        // I don't know how to step yet ;-)
        abort();
    } else {
        abort();
    }
}

static void sasl_step_response_handler(libmembase_server_t *server,
                                       protocol_binary_response_header *res)
{
    (void)server;
    (void)res;

    // I don't have sasl step support yet ;-)
    abort();

    // I should put the server to the notification!
    if (server->instance->vbucket_state_listener != NULL) {
        server->instance->vbucket_state_listener(server);
    }
}

static void dummy_tap_mutation_callback(libmembase_t instance,
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

static void dummy_tap_deletion_callback(libmembase_t instance,
                                        const void *key,
                                        size_t nkey,
                                        const void *es,
                                        size_t nes)
{
    (void)instance; (void)key; (void)nkey; (void)es; (void)nes;

}

static void dummy_tap_flush_callback(libmembase_t instance,
                                     const void *es,
                                     size_t nes)
{
    (void)instance; (void)es; (void)nes;
}

static void dummy_tap_opaque_callback(libmembase_t instance,
                                      const void *es,
                                      size_t nes)
{
    (void)instance; (void)es; (void)nes;
}
static void dummy_tap_vbucket_set_callback(libmembase_t instance,
                                           uint16_t vbid,
                                           vbucket_state_t state,
                                           const void *es,
                                           size_t nes)
{
    (void)instance; (void)vbid; (void)state; (void)es; (void)nes;
}

static void dummy_get_callback(libmembase_t instance,
                               libmembase_error_t error,
                               const void *key, size_t nkey,
                               const void *bytes, size_t nbytes,
                               uint32_t flags, uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)bytes; (void)nbytes; (void)flags; (void)cas;
}

static void dummy_storage_callback(libmembase_t instance,
                                   libmembase_error_t error,
                                   const void *key, size_t nkey,
                                   uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)cas;
}

static void dummy_arithmetic_callback(libmembase_t instance,
                                      libmembase_error_t error,
                                      const void *key, size_t nkey,
                                      uint64_t value, uint64_t cas)
{
    (void)instance; (void)error; (void)key; (void)nkey;
    (void)value; (void)cas;
}

static void dummy_remove_callback(libmembase_t instance,
                                  libmembase_error_t error,
                                  const void *key, size_t nkey)
{
    (void)instance; (void)error; (void)key; (void)nkey;
}


void libmembase_initialize_packet_handlers(libmembase_t instance)
{
    for (int ii = 0; ii < 0x100; ++ii) {
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

    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_MUTATION] = tap_mutation_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_DELETE] = tap_deletion_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_FLUSH] = tap_flush_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_OPAQUE] = tap_opaque_handler;
    instance->request_handler[PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET] = tap_vbucket_set_handler;


    instance->response_handler[PROTOCOL_BINARY_CMD_GETQ] = getq_response_handler;
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
}

LIBMEMBASE_API
void libmembase_set_callbacks(libmembase_t instance,
                              libmembase_callback_t *callbacks)
{
    if (callbacks->get != NULL) {
        instance->callbacks.get = callbacks->get;
    }

    if (callbacks->storage != NULL) {
        instance->callbacks.storage = callbacks->storage;
    }

    if (callbacks->arithmetic != NULL) {
        instance->callbacks.arithmetic = callbacks->arithmetic;
    }

    if (callbacks->remove != NULL) {
        instance->callbacks.remove = callbacks->remove;
    }

    if (callbacks->tap_mutation != NULL) {
        instance->callbacks.tap_mutation = callbacks->tap_mutation;
    }

    if (callbacks->tap_deletion != NULL) {
        instance->callbacks.tap_deletion = callbacks->tap_deletion;
    }

    if (callbacks->tap_flush != NULL) {
        instance->callbacks.tap_flush = callbacks->tap_flush;
    }

    if (callbacks->tap_opaque != NULL) {
        instance->callbacks.tap_opaque = callbacks->tap_opaque;
    }

    if (callbacks->tap_vbucket_set != NULL) {
        instance->callbacks.tap_vbucket_set = callbacks->tap_vbucket_set;
    }
}
