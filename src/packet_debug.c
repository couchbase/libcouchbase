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
 * Small utility filter to dump packets in textual form...
 *
 * @author Trond Norbye
 * @todo add more documentation
 * @todo print to another place than stdout...
 */

#include "internal.h"
#include "packet_debug.h"

#include <ctype.h>

typedef void (*DEBUG_REQ_PACKET_FUNC)(protocol_binary_request_header *req);
typedef void (*DEBUG_RES_PACKET_FUNC)(protocol_binary_response_header *res);

static const char *get_vbucket_state(uint32_t s)
{
    vbucket_state_t state = ntohl(s);
    if (!is_valid_vbucket_state_t(state)) {
        return "Illegal state";
    }
    switch (state) {
    case vbucket_state_active: return "active";
    case vbucket_state_replica: return "replica";
    case vbucket_state_pending: return "pending";
    case vbucket_state_dead: return "dead";
    default:
        abort();
    }
}

static void print_string(uint8_t *data, size_t len)
{
    for (size_t ii = 0; ii < len; ++ii) {
        if (isgraph(data[ii])) {
            printf("%c", data[ii]);
        } else {
            printf("0x%02x", data[ii]);
        }
    }
}

static void print_hex_string(void *data, size_t len)
{
    uint8_t *b = data;
    printf("0x");
    for (size_t ii = 0; ii < len; ++ii) {
        printf("%02x", b[ii]);
    }
}

static void print_uint64(uint64_t val, bool both, bool lf)
{
    print_hex_string(&val, sizeof(val));
    if (both) {
        val = ntohll(val);
        printf(" (%llu)", (unsigned long long)val);
    }

    if (lf) {
        printf("\n");
    }
}

static void print_uint32(uint32_t val, bool both, bool lf)
{
    print_hex_string(&val, sizeof(val));
    if (both) {
        val = ntohl(val);
        printf(" (%u)", val);
    }

    if (lf) {
        printf("\n");
    }
}

static void print_uint16(uint16_t val, bool both, bool lf)
{
    print_hex_string(&val, sizeof(val));
    if (both) {
        val = ntohs(val);
        printf(" (%u)", val);
    }

    if (lf) {
        printf("\n");
    }
}

static void debug_tap_connect_request(protocol_binary_request_header *req)
{
    if (req->request.extlen < sizeof(uint32_t)) {
        printf("Unknown extras field\n");
        return ;
    }

    int nextbyte = sizeof(*req);
    protocol_binary_request_tap_connect *t = (void*)req;
    printf("Flags        (%02d-%02d): ",
           nextbyte, nextbyte + (int)sizeof(t->message.body.flags) - 1);
    print_uint32(t->message.body.flags, false, true);
    nextbyte += sizeof(t->message.body.flags);

    char buffer[1024];
    buffer[0] = '\0';

    uint32_t flags = ntohl(t->message.body.flags);
    if (flags & TAP_CONNECT_FLAG_BACKFILL) {
        strcat(buffer, ", backfill");
    }

    if (flags & TAP_CONNECT_FLAG_DUMP) {
        strcat(buffer, ", dump");
    }

    if (flags & TAP_CONNECT_FLAG_LIST_VBUCKETS) {
        strcat(buffer, ", list vbuckets");
    }

    if (flags & TAP_CONNECT_FLAG_TAKEOVER_VBUCKETS) {
        strcat(buffer, ", takeover vbuckets");
    }

    if (flags & TAP_CONNECT_SUPPORT_ACK) {
        strcat(buffer, ", support ack");
    }

    if (flags & TAP_CONNECT_REQUEST_KEYS_ONLY) {
        strcat(buffer, ", request keys only");
    }

    if (buffer[0] != '\0') {
        printf("  %s\n", buffer + 2);
    }

    uint8_t *ptr = (void*)(t->bytes + sizeof(t->bytes));
    uint16_t keylen = ntohs(req->request.keylen);
    if (keylen > 0) {
        printf("Name         (%02d-%02d): [", nextbyte, nextbyte + keylen - 1);
        print_string((void*)ptr, (size_t)keylen);
        printf("]\n");
        nextbyte += keylen;
        ptr += keylen;
    }

    if (flags & TAP_CONNECT_FLAG_BACKFILL) {
        uint64_t backfill;
        memcpy(&backfill, ptr, sizeof(backfill));
        printf("Backfill date(%02d-%02d): ",
               nextbyte, nextbyte + (int)sizeof(backfill) - 1);
        print_uint64(backfill, true, true);
        nextbyte += sizeof(backfill);
        ptr += sizeof(backfill);
    }

    if (flags & TAP_CONNECT_FLAG_LIST_VBUCKETS) {
        uint16_t num;
        uint16_t val;
        memcpy(&val, ptr, sizeof(val));
        num = ntohs(val);
        printf("VBucket list (%02d-%02d): \n",
               nextbyte, nextbyte + (2 * num) + 1);

        printf("    # listed (%02d-%02d): ",
               nextbyte, nextbyte + (int)sizeof(num) - 1);

        print_uint16(val, true, true);
        nextbyte += sizeof(num);
        ptr += sizeof(num);
        for (uint16_t ii = 0; ii < num; ++ii) {
            memcpy(&val, ptr, sizeof(num));
            if (ii < 5 || num < 10) {
                printf("    vbucket  (%02d-%02d): ",
                       nextbyte, nextbyte + (int)sizeof(val) - 1);
                print_uint16(val, true, true);
            } else if (ii == num - 1) {
                printf("     (skipped %d)\n", num - 5);
            }
            nextbyte += sizeof(val);
            ptr += sizeof(val);
        }
    }
    fflush(stdout);
}

// @todo fix engine-specific bytes!!

static void debug_tap_common_body(protocol_binary_request_tap_no_extras *req) {
    int nextbyte = sizeof(req->message.header);
    printf("Engine priv. (%02d-%02d): ",
           nextbyte,
           nextbyte + (int)sizeof(req->message.body.tap.enginespecific_length) - 1);
    print_uint16(req->message.body.tap.enginespecific_length, true, true);
    nextbyte += sizeof(req->message.body.tap.enginespecific_length);

    printf("Flags        (%02d-%02d): ",
           nextbyte,
           nextbyte + (int)sizeof(req->message.body.tap.flags) - 1);
    print_uint16(req->message.body.tap.flags, false, true);
    nextbyte += sizeof(req->message.body.tap.flags);

    if (req->message.body.tap.flags != 0) {
        uint16_t flags = ntohs(req->message.body.tap.flags);
        char buffer[1024];
        buffer[0] = '\0';

        if (flags & TAP_FLAG_ACK) {
            strcat(buffer, ", ack");
        }

        if (flags & TAP_FLAG_NO_VALUE) {
            strcat(buffer, ", value stripped");
        }

        if (buffer[0] != '\0') {
            printf("  %s\n", buffer + 2);
        }
    }

    printf("TTL             (%02d): %02x\n", nextbyte,
           req->message.body.tap.ttl);
    ++nextbyte;
    printf("Reserved        (%02d): %02x\n", nextbyte,
           req->message.body.tap.res1);
    ++nextbyte;
    printf("Reserved        (%02d): %02x\n", nextbyte,
           req->message.body.tap.res2);
    ++nextbyte;
    printf("Reserved        (%02d): %02x\n", nextbyte,
           req->message.body.tap.res3);
    ++nextbyte;
}

static void debug_tap_mutation_request(protocol_binary_request_header *req)
{
    debug_tap_common_body((void*)req);
    protocol_binary_request_tap_mutation *t = (void*)req;
    int nextbyte = sizeof(protocol_binary_request_tap_no_extras);
    printf("Item Flags   (%02d-%02d): ",
           nextbyte, nextbyte + (int)sizeof(t->message.body.item.flags) - 1);
    print_uint32(t->message.body.item.flags, false, true);
    nextbyte += sizeof(t->message.body.item.flags);
    printf("Item Expiry  (%02d-%02d): ",
           nextbyte, nextbyte + (int)sizeof(t->message.body.item.expiration) - 1);
    print_uint32(t->message.body.item.expiration, false, true);
    nextbyte += sizeof(t->message.body.item.expiration);

    uint8_t *ptr = (uint8_t*)(t + 1);
    uint16_t keylen = ntohs(req->request.keylen);
    if (keylen > 0) {
        printf("Key          (%02d-%02d): [", nextbyte, nextbyte + keylen - 1);
        print_string(ptr, (size_t)keylen);
        printf("]\n");
        ptr += keylen;
        nextbyte += keylen;
    }

    uint32_t bodylen = ntohl(req->request.bodylen);
    bodylen -= keylen;
    bodylen -= req->request.extlen;
    bodylen -= ntohs(t->message.body.tap.enginespecific_length);
    if (bodylen > 0) {
        printf("Value        (%02d-%02d): [", nextbyte, nextbyte + keylen - 1);
        print_string(ptr, (size_t)(bodylen > 20 ? 20 : bodylen));
        printf("%s]\n", bodylen > 20 ? " ...cut..." : "");
        ptr += bodylen;
        nextbyte += bodylen;
    }
}

static void debug_tap_delete_request(protocol_binary_request_header *req)
{
    protocol_binary_request_tap_no_extras *t = (void*)req;
    debug_tap_common_body(t);
    int nextbyte = sizeof(*t);
    uint16_t keylen = ntohs(req->request.keylen);
    if (keylen > 0) {
        printf("Key          (%02d-%02d): [", nextbyte, nextbyte + keylen - 1);
        print_string((void*)(t + 1), (size_t)keylen);
        printf("]\n");
    }
}

static void debug_tap_flush_request(protocol_binary_request_header *req)
{
    debug_tap_common_body((void*)req);
}

static void debug_tap_opaque_request(protocol_binary_request_header *req)
{
    debug_tap_common_body((void*)req);
}

static void debug_tap_vbucket_set_request(protocol_binary_request_header *req)
{
    protocol_binary_request_tap_vbucket_set *t = (void*)req;
    debug_tap_common_body((void*)req);
    int nextbyte = sizeof(protocol_binary_request_tap_no_extras);
    printf("VB State     (%02d-%02d): ",
           nextbyte, nextbyte + (int)sizeof(uint32_t) - 1);
    uint32_t state;
    memcpy(&state, t + 1, sizeof(state));
    print_uint32(state, false, false);
    printf(" (%s)\n", get_vbucket_state(state));
    nextbyte += sizeof(state);
}

static void debug_sasl_list_mechs_response(protocol_binary_response_header *res)
{
    int nextbyte = sizeof(*res);
    uint32_t length = ntohl(res->response.bodylen);
    if (res->response.status == 0) {
        printf("Mechanisms   (%02d-%02d): ",
               nextbyte, nextbyte + length - 1);
    } else {
        printf("Error message(%02d-%02d): ",
               nextbyte, nextbyte + length - 1);
    }
    print_string((void*)(res + 1), length);
    printf("\n");
}

static void debug_sasl_auth_request(protocol_binary_request_header *req)
{
    int nextbyte = sizeof(*req);
    uint16_t keylen = ntohs(req->request.keylen);
    uint32_t value = ntohl(req->request.bodylen) - keylen;

    uint8_t *ptr = (void*)(req + 1);
    printf("Mechanisms   (%02d-%02d): ",
               nextbyte, nextbyte + keylen - 1);
    print_string(ptr, keylen);
    printf("\n");
    ptr += keylen;
    nextbyte += keylen;
    printf("Auth token   (%02d-%02d): ",
               nextbyte, nextbyte + value - 1);
    print_string(ptr, value);
    printf("\n");
}

static void debug_sasl_auth_response(protocol_binary_response_header *res)
{
    int nextbyte = sizeof(*res);
    uint32_t length = ntohl(res->response.bodylen);
    printf("Info         (%02d-%02d): ",
           nextbyte, nextbyte + length - 1);
    print_string((void*)(res + 1), length);
    printf("\n");
}

struct {
    const char *t;
    DEBUG_REQ_PACKET_FUNC req;
    DEBUG_RES_PACKET_FUNC res;
} packets [] = {
    [PROTOCOL_BINARY_CMD_GET] = {
        .t = "get",
    },
    [PROTOCOL_BINARY_CMD_SET] = {
        .t = "set",
    },
    [PROTOCOL_BINARY_CMD_ADD] = {
        .t = "add",
    },
    [PROTOCOL_BINARY_CMD_REPLACE] = {
        .t = "repace",
    },
    [PROTOCOL_BINARY_CMD_DELETE] = {
        .t = "delete",
    },
    [PROTOCOL_BINARY_CMD_INCREMENT] = {
        .t = "increment",
    },
    [PROTOCOL_BINARY_CMD_DECREMENT] = {
        .t = "decrement",
    },
    [PROTOCOL_BINARY_CMD_QUIT] = {
        .t = "quit",
    },
    [PROTOCOL_BINARY_CMD_FLUSH] = {
        .t = "flush",
    },
    [PROTOCOL_BINARY_CMD_GETQ] = {
        .t = "getq",
    },
    [PROTOCOL_BINARY_CMD_NOOP] = {
        .t = "noop",
    },
    [PROTOCOL_BINARY_CMD_VERSION] = {
        .t = "version",
    },
    [PROTOCOL_BINARY_CMD_GETK] = {
        .t = "getk",
    },
    [PROTOCOL_BINARY_CMD_GETKQ] = {
        .t = "getkq",
    },
    [PROTOCOL_BINARY_CMD_APPEND] = {
        .t = "append",
    },
    [PROTOCOL_BINARY_CMD_PREPEND] = {
        .t = "prepend",
    },
    [PROTOCOL_BINARY_CMD_STAT] = {
        .t = "stat",
    },
    [PROTOCOL_BINARY_CMD_SETQ] = {
        .t = "setq",
    },
    [PROTOCOL_BINARY_CMD_ADDQ] = {
        .t = "addq",
    },
    [PROTOCOL_BINARY_CMD_REPLACEQ] = {
        .t = "replaceq",
    },
    [PROTOCOL_BINARY_CMD_DELETEQ] = {
        .t = "deleteq",
    },
    [PROTOCOL_BINARY_CMD_INCREMENTQ] = {
        .t = "incrementq",
    },
    [PROTOCOL_BINARY_CMD_DECREMENTQ] = {
        .t = "decrementq",
    },
    [PROTOCOL_BINARY_CMD_QUITQ] = {
        .t = "quitq",
    },
    [PROTOCOL_BINARY_CMD_FLUSHQ] = {
        .t = "flushq",
    },
    [PROTOCOL_BINARY_CMD_APPENDQ] = {
        .t = "appendq",
    },
    [PROTOCOL_BINARY_CMD_PREPENDQ] = {
        .t = "prependq",
    },
    [PROTOCOL_BINARY_CMD_VERBOSITY] = {
        .t = "verbosity",
    },
    [PROTOCOL_BINARY_CMD_SASL_LIST_MECHS] = {
        .t = "sasl list mechs",
        .res = debug_sasl_list_mechs_response,
    },
    [PROTOCOL_BINARY_CMD_SASL_AUTH] = {
        .t = "sasl auth",
        .req = debug_sasl_auth_request,
        .res = debug_sasl_auth_response
    },
    [PROTOCOL_BINARY_CMD_SASL_STEP] = {
        .t = "sasl step",
    },
    [PROTOCOL_BINARY_CMD_RGET] = {
        .t = "rget",
    },
    [PROTOCOL_BINARY_CMD_RSET] = {
        .t = "rset",
    },
    [PROTOCOL_BINARY_CMD_RSETQ] = {
        .t = "rsetq",
    },
    [PROTOCOL_BINARY_CMD_RAPPEND] = {
        .t = "rappend",
    },
    [PROTOCOL_BINARY_CMD_RAPPENDQ] = {
        .t = "rappendq",
    },
    [PROTOCOL_BINARY_CMD_RPREPEND] = {
        .t = "rprepend",
    },
    [PROTOCOL_BINARY_CMD_RPREPENDQ] = {
        .t = "rprependq",
    },
    [PROTOCOL_BINARY_CMD_RDELETE] = {
        .t = "rdelete",
    },
    [PROTOCOL_BINARY_CMD_RDELETEQ] = {
        .t = "rdeleteq",
    },
    [PROTOCOL_BINARY_CMD_RINCR] = {
        .t = "rincrement",
    },
    [PROTOCOL_BINARY_CMD_RINCRQ] = {
        .t = "rincrementq",
    },
    [PROTOCOL_BINARY_CMD_RDECR] = {
        .t = "rdecrement",
    },
    [PROTOCOL_BINARY_CMD_RDECRQ] = {
        .t = "rdecrementq",
    },
    [PROTOCOL_BINARY_CMD_SET_VBUCKET] = {
        .t = "set vbucket",
    },
    [PROTOCOL_BINARY_CMD_GET_VBUCKET] = {
        .t = "get vbucket",
    },
    [PROTOCOL_BINARY_CMD_DEL_VBUCKET] = {
        .t = "del vbucket",
    },
    [PROTOCOL_BINARY_CMD_TAP_CONNECT] = {
        .t = "tap connect",
        .req = debug_tap_connect_request
    },
    [PROTOCOL_BINARY_CMD_TAP_MUTATION] = {
        .t = "tap mutation",
        .req = debug_tap_mutation_request
    },
    [PROTOCOL_BINARY_CMD_TAP_DELETE] = {
        .t = "tap delete",
        .req = debug_tap_delete_request
    },
    [PROTOCOL_BINARY_CMD_TAP_FLUSH] = {
        .t = "tap flush",
        .req = debug_tap_flush_request
    },
    [PROTOCOL_BINARY_CMD_TAP_OPAQUE] = {
        .t = "tap opaque",
        .req = debug_tap_opaque_request
    },
    [PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET] = {
        .t = "tap vbucket set",
        .req = debug_tap_vbucket_set_request
    },
    [PROTOCOL_BINARY_CMD_LAST_RESERVED] = {
        .t = "last reserved",
    },
    [PROTOCOL_BINARY_CMD_SCRUB] = {
        .t = "scrub"
    },

    /* Ensure that the array is big enough ;-) */
    [0xff] = {
        .t = NULL, .req = NULL, .res = NULL
    }
};

static const char* respnse_names[] = {
    [PROTOCOL_BINARY_RESPONSE_SUCCESS] = "SUCCESS",
    [PROTOCOL_BINARY_RESPONSE_KEY_ENOENT] = "KEY_ENOENT",
    [PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS] = "KEY_EEXISTS",
    [PROTOCOL_BINARY_RESPONSE_E2BIG] = "E2BIG",
    [PROTOCOL_BINARY_RESPONSE_EINVAL] = "EINVAL",
    [PROTOCOL_BINARY_RESPONSE_NOT_STORED] = "NOT_STORED",
    [PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL] = "DELTA_BADVAL",
    [PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET] = "NOT_MY_VBUCKET",
    [PROTOCOL_BINARY_RESPONSE_AUTH_ERROR] = "AUTH_ERROR",
    [PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE] = "AUTH_CONTINUE",
    [PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND] = "UNKNOWN_COMMAND",
    [PROTOCOL_BINARY_RESPONSE_ENOMEM] = "ENOMEM",
    [PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED] = "NOT_SUPPORTED",
    [PROTOCOL_BINARY_RESPONSE_EINTERNAL] = "EINTERNAL",
    [PROTOCOL_BINARY_RESPONSE_EBUSY] = "EBUSY",
    [PROTOCOL_BINARY_RESPONSE_ETMPFAIL] = "ETMPFAIL"
};

static const char *get_command_name(uint8_t opcode)
{
    const char *ret;
    if ((ret = packets[opcode].t) == NULL) {
        ret = "unknown";
    }
    return ret;
}

static const char *get_response_name(uint16_t code)
{
    code = ntohs(code);
    const char *ret;
    if (code > PROTOCOL_BINARY_RESPONSE_ETMPFAIL ||
        (ret = respnse_names[code]) == NULL) {
        ret = "unknown";
    }
    return ret;
}

static void print_header(void)
{
    printf("  Byte/     0       |       1       |       2       |       3       |\n");
    printf("     /              |               |               |               |\n");
    printf("    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|");

}

static void print_byte(uint8_t b) {
    if (isgraph(b)) {
        printf("    %02x ('%c')   |", b, b);
    } else {
        printf("       %02x      |", b);
    }
}

static void dump_bytes(uint8_t *bytes, size_t len)
{
    for (size_t ii = 0; ii < len; ++ii) {
        if (ii % 4 == 0) {
            printf("\n    +---------------+---------------+---------------+---------------+\n");
            printf(" %3zu|", ii);
        }
        print_byte(bytes[ii]);
    }
}

LIBMEMBASE_API
bool libmembase_packet_debug(libmembase_t instance, const void *ptr)
{
    (void)instance;
    const protocol_binary_request_header *req = ptr;

    assert((req->request.magic == PROTOCOL_BINARY_REQ) ||
           (req->request.magic == PROTOCOL_BINARY_RES));

    print_header();
    dump_bytes((void*)req, ntohl(req->request.bodylen) + sizeof(*req));
    printf("\n\nHeader breakdown\n");
    printf("Field        (offset) (value)\n");
    printf("Magic            (0): 0x%02x (%s)\n",
           req->request.magic,
           req->request.magic == PROTOCOL_BINARY_REQ ?
           "PROTOCOL_BINARY_REQ" : "PROTOCOL_BINARY_RES");
    printf("Opcode           (1): 0x%02x (%s)\n",
           req->request.opcode, get_command_name(req->request.opcode));
    printf("Key length     (2-3): ");
    print_uint16(req->request.keylen, true, true);
    printf("Extra length     (4): 0x%02x\n", req->request.extlen);
    printf("Data type        (5): 0x%02x\n", req->request.datatype);
    if (req->request.magic == PROTOCOL_BINARY_REQ) {
        printf("vbucket        (6-7): ");
        print_uint16(req->request.vbucket, true, true);
    } else {
        printf("Status         (6-7): ");
        print_uint16(req->request.vbucket, false, false);
        printf(" (%s)\n", get_response_name(req->request.vbucket));
    }
    printf("Total body    (8-11): ");
    print_uint32(req->request.bodylen, true, true);
    printf("Opaque       (12-15): ");
    print_uint32(req->request.opaque, true, true);
    printf("CAS          (16-23): ");
    print_uint64(req->request.cas, true, true);

    if (req->request.magic == PROTOCOL_BINARY_REQ) {
        if (packets[req->request.opcode].req != NULL) {
            packets[req->request.opcode].req((void*)req);
        }
    } else {
        if (packets[req->request.opcode].res != NULL) {
            packets[req->request.opcode].res((void*)req);
        }
    }

    return true;
}
