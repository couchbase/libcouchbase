/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2026 Couchbase, Inc.
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
 * Drives the library against a KV server that answers a cluster configuration
 * request with a malformed reply, and checks that the library rejects it
 * instead of following the header's length fields off the end of the packet.
 *
 * The server is built into the example, so no cluster is required. It completes
 * the bootstrap handshake, answers the first GET_CLUSTER_CONFIG with a valid
 * single-node configuration, pushes a CLUSTERMAP_CHANGE_NOTIFICATION to provoke
 * a refresh, and answers the refresh with the header named on the command line.
 *
 * The client half mirrors an application that owns its event base and pumps it
 * from its own thread, which is how the failure was first observed.
 *
 * The I/O backend is resolved through lcb_create_io_ops, which dlopens the
 * plugin, so a build tree needs it on the loader path:
 *
 * LD_LIBRARY_PATH=build/lib ./malformed-config       # runs every case
 * LD_LIBRARY_PATH=build/lib ./malformed-config list  # names them
 * LD_LIBRARY_PATH=build/lib ./malformed-config empty-ext8-snappy
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>
#include <libcouchbase/couchbase.h>

#define OP_GET 0x00
#define OP_HELO 0x1f
#define OP_SASL_LIST_MECHS 0x20
#define OP_SASL_AUTH 0x21
#define OP_SELECT_BUCKET 0x89
#define OP_GET_CLUSTER_CONFIG 0xb5
#define OP_GET_ERROR_MAP 0xfe
#define OP_CLUSTERMAP_CHANGE_NOTIFICATION 0x01

#define MAGIC_REQ 0x80
#define MAGIC_RES 0x81
#define MAGIC_ARES 0x18 /* response carrying flexible framing extras */

#define FEATURE_TLS 0x02
#define DATATYPE_JSON 0x01
#define DATATYPE_SNAPPY 0x02

/**
 * The reply the server sends for the second GET_CLUSTER_CONFIG. Every case
 * declares a body of zero bytes while claiming non-zero length fields, which is
 * what leaves the parsed packet without a payload pointer.
 */
struct testcase {
    const char *name;
    uint8_t op; /* the request whose reply is malformed */
    uint8_t magic;
    uint8_t keylen;
    uint8_t ffextlen;
    uint8_t extlen;
    uint8_t datatype;
    const char *expect;
};

static const struct testcase cases[] = {
    /* The configuration reply reaches inflated_value(), which reads value(). */
    {"valid", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 0, 0, 0, DATATYPE_JSON,
     "a well-formed configuration; the control case"},
    {"config-plain", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 0, 0, 0, 0, "no body and no length fields; value is empty"},
    {"config-ext8", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 0, 0, 8, 0, "no body, 8 bytes of extras claimed"},
    {"config-ext8-snappy", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 0, 0, 8, DATATYPE_SNAPPY, "as above, marked compressed"},
    {"config-ext16-snappy", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 0, 0, 16, DATATYPE_SNAPPY,
     "no body, 16 bytes of extras claimed"},
    {"config-key8-snappy", OP_GET_CLUSTER_CONFIG, MAGIC_RES, 8, 0, 0, DATATYPE_SNAPPY,
     "no body, 8 bytes of key claimed"},
    {"config-ffext8-snappy", OP_GET_CLUSTER_CONFIG, MAGIC_ARES, 0, 8, 0, DATATYPE_SNAPPY,
     "no body, 8 bytes of framing extras claimed"},

    /* The GET reply reaches ext() and key(), which the value guards do not
     * cover: H_get reads the item flags out of the extras. */
    {"get-ext4", OP_GET, MAGIC_RES, 0, 0, 4, 0, "no body, 4 bytes of extras claimed (the item flags)"},
    {"get-key8", OP_GET, MAGIC_RES, 8, 0, 0, 0, "no body, 8 bytes of key claimed"},
    {"get-ffext4", OP_GET, MAGIC_ARES, 0, 4, 0, 0, "no body, 4 bytes of framing extras claimed"},
    {"get-short-body", OP_GET, MAGIC_RES, 0, 0, 8, 0, "4 bytes of body against 8 bytes of extras"},
};
#define NCASES (sizeof(cases) / sizeof(cases[0]))

static const struct testcase *current;
static int listen_fd = -1;
static int listen_port;
static int config_requests;
static char config_json[1024];

static void die(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t written = write(fd, p, len);
        if (written <= 0) {
            return -1;
        }
        p += written;
        len -= written;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ssize_t got = read(fd, p, len);
        if (got <= 0) {
            return -1;
        }
        p += got;
        len -= got;
    }
    return 0;
}

static int send_packet(int fd, uint8_t magic, uint8_t opcode, uint8_t b2, uint8_t b3, uint8_t extlen, uint8_t datatype,
                       uint32_t opaque, const void *body, uint32_t bodylen)
{
    uint8_t header[24];

    memset(header, 0, sizeof(header));
    header[0] = magic;
    header[1] = opcode;
    header[2] = b2;
    header[3] = b3;
    header[4] = extlen;
    header[5] = datatype;
    *(uint32_t *)(header + 8) = htonl(bodylen);
    *(uint32_t *)(header + 12) = opaque;

    if (write_all(fd, header, sizeof(header)) < 0) {
        return -1;
    }
    if (bodylen && body) {
        return write_all(fd, body, bodylen);
    }
    return 0;
}

/**
 * Acknowledges every feature the client asked for except TLS, which cannot be
 * honoured on a plaintext socket. DUPLEX has to be among them for the server to
 * be allowed to push the notification that provokes the second config request.
 */
static void reply_helo(int fd, const uint8_t *body, uint32_t bodylen, uint16_t keylen, uint32_t opaque)
{
    const uint8_t *features = body + keylen;
    uint32_t count = (bodylen - keylen) / 2;
    uint8_t acknowledged[128];
    uint32_t len = 0;
    uint32_t i;

    for (i = 0; i < count && len + 2 <= sizeof(acknowledged); i++) {
        uint16_t feature = ntohs(*(const uint16_t *)(features + i * 2));
        if (feature == FEATURE_TLS) {
            continue;
        }
        *(uint16_t *)(acknowledged + len) = htons(feature);
        len += 2;
    }
    send_packet(fd, MAGIC_RES, OP_HELO, 0, 0, 0, 0, opaque, acknowledged, len);
}

static void send_malformed(int fd, uint8_t opcode, uint32_t opaque, uint32_t bodylen)
{
    char body[8] = {0};
    uint8_t b2 = (current->magic == MAGIC_ARES) ? current->ffextlen : 0;
    uint8_t b3 = current->keylen;

    send_packet(fd, current->magic, opcode, b2, b3, current->extlen, current->datatype, opaque, bodylen ? body : NULL,
                bodylen);
}

static void reply_config(int fd, uint32_t opaque)
{
    int first = (++config_requests == 1);

    if (first || current->op != OP_GET_CLUSTER_CONFIG || strcmp(current->name, "valid") == 0) {
        send_packet(fd, MAGIC_RES, OP_GET_CLUSTER_CONFIG, 0, 0, 0, DATATYPE_JSON, opaque, config_json,
                    (uint32_t)strlen(config_json));
        if (first && current->op == OP_GET_CLUSTER_CONFIG) {
            /* epoch and revision, in the extras of a server-initiated packet.
             * Only needed to provoke the second configuration request. */
            uint8_t extras[16] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0xe9};
            send_packet(fd, MAGIC_REQ, OP_CLUSTERMAP_CHANGE_NOTIFICATION, 0, 0, sizeof(extras), 0, 0, extras,
                        sizeof(extras));
        }
        return;
    }

    send_malformed(fd, OP_GET_CLUSTER_CONFIG, opaque, 0);
}

static void *serve(void *arg)
{
    static const char *errmap = "{\"version\":1,\"revision\":1,\"errors\":{}}";

    (void)arg;
    for (;;) {
        int nodelay = 1;
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            return NULL;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        for (;;) {
            uint8_t header[24];
            uint8_t *body = NULL;
            uint32_t bodylen;
            uint16_t keylen;
            uint32_t opaque;

            if (read_all(fd, header, sizeof(header)) < 0) {
                break;
            }
            bodylen = ntohl(*(uint32_t *)(header + 8));
            keylen = ntohs(*(uint16_t *)(header + 2));
            opaque = *(uint32_t *)(header + 12);
            if (bodylen) {
                body = malloc(bodylen);
                if (read_all(fd, body, bodylen) < 0) {
                    free(body);
                    break;
                }
            }

            switch (header[1]) {
                case OP_HELO:
                    reply_helo(fd, body, bodylen, keylen, opaque);
                    break;
                case OP_GET_ERROR_MAP:
                    send_packet(fd, MAGIC_RES, header[1], 0, 0, 0, 0, opaque, errmap, (uint32_t)strlen(errmap));
                    break;
                case OP_SASL_LIST_MECHS:
                    send_packet(fd, MAGIC_RES, header[1], 0, 0, 0, 0, opaque, "PLAIN", 5);
                    break;
                case OP_GET_CLUSTER_CONFIG:
                    reply_config(fd, opaque);
                    break;
                case OP_GET:
                    /* "get-short-body" sends a body that the extras overrun;
                     * every other GET case sends none at all. */
                    send_malformed(fd, OP_GET, opaque, strcmp(current->name, "get-short-body") == 0 ? 4 : 0);
                    break;
                case OP_SASL_AUTH:
                case OP_SELECT_BUCKET:
                default:
                    send_packet(fd, MAGIC_RES, header[1], 0, 0, 0, 0, opaque, NULL, 0);
                    break;
            }
            free(body);
        }
        close(fd);
    }
}

static int start_server(void)
{
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    pthread_t thread;
    int reuse = 1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        die("socket");
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        die("bind");
    }
    if (listen(listen_fd, 8) < 0) {
        die("listen");
    }
    getsockname(listen_fd, (struct sockaddr *)&address, &address_len);
    listen_port = ntohs(address.sin_port);

    snprintf(config_json, sizeof(config_json),
             "{\"rev\":1000,\"revEpoch\":1,\"name\":\"default\",\"nodeLocator\":\"vbucket\","
             "\"uuid\":\"00000000\",\"bucketCapabilities\":[],\"bucketType\":\"membase\","
             "\"nodesExt\":[{\"services\":{\"mgmt\":8091,\"kv\":%d},\"hostname\":\"127.0.0.1\","
             "\"thisNode\":true}],\"vBucketServerMap\":{\"hashAlgorithm\":\"CRC\",\"numReplicas\":0,"
             "\"serverList\":[\"127.0.0.1:%d\"],\"vBucketMap\":[[0]]}}",
             listen_port, listen_port);

    return pthread_create(&thread, NULL, serve, NULL);
}

static lcb_io_opt_t create_libevent_io_ops(struct event_base *evbase)
{
    struct lcb_create_io_ops_st ciops;
    lcb_io_opt_t ioops;
    lcb_STATUS error;

    memset(&ciops, 0, sizeof(ciops));
    ciops.v.v0.type = LCB_IO_OPS_LIBEVENT;
    ciops.v.v0.cookie = evbase;

    error = lcb_create_io_ops(&ioops, &ciops);
    if (error != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create an IOOPS structure for libevent: %s\n", lcb_strerror_short(error));
        exit(EXIT_FAILURE);
    }

    return ioops;
}

static void get_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *resp)
{
    (void)instance;
    (void)cbtype;
    printf("  get: %s\n", lcb_strerror_short(lcb_respget_status(resp)));
}

static void bootstrap_callback(lcb_INSTANCE *instance, lcb_STATUS error)
{
    (void)instance;
    if (error != LCB_SUCCESS) {
        fprintf(stderr, "  bootstrap failed: %s\n", lcb_strerror_short(error));
    }
}

static int run_case(const struct testcase *testcase)
{
    char connstr[256];
    struct event_base *evbase;
    lcb_io_opt_t ioops;
    lcb_CREATEOPTS *options = NULL;
    lcb_INSTANCE *instance = NULL;
    lcb_STATUS error;
    int i;

    current = testcase;
    config_requests = 0;
    printf("%-22s %s\n", testcase->name, testcase->expect);
    fflush(stdout);

    /* PLAIN has to be named explicitly: the library declines to downgrade to it
     * on a socket that is not encrypted. */
    snprintf(connstr, sizeof(connstr),
             "couchbase://127.0.0.1:%d/default"
             "?config_total_timeout=5.0&config_node_timeout=3.0&sasl_mech_force=PLAIN",
             listen_port);

    evbase = event_base_new();
    ioops = create_libevent_io_ops(evbase);

    lcb_createopts_create(&options, LCB_TYPE_BUCKET);
    lcb_createopts_connstr(options, connstr, strlen(connstr));
    lcb_createopts_credentials(options, "Administrator", 13, "password", 8);
    lcb_createopts_io(options, ioops);
    error = lcb_create(&instance, options);
    lcb_createopts_destroy(options);
    if (error != LCB_SUCCESS) {
        fprintf(stderr, "Failed to create a libcouchbase instance: %s\n", lcb_strerror_short(error));
        exit(EXIT_FAILURE);
    }

    lcb_set_bootstrap_callback(instance, bootstrap_callback);
    lcb_install_callback(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);
    lcb_connect(instance);

    /* An application that owns the loop drives it in slices rather than handing
     * control to the library, so a malformed packet faults on its thread. */
    for (i = 0; i < 500; i++) {
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        usleep(2000);
    }

    if (testcase->op == OP_GET) {
        lcb_CMDGET *cmd = NULL;
        lcb_cmdget_create(&cmd);
        lcb_cmdget_key(cmd, "malformed", 9);
        lcb_get(instance, NULL, cmd);
        lcb_cmdget_destroy(cmd);
    }

    for (i = 0; i < 1000; i++) {
        event_base_loop(evbase, EVLOOP_NONBLOCK);
        usleep(2000);
    }

    lcb_destroy(instance);
    ioops->destructor(ioops);
    event_base_free(evbase);

    if (testcase->op == OP_GET_CLUSTER_CONFIG && config_requests < 2) {
        printf("  configuration was requested %d time(s); the case did not run\n", config_requests);
        return 1;
    }
    printf("  survived\n");
    return 0;
}

int main(int argc, char **argv)
{
    size_t i;
    int failures = 0;

    if (argc > 1 && strcmp(argv[1], "list") == 0) {
        for (i = 0; i < NCASES; i++) {
            printf("%-22s %s\n", cases[i].name, cases[i].expect);
        }
        return EXIT_SUCCESS;
    }

    if (start_server() != 0) {
        die("pthread_create");
    }
    printf("serving on 127.0.0.1:%d\n\n", listen_port);

    for (i = 0; i < NCASES; i++) {
        if (argc > 1 && strcmp(argv[1], cases[i].name) != 0) {
            continue;
        }
        failures += run_case(&cases[i]);
    }

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
