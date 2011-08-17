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
 * This file contains the functions to operate on the packets
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

void libcouchbase_server_buffer_start_packet(libcouchbase_server_t *c,
                                             const void *command_cookie,
                                             buffer_t *buff,
                                             buffer_t *buff_cookie,
                                             const void *data,
                                             size_t size)
{
    (void)c;
    grow_buffer(buff, size);
    memcpy(buff->data + buff->avail, data, size);
    buff->avail += size;

    struct libcouchbase_command_data_st ct = { .start = c->instance->histogram != 0 ? gethrtime() : 0,
                                               .cookie = command_cookie };

    grow_buffer(buff_cookie, sizeof(ct));
    memcpy(buff_cookie->data + buff_cookie->avail, &ct, sizeof(ct));
    buff_cookie->avail += sizeof(ct);
}

void libcouchbase_server_buffer_write_packet(libcouchbase_server_t *c,
                                             buffer_t *buff,
                                             const void *data,
                                             size_t size)
{
    (void)c;
    grow_buffer(buff, size);
    memcpy(buff->data + buff->avail, data, size);
    buff->avail += size;
}

void libcouchbase_server_buffer_end_packet(libcouchbase_server_t *c,
                                           buffer_t *buff)
{
    (void)c;
    (void)buff;
    // NOOP
}

void libcouchbase_server_buffer_complete_packet(libcouchbase_server_t *c,
                                                const void *command_cookie,
                                                buffer_t *buff,
                                                buffer_t *buff_cookie,
                                                const void *data,
                                                size_t size)
{
    (void)c;
    grow_buffer(buff, size);
    memcpy(buff->data + buff->avail, data, size);
    buff->avail += size;

    struct libcouchbase_command_data_st ct = { .start = c->instance->histogram != 0 ? gethrtime() : 0,
                                               .cookie = command_cookie };

    grow_buffer(buff_cookie, sizeof(ct));
    memcpy(buff_cookie->data + buff_cookie->avail, &ct, sizeof(ct));
    buff_cookie->avail += sizeof(ct);
}

void libcouchbase_server_start_packet(libcouchbase_server_t *c,
                                      const void *command_cookie,
                                      const void *data,
                                      size_t size)
{
    assert(c->current_packet == (size_t)-1);
    if (c->connected) {
        c->current_packet = c->output.avail;
        libcouchbase_server_buffer_start_packet(c, command_cookie,
                                                &c->output,
                                                &c->output_cookies,
                                                data, size);
    } else {
        c->current_packet = c->pending.avail;
        libcouchbase_server_buffer_start_packet(c, command_cookie,
                                                &c->pending,
                                                &c->pending_cookies,
                                                data, size);
    }
}

void libcouchbase_server_write_packet(libcouchbase_server_t *c,
                                      const void *data,
                                      size_t size)
{
    if (c->connected) {
        libcouchbase_server_buffer_write_packet(c, &c->output, data, size);
    } else {
        libcouchbase_server_buffer_write_packet(c, &c->pending, data, size);
    }
}

void libcouchbase_server_end_packet(libcouchbase_server_t *c)
{
    buffer_t *buff;

    if (c->connected) {
        buff = &c->output;
    } else {
        buff = &c->pending;
    }

    if (!c->instance->packet_filter(c->instance, buff->data + c->current_packet)) {
        buff->avail = c->current_packet;
    }
    assert(c->current_packet != (size_t)-1);
    c->current_packet = (size_t)-1;
}

void libcouchbase_server_complete_packet(libcouchbase_server_t *c,
                                         const void *command_cookie,
                                         const void *data,
                                         size_t size)
{
    assert(c->current_packet == (size_t)-1);
    if (c->instance->packet_filter(c->instance, data)) {
        if (c->connected) {
            libcouchbase_server_buffer_complete_packet(c, command_cookie,
                                                       &c->output,
                                                       &c->output_cookies,
                                                       data, size);
        } else {
            libcouchbase_server_buffer_complete_packet(c, command_cookie,
                                                       &c->pending,
                                                       &c->pending_cookies,
                                                       data, size);
        }
    }
}
