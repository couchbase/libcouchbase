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
 * This file contains the functions to operate on the packets
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

void libcouchbase_server_buffer_start_packet(libcouchbase_server_t *c,
                                             const void *command_cookie,
                                             ringbuffer_t *buff,
                                             ringbuffer_t *buff_cookie,
                                             const void *data,
                                             size_t size)
{
    struct libcouchbase_command_data_st ct;
    if (c->instance->histogram != 0) {
        ct.start = gethrtime();
    } else {
        ct.start = 0;
    }
    ct.cookie = command_cookie;

    if (!libcouchbase_ringbuffer_ensure_capacity(buff, size) ||
        !libcouchbase_ringbuffer_ensure_capacity(buff_cookie, size) ||
        libcouchbase_ringbuffer_write(buff, data, size) != size ||
        libcouchbase_ringbuffer_write(buff_cookie, &ct, sizeof(ct)) != sizeof(ct)) {
        abort();
    }
}

void libcouchbase_server_buffer_write_packet(libcouchbase_server_t *c,
                                             ringbuffer_t *buff,
                                             const void *data,
                                             size_t size)
{
    (void)c;
    if (!libcouchbase_ringbuffer_ensure_capacity(buff, size) ||
        libcouchbase_ringbuffer_write(buff, data, size) != size) {
        abort();
    }
}

void libcouchbase_server_buffer_end_packet(libcouchbase_server_t *c,
                                           ringbuffer_t *buff)
{
    (void)c;
    (void)buff;
}

void libcouchbase_server_buffer_complete_packet(libcouchbase_server_t *c,
                                                const void *command_cookie,
                                                ringbuffer_t *buff,
                                                ringbuffer_t *buff_cookie,
                                                const void *data,
                                                size_t size)
{

    libcouchbase_server_buffer_start_packet(c, command_cookie,
                                            buff, buff_cookie, data, size);
    libcouchbase_server_buffer_end_packet(c, buff);
}

void libcouchbase_server_start_packet(libcouchbase_server_t *c,
                                      const void *command_cookie,
                                      const void *data,
                                      size_t size)
{
    if (c->connected) {
        libcouchbase_server_buffer_start_packet(c, command_cookie,
                                                &c->output,
                                                &c->output_cookies,
                                                data, size);
    } else {
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
    (void)c;
}

void libcouchbase_server_complete_packet(libcouchbase_server_t *c,
                                         const void *command_cookie,
                                         const void *data,
                                         size_t size)
{
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
