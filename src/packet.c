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
 * This file contains the functions to operate on the packets
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

void libmembase_server_start_packet(libmembase_server_t *c,
                                    const void *data,
                                    size_t size)
{
    assert(c->current_packet == (size_t)-1);
    c->current_packet = c->output.avail;

    if (size != 0) {
        grow_buffer(&c->output, size);
        memcpy(c->output.data + c->output.avail, data, size);
        c->output.avail += size;
    }
}

void libmembase_server_write_packet(libmembase_server_t *c,
                                    const void *data,
                                    size_t size)
{
    grow_buffer(&c->output, size);
    memcpy(c->output.data + c->output.avail, data, size);
    c->output.avail += size;
}

void libmembase_server_end_packet(libmembase_server_t *c)
{
    if (!c->instance->packet_filter(c->output.data + c->current_packet)) {
        c->output.avail = c->current_packet;
    }
    assert(c->current_packet != (size_t)-1);
    c->current_packet = (size_t)-1;
}

void libmembase_server_complete_packet(libmembase_server_t *c,
                                       const void *data,
                                       size_t size)
{
    assert(c->current_packet == (size_t)-1);
    if (c->instance->packet_filter(data)) {
        grow_buffer(&c->output, size);
        memcpy(c->output.data + c->output.avail, data, size);
        c->output.avail += size;
    }
}
