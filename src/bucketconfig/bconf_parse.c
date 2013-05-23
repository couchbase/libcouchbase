/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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
 * This file contains parsing routines for the vbucket stream
 * @author Mark Nunberg
 */

#include "internal.h"


/** Don't create any buffers less than 2k */
const lcb_size_t min_buffer_size = 2048;


/**
 * Grow a buffer so that it got at least a minimum size of available space.
 * I'm <b>always</b> allocating one extra byte to add a '\0' so that if you
 * use one of the str* functions you won't run into random memory.
 *
 * @param buffer the buffer to grow
 * @param min_free the minimum amount of free space I need
 * @return 1 if success, 0 otherwise
 */
int grow_buffer(buffer_t *buffer, lcb_size_t min_free)
{
    if (min_free == 0) {
        /*
        ** no minimum size requested, just ensure that there is at least
        ** one byte there...
        */
        min_free = 1;
    }

    if (buffer->size - buffer->avail < min_free) {
        lcb_size_t next = buffer->size ? buffer->size << 1 : min_buffer_size;
        char *ptr;

        while ((next - buffer->avail) < min_free) {
            next <<= 1;
        }

        ptr = realloc(buffer->data, next + 1);
        if (ptr == NULL) {
            return 0;
        }
        ptr[next] = '\0';
        buffer->data = ptr;
        buffer->size = next;
    }

    return 1;
}


/**
 * Try to parse the piece of data we've got available to see if we got all
 * the data for this "chunk"
 * @param instance the instance containing the data
 * @return 1 if we got all the data we need, 0 otherwise
 */
static int parse_chunk(lcb_t instance)
{
    buffer_t *buffer = &instance->vbucket_stream.chunk;
    assert(instance->vbucket_stream.chunk_size != 0);

    if (instance->vbucket_stream.chunk_size == (lcb_size_t) - 1) {
        char *ptr = strstr(buffer->data, "\r\n");
        long val;
        if (ptr == NULL) {
            /* We need more data! */
            return 0;
        }
        ptr += 2;
        val = strtol(buffer->data, NULL, 16);
        val += 2;
        instance->vbucket_stream.chunk_size = (lcb_size_t)val;
        buffer->avail -= (lcb_size_t)(ptr - buffer->data);
        memmove(buffer->data, ptr, buffer->avail);
        buffer->data[buffer->avail] = '\0';
    }

    if (buffer->avail < instance->vbucket_stream.chunk_size) {
        /* need more data! */
        return 0;
    }

    return 1;
}

/**
 * Try to parse the headers in the input chunk.
 *
 * @param instance the instance containing the data
 * @return 0 success, 1 we need more data, -1 incorrect response
 */
static int parse_header(lcb_t instance)
{
    int response_code;

    buffer_t *buffer = &instance->vbucket_stream.chunk;
    char *ptr = strstr(buffer->data, "\r\n\r\n");

    if (ptr != NULL) {
        *ptr = '\0';
        ptr += 4;
    } else if ((ptr = strstr(buffer->data, "\n\n")) != NULL) {
        *ptr = '\0';
        ptr += 2;
    } else {
        /* We need more data! */
        return 1;
    }

    /* parse the headers I care about... */
    if (sscanf(buffer->data, "HTTP/1.1 %d", &response_code) != 1) {
        lcb_error_handler(instance, LCB_PROTOCOL_ERROR,
                          buffer->data);
    } else if (response_code != 200) {
        lcb_error_t err;
        switch (response_code) {
        case 401:
            err = LCB_AUTH_ERROR;
            break;
        case 404:
            err = LCB_BUCKET_ENOENT;
            break;
        default:
            err = LCB_PROTOCOL_ERROR;
            break;
        }

        lcb_error_handler(instance, err, buffer->data);

        if (instance->compat.type == LCB_CACHED_CONFIG) {
            /* cached config should try a bootsrapping logic */
            return -2;
        }

        return -1;
    }

    if (instance->type == LCB_TYPE_BUCKET &&
            strstr(buffer->data, "Transfer-Encoding: chunked") == NULL &&
            strstr(buffer->data, "Transfer-encoding: chunked") == NULL) {
        lcb_error_handler(instance, LCB_PROTOCOL_ERROR,
                          buffer->data);
        return -1;
    }

    instance->vbucket_stream.header = strdup(buffer->data);
    /* realign remaining data.. */
    buffer->avail -= (lcb_size_t)(ptr - buffer->data);
    memmove(buffer->data, ptr, buffer->avail);
    buffer->data[buffer->avail] = '\0';
    instance->vbucket_stream.chunk_size = (lcb_size_t) - 1;

    return 0;
}


void lcb_parse_vbucket_stream(lcb_t instance)
{
    buffer_t *buffer = &instance->vbucket_stream.chunk;
    lcb_size_t nw, expected;

    if (!grow_buffer(buffer, instance->input.nbytes+1)) {
        lcb_error_handler(instance, LCB_CLIENT_ENOMEM,
                          "Failed to allocate memory");
        return;
    }
    /**
     * Read any data from the ringbuffer into our 'buffer_t' structure.
     * TODO: Refactor this code to use ringbuffer directly, so we don't need
     * to copy
     */
    expected = instance->input.nbytes;
    assert(buffer->data);

    /**
     * XXX: The semantics of the buffer fields are confusing. Normally,
     * 'avail' is the length of the allocated buffer and 'size' is the length
     * of the used contents within that buffer. Here however it appears to be
     * that 'size' is the allocated length, and 'avail' is the length of the
     * contents within the buffer
     */
    nw = ringbuffer_read(&instance->input,
                         buffer->data + buffer->avail,
                         buffer->size - buffer->avail);

    assert(nw == expected);
    buffer->avail += nw;
    buffer->data[buffer->avail] = '\0';

    if (instance->vbucket_stream.header == NULL) {
        switch (parse_header(instance)) {
        case -1:
            /* error already reported */
            lcb_maybe_breakout(instance);
            return;
        case -2:
            instance->backup_idx++;
            if (lcb_switch_to_backup_node(instance, LCB_CONNECT_ERROR,
                                          "Failed to parse REST response") != -1) {
                return;
            }
            /* We should try another server */
            return;
        default:
            ;
        }
    }

    if (instance->vbucket_stream.header != NULL) {
        int done;
        do {
            done = 1;
            if (parse_chunk(instance)) {
                /* @todo copy the data over to the input buffer there.. */
                char *term;
                if (!grow_buffer(&instance->vbucket_stream.input,
                                 instance->vbucket_stream.chunk_size)) {
                    abort();
                }
                memcpy(instance->vbucket_stream.input.data + instance->vbucket_stream.input.avail,
                       buffer->data, instance->vbucket_stream.chunk_size);
                instance->vbucket_stream.input.avail += instance->vbucket_stream.chunk_size;
                /* the chunk includes the \r\n at the end.. We shouldn't add
                ** that..
                */
                instance->vbucket_stream.input.avail -= 2;
                instance->vbucket_stream.input.data[instance->vbucket_stream.input.avail] = '\0';

                /* realign buffer */
                memmove(buffer->data, buffer->data + instance->vbucket_stream.chunk_size,
                        buffer->avail - instance->vbucket_stream.chunk_size);
                buffer->avail -= instance->vbucket_stream.chunk_size;
                buffer->data[buffer->avail] = '\0';
                term = strstr(instance->vbucket_stream.input.data, "\n\n\n\n");
                if (term != NULL) {
                    *term = '\0';
                    instance->vbucket_stream.input.avail -= 4;
                    lcb_update_vbconfig(instance, NULL);
                }

                instance->vbucket_stream.chunk_size = (lcb_size_t) - 1;
                if (buffer->avail > 0) {
                    done = 0;
                }
            }
        } while (!done);
    }

    if (instance->type != LCB_TYPE_BUCKET) {
        instance->connection_ready = 1;
        lcb_maybe_breakout(instance);
    } /* LCB_TYPE_BUCKET connection must receive valid config */

    /* Make it known that this was a success. */
    lcb_error_handler(instance, LCB_SUCCESS, NULL);
}
