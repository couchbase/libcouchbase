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
#include "internal.h"

/*
 * Function to base64 encode a text string as described in RFC 3548
 *
 * @author Trond Norbye
 */

/**
 * An array of the legal charracters used for direct lookup
 */
static const char code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode up to 3 characters to 4 output character.
 *
 * @param s pointer to the input stream
 * @param d pointer to the output stream
 * @param num the number of characters from s to encode
 */
static void encode(const char *s, char *d, size_t num) {
    uint32_t val = 0;
    switch (num) {
    case 3: val = (uint32_t)((*s << 16) | (*(s + 1) << 8) | (*(s + 2))); break;
    case 2: val = (uint32_t)((*s << 16) | (*(s + 1) << 8)); break;
    case 1: val = (uint32_t)((*s << 16)); break;
    default:
        abort();
    }

    *(d+3) = '=';
    *(d+2) = '=';

    if (num == 3) {
        *(d+3) =  code[val & 63] ;
    }
    if (num != 1) {
        *(d+2) = code[(val >> 6) & 63];
    }

    *(d+1) = code[(val >> 12) & 63];
    *d = code[(val >> 18) & 63];
}

/**
 * Base64 encode a string into an output buffer.
 * @param src string to encode
 * @param dst destination buffer
 * @param sz size of destination buffer
 * @return 0 if success, -1 if the destination buffer isn't big enough
 */
int libcouchbase_base64_encode(const char *src, char *dst, size_t sz) {
    size_t len = strlen(src);
    size_t triplets = len / 3;
    size_t rest = len % 3;
    if (sz < (size_t)((triplets + 1) * 4)) {
        return -1;
    }
    for (size_t ii = 0; ii < triplets; ++ii) {
        encode(src, dst, 3);
        src += 3;
        dst += 4;
    }
    if (rest > 0) {
        encode(src, dst, rest);
    }
    dst += 4;
    *dst = '\0';
    return 0;
}
