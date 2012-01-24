/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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
#ifndef LIBCOUCHBASE_DOC_H
#define LIBCOUCHBASE_DOC_H 1

#ifndef LIBCOUCHBASE_COUCHBASE_H
#error "Include libcouchbase/couchbase.h instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Execute CouchDB view matching given path and yield JSON result object.
     * The client should setup view_complete callback in order to fetch the
     * result. Also he can setup view_data callback to fetch response body
     * in chunks as soon as possible, it will be called each time the library
     * receive a data chunk from socket. The empty <tt>bytes</tt> argument
     * (NULL pointer and zero size) is the sign of end of response. Chunked
     * callback allows to save memory on large datasets.
     *
     * It doesn't automatically breakout like other operations when you use
     * libcouchbase_execute().
     *
     * @param instance The handle to libcouchbase
     * @param command_cookie A cookie passed to all of the notifications
     *                       from this command
     * @param path A view path string with optional query params (e.g. skip,
     *             limit etc.)
     * @param method HTTP message type to be sent to server
     * @param body The POST body for CouchDB view request. If the body
     *             parameter is NULL, function will use GET request.
     * @param nbody Size of body
     * @param chunked If true the client will use libcouchbase_doc_data_callback
     *                to notify about response and libcouchbase_doc_complete
     *                otherwise.
     */
    LIBCOUCHBASE_API
    libcouchbase_error_t libcouchbase_make_doc_request(libcouchbase_t instance,
                                                       const void *command_cookie,
                                                       const char *path,
                                                       libcouchbase_http_method_t method,
                                                       const void *body,
                                                       libcouchbase_size_t nbody,
                                                       int chunked);

    LIBCOUCHBASE_API
    libcouchbase_doc_complete_callback libcouchbase_set_doc_complete_callback(libcouchbase_t,
                                                                              libcouchbase_doc_complete_callback);

    LIBCOUCHBASE_API
    libcouchbase_doc_data_callback libcouchbase_set_doc_data_callback(libcouchbase_t,
                                                                      libcouchbase_doc_data_callback);


#ifdef __cplusplus
}
#endif

#endif
