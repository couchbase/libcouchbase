/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2010 Membase, Inc
 * All rights reserved.
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

/* This is a minimalistic SASL implementation */
#ifndef SASL_ISASL_H
#define SASL_ISASL_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        unsigned long len;
        unsigned char data[1];
    } sasl_secret_t;

    typedef struct {
        unsigned long id;
        int (*proc)(void);
        void *context;
    } sasl_callback_t;

    /* define the different callback id's we support */
#define SASL_CB_USER 1
#define SASL_CB_AUTHNAME 2
#define SASL_CB_PASS 3
#define SASL_CB_LIST_END 4

    /* Define the error codes we support */
#define SASL_OK 1
#define SASL_CONTINUE 2
#define SASL_ERROR 3
#define SASL_BADPARAM 4

    typedef struct sasl_conn sasl_conn_t;

    int sasl_client_init(const sasl_callback_t *callbacks);

    void sasl_done(void);

    int sasl_client_new(const char *service,
                        const char *serverFQDN,
                        const char *iplocalport,
                        const char *ipremoteport,
                        const sasl_callback_t *prompt_supp,
                        unsigned int flags,
                        sasl_conn_t **pconn);

    void sasl_dispose(sasl_conn_t **pconn);

    int sasl_client_start(sasl_conn_t *conn,
                          const char *mechlist,
                          void **prompt_need,
                          const char **clientout,
                          unsigned int *clientoutlen,
                          const char **mech);

    int sasl_client_step(sasl_conn_t *a, const void *b, unsigned int c,
                         void *d, const void *e, void *f);

#ifdef __cplusplus
}
#endif

#endif
