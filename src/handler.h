#ifndef HANDLER_H
#define HANDLER_H 1

static inline void setup_lcb_get_resp_t(lcb_get_resp_t *resp,
                                        const void *key,
                                        lcb_size_t nkey,
                                        const void *bytes,
                                        lcb_size_t nbytes,
                                        lcb_uint32_t flags,
                                        lcb_cas_t cas,
                                        lcb_datatype_t datatype)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
    resp->v.v0.bytes = bytes;
    resp->v.v0.nbytes = nbytes;
    resp->v.v0.flags = flags;
    resp->v.v0.cas = cas;
    resp->v.v0.datatype = datatype;
}

static inline void setup_lcb_remove_resp_t(lcb_remove_resp_t *resp,
                                           const void *key,
                                           lcb_size_t nkey)
{
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
}

static inline void setup_lcb_store_resp_t(lcb_store_resp_t *resp,
                                          const void *key,
                                          lcb_size_t nkey,
                                          lcb_cas_t cas)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
    resp->v.v0.cas = cas;
}

static inline void setup_lcb_touch_resp_t(lcb_touch_resp_t *resp,
                                          const void *key,
                                          lcb_size_t nkey,
                                          lcb_cas_t cas)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
    resp->v.v0.cas = cas;
}

static inline void setup_lcb_unlock_resp_t(lcb_unlock_resp_t *resp,
                                           const void *key,
                                           lcb_size_t nkey)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
}

static inline void setup_lcb_arithmetic_resp_t(lcb_arithmetic_resp_t *resp,
                                               const void *key,
                                               lcb_size_t nkey,
                                               lcb_uint64_t value,
                                               lcb_cas_t cas)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
    resp->v.v0.value = value;
    resp->v.v0.cas = cas;
}

static inline void setup_lcb_observe_resp_t(lcb_observe_resp_t *resp,
                                            const void *key,
                                            lcb_size_t nkey,
                                            lcb_cas_t cas,
                                            lcb_observe_t status,
                                            int from_master,
                                            lcb_time_t ttp,
                                            lcb_time_t ttr)
{
    memset(resp, 0, sizeof(*resp));
    resp->version = 0;
    resp->v.v0.key = key;
    resp->v.v0.nkey = nkey;
    resp->v.v0.cas = cas;
    resp->v.v0.status = status;
    resp->v.v0.from_master = from_master;
    resp->v.v0.ttp = ttp;
    resp->v.v0.ttr = ttr;
}

#endif
