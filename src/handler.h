#ifndef HANDLER_H
#define HANDLER_H 1

void setup_lcb_get_resp_t(lcb_get_resp_t *resp,
                          const void *key,
                          lcb_size_t nkey,
                          const void *bytes,
                          lcb_size_t nbytes,
                          lcb_uint32_t flags,
                          lcb_cas_t cas,
                          lcb_datatype_t datatype);
void setup_lcb_remove_resp_t(lcb_remove_resp_t *resp,
                             const void *key,
                             lcb_size_t nkey);
void setup_lcb_store_resp_t(lcb_store_resp_t *resp,
                            const void *key,
                            lcb_size_t nkey,
                            lcb_cas_t cas);
void setup_lcb_touch_resp_t(lcb_touch_resp_t *resp,
                            const void *key,
                            lcb_size_t nkey,
                            lcb_cas_t cas);
void setup_lcb_unlock_resp_t(lcb_unlock_resp_t *resp,
                             const void *key,
                             lcb_size_t nkey);
void setup_lcb_arithmetic_resp_t(lcb_arithmetic_resp_t *resp,
                                 const void *key,
                                 lcb_size_t nkey,
                                 lcb_uint64_t value,
                                 lcb_cas_t cas);
void setup_lcb_observe_resp_t(lcb_observe_resp_t *resp,
                              const void *key,
                              lcb_size_t nkey,
                              lcb_cas_t cas,
                              lcb_observe_t status,
                              int from_master,
                              lcb_time_t ttp,
                              lcb_time_t ttr);
void setup_lcb_server_stat_resp_t(lcb_server_stat_resp_t *resp,
                                  const char *server_endpoint,
                                  const void *key,
                                  lcb_size_t nkey,
                                  const void *bytes,
                                  lcb_size_t nbytes);
void setup_lcb_server_version_resp_t(lcb_server_version_resp_t *resp,
                                     const char *server_endpoint,
                                     const char *vstring,
                                     lcb_size_t nvstring);
void setup_lcb_verbosity_resp_t(lcb_verbosity_resp_t *resp,
                                const char *server_endpoint);

#endif
