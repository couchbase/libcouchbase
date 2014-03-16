#include "internal.h"

static void dummy_error_callback(lcb_t instance,
                                 lcb_error_t error,
                                 const char *errinfo)
{
    lcb_breakout(instance);
    (void)error;
    (void)errinfo;
}

static void dummy_stat_callback(lcb_t instance,
                                const void *cookie,
                                lcb_error_t error,
                                const lcb_server_stat_resp_t *resp)
{
    (void)instance;
    (void)error;
    (void)cookie;
    (void)resp;
}

static void dummy_version_callback(lcb_t instance,
                                   const void *cookie,
                                   lcb_error_t error,
                                   const lcb_server_version_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)resp;
    (void)error;
}

static void dummy_verbosity_callback(lcb_t instance,
                                     const void *cookie,
                                     lcb_error_t error,
                                     const lcb_verbosity_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)resp;
    (void)error;
}

static void dummy_get_callback(lcb_t instance,
                               const void *cookie,
                               lcb_error_t error,
                               const lcb_get_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_store_callback(lcb_t instance,
                                 const void *cookie,
                                 lcb_storage_t operation,
                                 lcb_error_t error,
                                 const lcb_store_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)operation;
    (void)error;
    (void)resp;
}

static void dummy_arithmetic_callback(lcb_t instance,
                                      const void *cookie,
                                      lcb_error_t error,
                                      const lcb_arithmetic_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_remove_callback(lcb_t instance,
                                  const void *cookie,
                                  lcb_error_t error,
                                  const lcb_remove_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_touch_callback(lcb_t instance,
                                 const void *cookie,
                                 lcb_error_t error,
                                 const lcb_touch_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_flush_callback(lcb_t instance,
                                 const void *cookie,
                                 lcb_error_t error,
                                 const lcb_flush_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)resp;
    (void)error;
}

static void dummy_http_complete_callback(lcb_http_request_t request,
                                         lcb_t instance,
                                         const void *cookie,
                                         lcb_error_t error,
                                         const lcb_http_resp_t *resp)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_http_data_callback(lcb_http_request_t request,
                                     lcb_t instance,
                                     const void *cookie,
                                     lcb_error_t error,
                                     const lcb_http_resp_t *resp)
{
    (void)request;
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_unlock_callback(lcb_t instance,
                                  const void *cookie,
                                  lcb_error_t error,
                                  const lcb_unlock_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_configuration_callback(lcb_t instance,
                                         lcb_configuration_t val)
{
    (void)instance;
    (void)val;
}

static void dummy_observe_callback(lcb_t instance,
                                   const void *cookie,
                                   lcb_error_t error,
                                   const lcb_observe_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

static void dummy_durability_callback(lcb_t instance,
                                      const void *cookie,
                                      lcb_error_t error,
                                      const lcb_durability_resp_t *resp)
{
    (void)instance;
    (void)cookie;
    (void)error;
    (void)resp;
}

void lcb_initialize_packet_handlers(lcb_t instance)
{
    instance->callbacks.get = dummy_get_callback;
    instance->callbacks.store = dummy_store_callback;
    instance->callbacks.arithmetic = dummy_arithmetic_callback;
    instance->callbacks.remove = dummy_remove_callback;
    instance->callbacks.touch = dummy_touch_callback;
    instance->callbacks.error = dummy_error_callback;
    instance->callbacks.stat = dummy_stat_callback;
    instance->callbacks.version = dummy_version_callback;
    instance->callbacks.http_complete = dummy_http_complete_callback;
    instance->callbacks.http_data = dummy_http_data_callback;
    instance->callbacks.flush = dummy_flush_callback;
    instance->callbacks.unlock = dummy_unlock_callback;
    instance->callbacks.configuration = dummy_configuration_callback;
    instance->callbacks.observe = dummy_observe_callback;
    instance->callbacks.verbosity = dummy_verbosity_callback;
    instance->callbacks.durability = dummy_durability_callback;
    instance->callbacks.errmap = lcb_errmap_default;
}

LIBCOUCHBASE_API
lcb_get_callback lcb_set_get_callback(lcb_t instance,
                                      lcb_get_callback cb)
{
    lcb_get_callback ret = instance->callbacks.get;
    if (cb != NULL) {
        instance->callbacks.get = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_store_callback lcb_set_store_callback(lcb_t instance,
                                          lcb_store_callback cb)
{
    lcb_store_callback ret = instance->callbacks.store;
    if (cb != NULL) {
        instance->callbacks.store = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_arithmetic_callback lcb_set_arithmetic_callback(lcb_t instance,
                                                    lcb_arithmetic_callback cb)
{
    lcb_arithmetic_callback ret = instance->callbacks.arithmetic;
    if (cb != NULL) {
        instance->callbacks.arithmetic = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_observe_callback lcb_set_observe_callback(lcb_t instance,
                                              lcb_observe_callback cb)
{
    lcb_observe_callback ret = instance->callbacks.observe;
    instance->callbacks.observe = cb;
    return ret;
}

LIBCOUCHBASE_API
lcb_remove_callback lcb_set_remove_callback(lcb_t instance,
                                            lcb_remove_callback cb)
{
    lcb_remove_callback ret = instance->callbacks.remove;
    if (cb != NULL) {
        instance->callbacks.remove = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_touch_callback lcb_set_touch_callback(lcb_t instance,
                                          lcb_touch_callback cb)
{
    lcb_touch_callback ret = instance->callbacks.touch;
    if (cb != NULL) {
        instance->callbacks.touch = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_stat_callback lcb_set_stat_callback(lcb_t instance,
                                        lcb_stat_callback cb)
{
    lcb_stat_callback ret = instance->callbacks.stat;
    if (cb != NULL) {
        instance->callbacks.stat = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_version_callback lcb_set_version_callback(lcb_t instance,
                                              lcb_version_callback cb)
{
    lcb_version_callback ret = instance->callbacks.version;
    if (cb != NULL) {
        instance->callbacks.version = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_error_callback lcb_set_error_callback(lcb_t instance,
                                          lcb_error_callback cb)
{
    lcb_error_callback ret = instance->callbacks.error;
    if (cb != NULL) {
        instance->callbacks.error = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_flush_callback lcb_set_flush_callback(lcb_t instance,
                                          lcb_flush_callback cb)
{
    lcb_flush_callback ret = instance->callbacks.flush;
    if (cb != NULL) {
        instance->callbacks.flush = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_http_complete_callback lcb_set_http_complete_callback(lcb_t instance,
                                                          lcb_http_complete_callback cb)
{
    lcb_http_complete_callback ret = instance->callbacks.http_complete;
    if (cb != NULL) {
        instance->callbacks.http_complete = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_http_data_callback lcb_set_http_data_callback(lcb_t instance,
                                                  lcb_http_data_callback cb)
{
    lcb_http_data_callback ret = instance->callbacks.http_data;
    if (cb != NULL) {
        instance->callbacks.http_data = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_unlock_callback lcb_set_unlock_callback(lcb_t instance,
                                            lcb_unlock_callback cb)
{
    lcb_unlock_callback ret = instance->callbacks.unlock;
    if (cb != NULL) {
        instance->callbacks.unlock = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_configuration_callback lcb_set_configuration_callback(lcb_t instance,
                                                          lcb_configuration_callback cb)
{
    lcb_configuration_callback ret = instance->callbacks.configuration;
    if (cb != NULL) {
        instance->callbacks.configuration = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_verbosity_callback lcb_set_verbosity_callback(lcb_t instance,
                                                  lcb_verbosity_callback cb)
{
    lcb_verbosity_callback ret = instance->callbacks.verbosity;
    if (cb != NULL) {
        instance->callbacks.verbosity = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_durability_callback lcb_set_durability_callback(lcb_t instance,
                                                    lcb_durability_callback cb)
{
    lcb_durability_callback ret = instance->callbacks.durability;
    if (cb != NULL) {
        instance->callbacks.durability = cb;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_errmap_callback lcb_set_errmap_callback(lcb_t instance,
                                            lcb_errmap_callback cb)
{
    lcb_errmap_callback ret = instance->callbacks.errmap;
    if (cb != NULL) {
        instance->callbacks.errmap = cb;
    }
    return ret;
}
