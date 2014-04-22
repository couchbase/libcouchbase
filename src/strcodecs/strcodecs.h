#ifndef LCB_STRCODECS_H
#define LCB_STRCODECS_H
#ifdef __cplusplus
extern "C" {
#endif
#include <libcouchbase/couchbase.h>
lcb_error_t lcb_urlencode_path(const char *path,
                               lcb_size_t npath,
                               char **out,
                               lcb_size_t *nout);

/**
 * Base64 encode a string into an output buffer.
 * @param src string to encode
 * @param dst destination buffer
 * @param sz size of destination buffer
 * @return 0 if success, -1 if the destination buffer isn't big enough
 */
int lcb_base64_encode(const char *src, char *dst, lcb_size_t sz);

#ifdef __cplusplus
}
#endif
#endif
