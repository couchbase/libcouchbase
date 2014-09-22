#ifndef LCB_DURABILITY_INTERNAL_H
#define LCB_DURABILITY_INTERNAL_H

#include "simplestring.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Here is the internal API for the durability functions.
 *
 * Durability works on polling multiple observe responses and waiting until a
 * key (or set of keys) have either been persisted, or the wait period has
 * expired.
 *
 * The operation maintains an internal counter which counts how many keys
 * do not have a conclusive observe response yet (i.e. how many do not have
 * their criteria satisfied yet). The operation is considered complete when
 * the counter reaches 0.
 */

/**Information a single entry in a durability set. Each entry contains a single
 * key */
typedef struct lcb_DURITEM_st {
    lcb_KEYBUF hashkey;
    lcb_U64 reqcas; /**< Last known CAS for the user */
    lcb_RESPENDURE result; /**< Result to be passed to user */
    struct lcb_DURSET_st *parent;
    unsigned char done; /**< Whether we have a conclusive result for this entry */
} lcb_DURITEM;

/**
 * A collection encompassing one or more entries which are to be checked for
 * persistence
 */
typedef struct lcb_DURSET_st {
    lcb_MULTICMD_CTX mctx; /**< Base class returned to user for scheduling */
    struct lcb_durability_opts_st opts; /**< Sanitized user options */
    struct lcb_DURITEM_st *entries; /**< Entries to poll for */
    unsigned nentries; /**< Number of items in the array */
    unsigned ents_alloced; /**< How many of those were allocated */
    struct { lcb_DURITEM ent; } single; /* For when we only have a single item */
    unsigned nremaining; /**< Number of entries remaining to poll for */
    int waiting; /**< Set if currently awaiting an observe callback */
    unsigned refcnt; /**< Reference count */
    unsigned next_state; /**< Internal state */
    genhash_t *ht; /**< Used to associate a key to its entry within dset_update */
    lcb_string kvbufs; /**< Backing storage for key buffers */
    const void *cookie; /**< User cookie */
    lcb_U32 us_timeout; /**< Timestamp of next timeout */
    void *timer;
    lcb_t instance;
} lcb_DURSET;

void
lcb_durability_dset_update(lcb_t instance, lcb_DURSET *dset, lcb_error_t err,
    const lcb_RESPOBSERVE *resp);
lcb_MULTICMD_CTX *
lcb_observe_ctx_dur_new(lcb_t instance);

#ifdef __cplusplus
}
#endif

#endif
