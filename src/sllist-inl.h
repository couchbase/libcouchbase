#include "sllist.h"
#include <stdlib.h>
#include <assert.h>

#ifndef INLINE
#ifdef _MSC_VER
#define INLINE __inline
#elif __GNUC__
#define INLINE __inline__
#else
#define INLINE inline
#endif /* MSC_VER */
#endif /* !INLINE */


static INLINE int
sllist_contains(sllist_root *list, sllist_node *item)
{
    sllist_node *ll;
    SLLIST_FOREACH(list, ll) {
        if (item == ll) {
            return 1;
        }
    }
    return 0;
}

/* #define SLLIST_DEBUG */

#ifdef SLLIST_DEBUG
#define slist_sanity_insert(l, n) assert(!slist_contains(l, n))
#else
#define slist_sanity_insert(l, n)
#endif

static INLINE void
slist_iter_init_at(sllist_node *node, sllist_iterator *iter)
{
    iter->cur = node->next;
    iter->prev = node;
    iter->removed = 0;

    if (iter->cur) {
        iter->next = iter->cur->next;
    } else {
        iter->next = NULL;
    }
}

static INLINE void
slist_iter_init(const sllist_root *list, sllist_iterator *iter)
{
    slist_iter_init_at((sllist_node *)&list->first, iter);
}

static INLINE void
slist_iter_incr(sllist_root *list, sllist_iterator *iter)
{
    if (!iter->removed) {
        iter->prev = iter->prev->next;
    } else {
        iter->removed = 0;
    }

    if ((iter->cur = iter->next)) {
        iter->next = iter->cur->next;
    } else {
        iter->next = NULL;
    }

    assert(iter->cur != iter->prev);

    (void)list;
}

static INLINE void
sllist_iter_remove(sllist_root *list, sllist_iterator *iter)
{
    iter->prev->next = iter->next;
    /** GCC strict aliasing. Yay. */
    if (iter->prev->next == NULL && (void *)iter->prev == (void *)&list->first) {
        list->last = NULL;
    }
    iter->removed = 1;
}

static INLINE void
sllist_remove_head(sllist_root *list)
{
    if (!list->first) {
        return;
    }

    list->first = list->first->next;

    if (!list->first) {
        list->last = NULL;
    }
}

static INLINE void
sllist_append(sllist_root *list, sllist_node *item)
{
    if (SLLIST_IS_EMPTY(list)) {
        list->first = list->last = item;
        item->next = NULL;
    } else {
        slist_sanity_insert(list, item);
        list->last->next = item;
        list->last = item;
    }
    item->next = NULL;
}

static INLINE void
sllist_prepend(sllist_root *list, sllist_node *item)
{
    if (SLLIST_IS_EMPTY(list)) {
        list->first = list->last = item;
    } else {
        slist_sanity_insert(list, item);
        item->next = list->first;
        list->first = item;
    }
}

/**
 * Insert a sorted item into the list. This is not a very fast operation but
 * is maintained here for simplicity.
 *
 * It is assumed that the list is otherwise sorted, so that the item with
 * the lowest value begins at the beginning and the highest value is at the
 * tail.
 */
static INLINE void
sllist_insert_sorted(sllist_root *list, sllist_node *item,
                     int (*compar)(sllist_node*, sllist_node*))
{
    sllist_iterator iter;
    if (SLLIST_IS_EMPTY(list)) {
        sllist_append(list, item);
        return;
    }

    SLLIST_ITERFOR(list, &iter) {
        int rv;
        if (!iter.next) {
            /* end of list */
            sllist_append(list, item);
            break;
        }

        rv = compar(item, iter.next);
        if (rv > 0) {
            continue;
        }

        if (iter.cur == list->first) {
            sllist_prepend(list, item);
        } else {
            item->next = iter.cur->next;
            iter.cur->next = item;
        }
        return;
    }
}
