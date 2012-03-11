/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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

#include <stdlib.h>

struct hashset_st {
    size_t nbits;
    size_t mask;

    size_t capacity;
    size_t *items;
    size_t nitems;
};

typedef struct hashset_st *hashset_t;

/* create hashset instance */
hashset_t hashset_create(void);

/* destroy hashset instance */
void hashset_destroy(hashset_t set);

size_t hashset_num_items(hashset_t set);

/* add item into the hashset
 *
 * returns zero if the item already in the set and non-zero otherwise
 */
int hashset_add(hashset_t set, void *item);

/* remove item from the hashset
 *
 * returns non-zero if the item was removed and zero if the item wasn't
 * exist
 */
int hashset_remove(hashset_t set, void *item);

/* check if existence of the item
 *
 * returns non-zero if the item exists and zero otherwise
 */
int hashset_is_member(hashset_t set, void *item);
