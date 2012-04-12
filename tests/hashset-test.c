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

#include <stdio.h>
#include <assert.h>
#include "hashset.h"
#include "test.h"

static void trivial(void)
{
    char *missing = "missing";
    char *items[] = {"zero", "one", "two", "three", NULL};
    char *foo = "foo";
    size_t ii, nitems = 4;
    hashset_t set = hashset_create();

    if (set == NULL) {
        fprintf(stderr, "failed to create hashset instance\n");
        abort();
    }

    for (ii = 0; ii < nitems; ++ii) {
        hashset_add(set, items[ii]);
    }

    for (ii = 0; ii < nitems; ++ii) {
        assert(hashset_is_member(set, items[ii]));
    }
    assert(hashset_is_member(set, missing) == 0);

    assert(hashset_remove(set, items[1]) == 1);
    assert(hashset_num_items(set) == 3);
    assert(hashset_remove(set, items[1]) == 0);

    assert(hashset_add(set, foo) == 1);
    assert(hashset_add(set, foo) == 0);

    hashset_destroy(set);
}

static void test_gaps(void)
{
    hashset_t set = hashset_create();

    /* fill the hashset */
    hashset_add(set, (void *)0xbabe);
    hashset_add(set, (void *)0xbeef);
    hashset_add(set, (void *)0xbad);
    hashset_add(set, (void *)0xf00d);
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0xbeef */

    /* make a gap */
    hashset_remove(set, (void *)0xbeef);
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0x1 */

    /* check that 0xf00d is still reachable */
    assert(hashset_is_member(set, (void *)0xf00d));

    /* add 0xbeef back */
    hashset_add(set, (void *)0xbeef);
    /* 0xf00d (nil) (nil) (nil) (nil) 0xbad 0xbabe 0xbeef */

    /* verify */
    assert(hashset_is_member(set, (void *)0xbeef));
    assert(hashset_is_member(set, (void *)0xf00d));
}

static void test_exceptions(void)
{
    hashset_t set = hashset_create();

    assert(hashset_add(set, (void *)0) == -1);
    assert(hashset_add(set, (void *)1) == -1);
}

int main(int argc, char *argv[])
{
    trivial();
    test_gaps();
    test_exceptions();

    (void)argc;
    (void)argv;
    return 0;
}
