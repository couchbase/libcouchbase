#include <gtest/gtest.h>
#include "sllist.h"
#include "sllist-inl.h"

#ifndef ASSERT_NZ
#define ASSERT_NZ(e) ASSERT_NE(0, e)
#endif

#ifndef ASSERT_Z
#define ASSERT_Z(e) ASSERT_EQ(0, e)
#endif

class SListTests : public ::testing::Test
{
};

struct my_elem {
    int value;
    sllist_node slnode;
};

TEST_F(SListTests, testBasic)
{
    sllist_root sl;
    memset(&sl, 0, sizeof(sl));

    ASSERT_NZ(SLLIST_IS_EMPTY(&sl));
    my_elem elem1, elem2, elem3;

    sllist_append(&sl, &elem1.slnode);
    ASSERT_NZ(sllist_contains(&sl, &elem1.slnode));
    ASSERT_Z(SLLIST_IS_EMPTY(&sl));

    sllist_node *tmpnode = sl.first;
    sllist_remove_head(&sl);
    ASSERT_NE(tmpnode, sl.first);
    ASSERT_EQ(tmpnode, &elem1.slnode);
    ASSERT_EQ(&elem1, SLLIST_ITEM(tmpnode, struct my_elem, slnode));
    ASSERT_NZ(SLLIST_IS_EMPTY(&sl));

    sllist_append(&sl, &elem1.slnode);
    sllist_append(&sl, &elem2.slnode);
    sllist_append(&sl, &elem3.slnode);
    ASSERT_EQ(sl.last, &elem3.slnode);
    ASSERT_EQ(sl.first, &elem1.slnode);

    // Test prepend
    my_elem elem4;
    sllist_prepend(&sl, &elem4.slnode);
    tmpnode = sl.first;
    ASSERT_EQ(tmpnode, &elem4.slnode);
    sllist_node *cur;
    int itercount = 0;
    SLLIST_ITERBASIC(&sl, cur) {
        itercount++;
    }
    ASSERT_EQ(4, itercount);
}

#define BASIC_NELEM 3
TEST_F(SListTests, testBasicIter)
{
    sllist_root sl;
    my_elem elems[BASIC_NELEM];

    memset(&sl, 0, sizeof(sl));
    memset(elems, 0, sizeof(elems));

    for (int ii = 0; ii < BASIC_NELEM; ii++) {
        sllist_append(&sl, &elems[ii].slnode);
    }

    sllist_node *cur;
    int itercount = 0;
    SLLIST_ITERBASIC(&sl, cur) {
        my_elem *elem = SLLIST_ITEM(cur, struct my_elem, slnode);
        itercount++;
        elem->value++;
    }

    ASSERT_EQ(BASIC_NELEM, itercount);
    for (int ii = 0; ii < BASIC_NELEM; ii++) {
        ASSERT_EQ(1, elems[ii].value);
    }
}


static void fillDynamicSlist(sllist_root *root, my_elem **ptrs, int nptrs)
{
    sllist_iterator iter;
    SLLIST_ITERFOR(root, &iter) {
        sllist_iter_remove(root, &iter);
    }

    for (int ii = 0; ii < nptrs; ii++) {
        free(ptrs[ii]);
        ptrs[ii] = (my_elem *)calloc(1, sizeof(*ptrs[ii]));
        sllist_append(root, &ptrs[ii]->slnode);
    }
}

TEST_F(SListTests, testExtendedIter)
{
    sllist_root sl;
    my_elem *elemp[BASIC_NELEM] = { NULL };
    memset(&sl, 0, sizeof(sl));

    fillDynamicSlist(&sl, elemp, BASIC_NELEM);

    // Delete all elements from the list
    sllist_iterator iter;
    SLLIST_ITERFOR(&sl, &iter) {
        my_elem *elem = SLLIST_ITEM(iter.cur, struct my_elem, slnode);
        sllist_iter_remove(&sl, &iter);
        memset(elem, 0xff, sizeof(*elem));
        free(elem);
    }

    ASSERT_NZ(SLLIST_IS_EMPTY(&sl));
    memset(elemp, 0, sizeof(*elemp) * BASIC_NELEM);

    // Delete only the first element of the list. Repopulate
    fillDynamicSlist(&sl, elemp, BASIC_NELEM);
    SLLIST_ITERFOR(&sl, &iter) {
        my_elem *elem = SLLIST_ITEM(iter.cur, struct my_elem, slnode);
        if (elem == elemp[0]) {
            sllist_iter_remove(&sl, &iter);
            memset(elem, 0xff, sizeof(*elem));
            free(elem);
            elemp[0] = NULL;
        }
    }

    int itercount = 0;
    SLLIST_ITERFOR(&sl, &iter) {
        sllist_iter_remove(&sl, &iter);
        itercount++;
    }
    ASSERT_EQ(BASIC_NELEM-1, itercount);
    ASSERT_NZ(SLLIST_IS_EMPTY(&sl));

    // Delete only the middle element
    fillDynamicSlist(&sl, elemp, BASIC_NELEM);
    SLLIST_ITERFOR(&sl, &iter) {
        my_elem *elem = SLLIST_ITEM(iter.cur, struct my_elem, slnode);
        if (elem == elemp[1]) {
            sllist_iter_remove(&sl, &iter);
            memset(elem, 0xff, sizeof(*elem));
            free(elem);
            elemp[1] = NULL;
        }
    }
    ASSERT_Z(SLLIST_IS_EMPTY(&sl));

    // Delete only the last element
    fillDynamicSlist(&sl, elemp, BASIC_NELEM);
    SLLIST_ITERFOR(&sl, &iter) {
        my_elem *elem = SLLIST_ITEM(iter.cur, struct my_elem, slnode);
        if (elem == elemp[BASIC_NELEM-1]) {
            sllist_iter_remove(&sl, &iter);
            memset(elem, 0xff, sizeof(*elem));
            free(elem);
            elemp[BASIC_NELEM-1] = NULL;
        }
    }
    ASSERT_Z(SLLIST_IS_EMPTY(&sl));
    SLLIST_ITERFOR(&sl, &iter) {
        my_elem *elem = SLLIST_ITEM(iter.cur, struct my_elem, slnode);
        sllist_iter_remove(&sl, &iter);
        free(elem);
    }
}

struct NumberedItem {
    sllist_node slnode;
    int value;
};
static int
ni_compare(sllist_node *a, sllist_node *b)
{
    NumberedItem *na = SLLIST_ITEM(a, NumberedItem, slnode);
    NumberedItem *nb = SLLIST_ITEM(b, NumberedItem, slnode);
    return na->value - nb->value;
}
TEST_F(SListTests, testSort)
{
    sllist_root l;
    memset(&l, 0, sizeof(l));
    NumberedItem items[10];
    for (unsigned ii = 0; ii < 10; ii++) {
        items[ii].value = ii;
        sllist_insert_sorted(&l, &items[ii].slnode, ni_compare);
    }

    int last = -1;
    sllist_node *cur;
    SLLIST_FOREACH(&l, cur) {
        NumberedItem *ni = SLLIST_ITEM(cur, NumberedItem, slnode);
        ASSERT_EQ(last, ni->value-1);
        last = ni->value;
    }

    /** Insert another item */
    NumberedItem big1;
    big1.value = 100;
    sllist_insert_sorted(&l, &big1.slnode, ni_compare);
    ASSERT_EQ(l.last, &big1.slnode);

    NumberedItem small1;
    small1.value = -100;
    sllist_insert_sorted(&l, &small1.slnode, ni_compare);
    ASSERT_EQ(l.first, &small1.slnode);

    NumberedItem middle1;
    middle1.value = 5;
    sllist_insert_sorted(&l, &middle1.slnode, ni_compare);
    NumberedItem *ni_next = SLLIST_ITEM(middle1.slnode.next, NumberedItem, slnode);
    ASSERT_EQ(5, ni_next->value);

    ni_next = SLLIST_ITEM(items[3].slnode.next, NumberedItem, slnode);
    ASSERT_EQ(&middle1.slnode, ni_next->slnode.next);
}
