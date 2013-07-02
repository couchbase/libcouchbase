/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
*     Copyright 2013 Couchbase, Inc.
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

/**
* New-Style v1 plugin for Windows, Using IOCP
* @author Mark Nunberg
*/

#include "iocp_iops.h"

static int iocp_timer_cmp_asc(lcb_list_t *a, lcb_list_t *b)
{
    iocp_timer_t *aa, *bb;

    aa = LCB_LIST_ITEM(a, iocp_timer_t, list);
    bb = LCB_LIST_ITEM(b, iocp_timer_t, list);
    if (aa->ms > bb->ms) {
        return 1;
    } else if (aa->ms < bb->ms) {
        return -1;
    } else {
        return 0;
    }
}

unsigned long iocp_tmq_next_timeout(lcb_list_t *list, lcb_uint64_t now)
{
    if (LCB_LIST_IS_EMPTY(list)) {
        return 0;
    } else {
        iocp_timer_t *tt;
        tt = LCB_LIST_ITEM(list->next, iocp_timer_t, list);
        /* is tt->ms always greater then now? */
        return (unsigned long)(tt->ms - now);
    }
}

iocp_timer_t *iocp_tmq_pop(lcb_list_t *list, lcb_uint64_t now)
{
    iocp_timer_t *tt;

    if (LCB_LIST_IS_EMPTY(list)) {
        return NULL;
    }
    tt = LCB_LIST_ITEM(list->next, iocp_timer_t, list);
    if (tt->ms > now) {
        return NULL;
    }
    lcb_list_delete(&tt->list);
    return tt;
}

void iocp_tmq_add(lcb_list_t *list, iocp_timer_t *timer)
{
    lcb_list_add_sorted(list, &timer->list, iocp_timer_cmp_asc);
}

void iocp_tmq_del(lcb_list_t *list, iocp_timer_t *timer)
{
    lcb_list_delete(&timer->list);
    (void)list;
}
