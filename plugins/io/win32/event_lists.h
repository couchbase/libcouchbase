#ifndef EVENT_LISTS_H
#define EVENT_LISTS_H

#ifdef EVENT_LISTS_UNIT_TESTS
struct winsock_event {
winsock_event() : next(NULL) {};
    struct winsock_event *next;
};

struct winsock_timer {
winsock_timer() : next(NULL) {};
    struct winsock_timer *next;
};

struct winsock_io_cookie {
winsock_io_cookie() : events(NULL), timers(NULL) {};
    struct winsock_event *events;
    struct winsock_timer *timers;
};

static int event_contains(struct winsock_io_cookie *instance,
                          struct winsock_event *event)
{
    struct winsock_event *ptr = instance->events;
    while (ptr != NULL && ptr != event) {
        ptr = ptr->next;
    }

    return (ptr == event) ? 1 : 0;
}

static int timer_contains(struct winsock_io_cookie *instance,
                          struct winsock_timer *timer)
{
    struct winsock_timer *ptr = instance->timers;
    while (ptr != NULL && ptr != timer) {
        ptr = ptr->next;
    }

    return (ptr == timer) ? 1 : 0;
}

#endif

static void link_event(struct winsock_io_cookie *instance,
                       struct winsock_event *event)
{
    event->next = instance->events;
    instance->events = event;
}

static void unlink_event(struct winsock_io_cookie *instance,
                         struct winsock_event *event)
{
    if (instance->events == event) {
        instance->events = event->next;
    } else {
        struct winsock_event *prev = instance->events;
        struct winsock_event *next;
        for (next = prev->next; next != NULL; prev=next, next = next->next) {
            if (event == next) {
                prev->next = next->next;
                return;
            }
        }
    }
}

static void link_timer(struct winsock_io_cookie *instance,
                       struct winsock_timer *timer)
{
    timer->next = instance->timers;
    instance->timers = timer;
}

static void unlink_timer(struct winsock_io_cookie *instance,
                         struct winsock_timer *timer)
{
    if (instance->timers == timer) {
        instance->timers = timer->next;
    } else {
        struct winsock_timer *prev = instance->timers;
        struct winsock_timer *next;
        for (next = prev->next; next != NULL; prev = next, next = next->next) {
            if (timer == next) {
                prev->next = next->next;
                return;
            }
        }
    }
}
#endif
