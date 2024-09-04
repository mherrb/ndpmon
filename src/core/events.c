
#include "events.h"

static struct event_list* events=NULL;

static struct event_handler_list* event_handlers;

extern int DEBUG;

pthread_mutex_t events_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  events_cond = PTHREAD_COND_INITIALIZER;

union event_data* event_data_create() {
    union event_data* new;

    if ((new=malloc(sizeof(union event_data)))==NULL) {
        perror("[events] malloc failed");
        exit(1);
    }
    memset(new, 0, sizeof(union event_data));
    return new;
}

int event_handler_add(char* name, event_handler_t handler) {
    struct event_handler_list* new;
    struct event_handler_list* tmp_handlers = event_handlers;

    if ((new=malloc(sizeof(struct event_handler_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    strncpy(new->name, name, EVENT_HANDLER_NAME_SIZE);
    new->handler = handler;
    new->next = NULL;
    if (event_handlers==NULL) {
        /* if list is empty this will be the new list: */
        event_handlers = new;
    } else {
        /* to keep ordering we have to walk to the list's end: */
        while (tmp_handlers->next != NULL) {
            tmp_handlers = tmp_handlers->next;
        }
        tmp_handlers->next = new;
    }
    return 0;
}

void event_handler_list_free() {
    while (event_handlers!=NULL) {
        struct event_handler_list* current = event_handlers;
        event_handlers = event_handlers->next;
        free(current);
    }
}

void event_data_free(enum event_type type, union event_data** event) {
    switch (type) {
        case EVENT_TYPE_ALERT:
            alert_free(event);
            break;
        case EVENT_TYPE_PROBE_UPDOWN:
            probe_updown_free(event);
            break;
        case EVENT_TYPE_NEIGHBOR_UPDATE:
            neighbor_update_free(event);
        default:
            break;
    }
}

void event_queue(enum event_type type, union event_data* const data) {
    struct event_list* new;
    struct event_list* tmp_events;

    if ((new=malloc(sizeof(struct event_list)))==NULL) {
         perror("[events] malloc failed");
         exit(1);
     }
     memset(new, 0, sizeof(struct event_list));
     new->entry.type = type;
     new->entry.data = data;
     new->next = NULL;

     pthread_mutex_lock(&events_lock);
     if (events==NULL) {
         /* if the queue is empty, this will be the new queue: */
         events = new;
     } else {
         /* else add at queue end (FIFO): */
         tmp_events = events;
         while (tmp_events->next != NULL) {
             tmp_events = tmp_events->next;
         }
         tmp_events->next = new;
     }
     pthread_mutex_unlock(&events_lock);
     pthread_cond_signal(&events_cond);
     sched_yield();
}

void event_queue_cleanup() {
    while (events!=NULL) {
        struct event_list* current = events;
        events = events->next;
        event_data_free(current->entry.type, &current->entry.data);
        free(current);
    }
    pthread_mutex_unlock(&events_lock);
    pthread_mutex_destroy(&events_lock);
    pthread_cond_destroy(&events_cond);
}

struct event_info* event_queue_pop() {
    struct event_info* next_event;
    struct event_list* tmp_event_list;

    pthread_mutex_lock(&events_lock);
    while (events==NULL) {
        /* wait until there is an event: */
        if (DEBUG) {
                    fprintf(stderr, "[events] waiting for events...\n");
        }
        pthread_cond_wait(&events_cond, &events_lock);
    }
    /* There is an event: */
    if (DEBUG) {
                fprintf(stderr, "[events] woke up, serving queue...\n");
    }
    /* copy the event_info structure: */
    if ((next_event=malloc(sizeof(struct event_info)))==NULL) {
        perror("[events] malloc failed");
        exit(1);
    }
    memcpy(next_event, &events->entry, sizeof(struct event_info));
    /* release the current event_list entry: */
    tmp_event_list = events;
    events = events->next;
    free(tmp_event_list);
    pthread_mutex_unlock(&events_lock);
    return next_event;
}

void* event_queue_run(void *unused) {
    int running = 1;

    pthread_cleanup_push(event_queue_cleanup, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    while (running == 1) {
        /* The thread was awakened and there are events: */
        struct event_handler_list* tmp_event_handlers = event_handlers;
        /* blocks until there is an event: */
        struct event_info* next_event = event_queue_pop();

        /* catch the EVENT_TYPE_EXIT event: */
        if (next_event->type==EVENT_TYPE_EXIT) {
            pthread_exit(NULL);
        }
        /* call all handlers for this event: */
        while (tmp_event_handlers != NULL) {
            if (DEBUG) {
                fprintf(stderr,
                        "[events] calling handlers %s\n",
                        tmp_event_handlers->name);
                }
            (tmp_event_handlers->handler)(next_event);
            tmp_event_handlers = tmp_event_handlers->next;
            sched_yield();
        }
        event_data_free(next_event->type, &next_event->data);
        free(next_event);
    }
    /* cleanup */
    pthread_cleanup_pop(1);
    return NULL;
}
