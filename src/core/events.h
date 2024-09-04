#ifndef _EVENTS_H_
#define _EVENTS_H_

#include <pthread.h>
#include <sched.h>
#include <libxml/tree.h>

#include "../ndpmon_netheaders.h"
#include "cache_types.h"


/** @file
 *  This module serializes the events being raised in the parallel threads
 *  of NDPMon.
 */

/** Maximum size for the <I>reason</I> field of an @ref alert_info. */
#define ALERT_REASON_SIZE   100
/** Maximum size for the <I>message</I> field of an @ref alert_info. */
#define ALERT_MESSAGE_SIZE  256
/** Maximum size for the <I>name</I> field of an @ref event_handler_list. */
#define EVENT_HANDLER_NAME_SIZE 100

struct event_info; /*forward declaration*/

/** A type definition for functions that react to an event. */
typedef void (*event_handler_t) (const struct event_info* event);

/** Holds information about alerts raised for a single packet captured.*/
struct alert_info {
    /** Priority of this alert.*/
    int priority;
    /** The time of this alert. */
    time_t time;
    /** The name of the probe that raised this alert. */
    char probe_name[PROBE_NAME_SIZE];
    /** The short reason for this alert.*/
    char reason[ALERT_REASON_SIZE];
    /** A brief description of what happened.*/
    char message[ALERT_MESSAGE_SIZE];
    /** The affected mac address.*/
    struct ether_addr ethernet_address1;
    /** Another mac address, if one involved.*/
    struct ether_addr ethernet_address2;
    /** A IPv6 address, if one involved.*/
    struct in6_addr ipv6_address;
    /** Further information. */
    struct extinfo_list* extinfo;
};

/** Information from a neighbor update. */
struct neighbor_update_info {
    /** Name of the probe this neighbor belongs to. */
    char probe_name[PROBE_NAME_SIZE];
    /** Which address may be used as a key for update actions. */
    enum neighbor_update_key_type {
        /** MAC address constant */
        NEIGHBOR_UPDATE_KEY_TYPE_ETHERNET,
        /** LLA constant */
        NEIGHBOR_UPDATE_KEY_TYPE_LLA,
        /** New station: */
        NEIGHBOR_UPDATE_KEY_TYPE_NONE
    } key_type;
    /** The new data of the neighbor. */
    neighbor_list_t neighbor;
};

/** Information from a probe updown. */
struct probe_updown_info {
    /** Is the probe started or stopped? */
    enum probe_updown_state {
        /** Probe was started. */
        PROBE_UPDOWN_STATE_UP,
        /** Probe was stopped. */
        PROBE_UPDOWN_STATE_DOWN
    } state;
    /** The configuration and state information of the probe. */
    struct probe probe;
};

/** Possible event types. */
enum event_type {
    /** An alert has been raised. */
    EVENT_TYPE_ALERT,
    /** Neighbor data has changed. */
    EVENT_TYPE_NEIGHBOR_UPDATE,
    /** Listening on an interface has been started or stopped.*/
    EVENT_TYPE_PROBE_UPDOWN,
    /** Stop the event queue. */
    EVENT_TYPE_EXIT
};


/** Holds a list of functions that react if an event is raised. */
struct event_handler_list {
    /** The name of this handler. */
    char name[EVENT_HANDLER_NAME_SIZE];
    /** The function to be called. */
    event_handler_t handler;
    /** The next handler. */
    struct event_handler_list* next;
};

/** The different concrete types that an event may actually have. */
union event_data {
    struct alert_info alert;
    struct neighbor_update_info neighbor_update;
    struct probe_updown_info probe_updown;
};

struct event_info {
    /** The event type. */
    enum event_type type;
    /** The event raised.*/
    union event_data* data;
};

/** Holds a list of events raised. */
struct event_list {
    /** The event raised. */
    struct event_info entry;
    /** The next list entry.*/
    struct event_list* next;
};

/** Frees the data of an alert event.
 *  @param alert The alert to be freed.
 */
extern void alert_free(union event_data** alert);

/** Frees the data of an neighbor update event
 *  (including referenced data structures).
 *  @param neighbor_update The neighbor update to be freed.
 */
extern void neighbor_update_free(union event_data** neighbor_update);

/** Frees the data of a probe updown event (including referenced data
 *  structures).
 *  @param probe_updown The probe updown to be freed.
 */
extern void probe_updown_free(union event_data** probe_updown);

/** Allocates buffer for an event_data union and sets all content to zero.
 *  @return Pointer to the allocated buffer.
 */
union event_data* event_data_create();

/** Frees the data associated to an event.
 *  @param type  Event type.
 *  @param event The data to be released.
 */
void event_data_free(enum event_type type, union event_data** event);

/** Adds a handler that reacts if an event is raised.
 *  @param name    The descriptive name of this handler.
 *  @param handler The handler to be added.
 *  @return        0 on success, -1 otherwise.
 */
int event_handler_add(char* name, event_handler_t handler);

/* Frees all handler list entries.
 */
void event_handler_list_free();

/** Adds a given list to the event queue.
 *  @param type The event type (@ref event_type).
 *  @param data The event data (which is copied).
 */
void event_queue(enum event_type type, union event_data* const data);

/** Frees the queue of events (should be empty on teardown). */
void event_queue_free();

/** This thread consumes everything that is added to the queue.
 *  @param unused The thread parameter is not used.
 *  @return       Always NULL.
 * */
void* event_queue_run(void* unused);

/** Saves an event to the given XML element.
 *  @param element The element to add the information to.
 *  @param event   The event information.
 *  @return        0 on success, -1 otherwise.
 */
int event_save(xmlNodePtr element, struct event_info* event);

#endif
