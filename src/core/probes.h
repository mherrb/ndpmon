#ifndef _PROBES_H_
#define _PROBES_H_

/** @file
 *  Managment of probes (interfaces).
 */

#include <pthread.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>

#include "../ndpmon_defs.h"
#include "../ndpmon_netheaders.h"
#include "../membounds.h"

#include "cache_types.h"
#include "extinfo.h"
#include "neighbors.h"
#include "routers.h"

/** A list of probes. The <B>entry</B> field is a nested structure only to prevent
 * publishing the <B>next</B> field to plugins or watchers.
 */
struct probe_list {
    /** Lock to control read/write access to this probe's state information. */
    pthread_mutex_t lock;
    /** The probe's state information. */
    struct probe entry;
    /** The next list entry. */
    struct probe_list* next;
};


#ifdef _COUNTERMEASURES_
/** Tells if countermeasures are enabled or not for a probe
 *  @param probe The probe to be locked.
 *  @return      1 if enabled, 0 otherwise, -1 on error (probe not found).
 */
int probe_cm_enabled(const char* probe_name);
#endif


/** Performs a deep copy of the given probe including all addresses,
 *  neighbors, routers, extinfo, etc.
 *  @param destination The destination to copy to (must be allocated).
 *  @param source      The source to copy from.
 */
void probe_copy(struct probe *destination, const struct probe *source);

/** Locks a given probe to have save read/write access and blocks
 *  if probe is already locked.
 *  @param probe The probe to be locked.
 *  @return      The locked probe or NULL on error.
 */
struct probe* probe_lock(const char* probe_name);

#ifdef _COUNTERMEASURES_
/** Adds a new probe list entry to the global list of probes.
 *  @param name      The probe identifier, must be unique.
 *  @param type      The type of this probe.
 *  @param extinfo   Extinfo on this probe.
 *  @param neighbors The neighbor cache for this probe.
 *  @param routers   The router list for this probe.
 *  @param cm_enabled Will hold the flag to tell if countermeasures are enabled on that probe
 *  @return          0 on success, -1 on error.
 */
int probe_list_add(char* const name, enum probe_type type,
        struct extinfo_list* const extinfo, neighbor_list_t* neighbors,
        router_list_t* routers, int cm_enabled);
#else
/** Adds a new probe list entry to the global list of probes.
 *  @param name      The probe identifier, must be unique.
 *  @param type      The type of this probe.
 *  @param extinfo   Extinfo on this probe.
 *  @param neighbors The neighbor cache for this probe.
 *  @param routers   The router list for this probe.
 *  @return          0 on success, -1 on error.
 */
int probe_list_add(char* const name, enum probe_type type,
        struct extinfo_list* const extinfo, neighbor_list_t* neighbors,
        router_list_t* routers);
#endif

/** Frees the global list of probes.
  */
void probe_list_free();

/** Gets the probe state of a given probe for <B>read access only</B> and is
 *  used during XML neighbor cache parsing.
 *  Should <B>not</B> be used during multithreaded operation, for example by
 *  watchers.
 *  @param name The probe's name.
 */
const struct probe* probe_list_get(char* name);

/** Loads the probe list from a XML "probes" element.
 *  @param element The element to be used.
 *  @return        0 on success, -1 otherwise.
 */
int probe_list_load_config(xmlNodePtr element);

/** Load the neighbors of all entries of the neighbor cache.
 *  @param element The root element of the neighbor cache.
 *  @return        0 on success, -1 otherwise.
 */
int probe_list_load_neighbors(xmlNodePtr element);

/** Locks the list of probes to have save read/write access.
 *  @return The locked probe list.
 */
struct probe_list** probe_list_lock();

/** Prints the list of probes to stderr.
 */
void probe_list_print();

/** Saves the probe list to a XML DOM.
 *  @param element The element to add the information to.
 */
int probe_list_save_config(xmlNodePtr element);

/** Saves the neighbor cache of each probe to a XML DOM.
 *  @param element The element to add the information to.
 */
int probe_list_save_neighbors(xmlNodePtr element);

/** Sends the EVENT_TYPE_PROBE_UPDOWN event with probe state
 *  PROBE_UPDOWN_STATE_DOWN for all probes (used on teardown).
 */
void probe_list_send_down_event();

/** Adds addressing information to all probes.
 *  @ref probe_set_addresses()
 *  @return 0 on success, -1 otherwise.
 */
int probe_list_set_addresses();

/** Unlocks the list of probes.
 */
void probe_list_unlock();

#ifdef _COUNTERMEASURES_
/** Loads configuration information for a given probe.
 *  @param element The XML element to load the information from.
 *  @param name    Will hold the probe's name (pointer to buffer).
 *  @param type    Will hold the probe type (call by reference).
 *  @param extinfo Will hold the extinfo for the probe (call by reference).
 *  @param routers Will hold the router list for the probe (call by reference).
 *  @param cm_enabled Will hold the flag to tell if countermeasures are enabled on that probe
 *  @return        0 on success, -1 otherwise.
 */
int probe_load_config(xmlNodePtr element, char* name, enum probe_type* type,
        struct extinfo_list** extinfo, router_list_t** routers,
        int load_remote_config, int *cm_enabled);
#else
/** Loads configuration information for a given probe.
 *  @param element The XML element to load the information from.
 *  @param name    Will hold the probe's name (pointer to buffer).
 *  @param type    Will hold the probe type (call by reference).
 *  @param extinfo Will hold the extinfo for the probe (call by reference).
 *  @param routers Will hold the router list for the probe (call by reference).
 *  @return        0 on success, -1 otherwise.
 */
int probe_load_config(xmlNodePtr element, char* name, enum probe_type* type,
        struct extinfo_list** extinfo, router_list_t** routers,
        int load_remote_config);

#endif

/** Loads all neighbor information for a given probe from a XML element.
 *  @param element The element to load the probe information from.
 *  @param probe   The probe to add the information to.
 *  @return        0 on success, -1 otherwise.
 */
int probe_load_neighbors(xmlNodePtr element, struct probe* probe,
        int load_remote_neighbors);

/** Saves configuration information for a given probe to a
 *  XML element.
 *  @param probe_element The element to save the configuration to.
 *  @param probe         The probe that is to be saved.
 *  @return              0 on success, -1 otherwise.
 */
int probe_save_config(xmlNodePtr element, const struct probe* probe);

/** Saves neighbor cache information for a given probe to a
 *  XML element.
 *  @param element The element to save the configuration to.
 *  @param probe   The probe that is to be saved.
 *  @return        0 on success, -1 otherwise.
 */
int probe_save_neighbors(xmlNodePtr element, const struct probe* probe);

/** Adds addressing information to a probe using getifaddrs().
 *  It sets the ethernet address of the probe and adds an address_t
 *  entry for each IPv6 address of the probe.
 *  @param probe The probe to add the information to.
 *  @return      0 on success, -1 otherwise.
 */
int probe_set_addresses(struct probe* probe);

/** Unlocks a given probe to grant other threads save read/write access.
 *  @param probe The probe to be unlocked.
 */
void probe_unlock(const char* probe_name);

/** Raises an probe_updown event and copies all probe state information
 *  to that event (for thread safety reasons).
 *  @param state If this probe has been started or stopped
 *               (PROBE_UPDOWN_STATE_UP or PROBE_UPDOWN_STATE_DOWN).
 *  @param probe The probe's state information to be copied.
 */
void probe_updown(enum probe_updown_state state, struct probe* probe);

/** Frees the data of a probe updown event (including referenced data
 *  structures).
 *  @param probe_updown The probe updown to be freed.
 */
extern void probe_updown_free(union event_data** probe_updown);

/** Saves a probe updown event to a XML element.
 *  @param element      The element to add the information to.
 *  @param probe_updown The event to be saved.
 */
int probe_updown_save(xmlNodePtr element,
        const struct probe_updown_info* probe_updown);


#endif /* _PROBES_H_ */
