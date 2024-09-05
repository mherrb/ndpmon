#ifndef _NEIGHBOR_LIST_H_
#define _NEIGHBOR_LIST_H_

/** @file
    Neighbor cache management.
*/

#include "../membounds.h"
#include "ndpmon_defs.h"

#include "alerts.h"
#include "cache_types.h"
#include "extinfo.h"
#include "probes.h"


#ifdef _MACRESOLUTION_
#include "../plugins/mac_resolv/mac_resolv.h"
#endif

#ifdef _COUNTERMEASURES_
#include "../plugins/countermeasures/countermeasures.h"
#endif



/** Adds a neighbor to the given neighbor list.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the new neighbor.
 */
int add_neighbor(neighbor_list_t **list, const struct ether_addr* eth);

/** Adds an address to a list of addresses.
 *  @param addresses     The list to be used (call by reference).
 *  @param inet6_address The address to be added.
 *  @param firstseen     Time when this address was first seen.
 *  @param lastseen      Time when this address was last seen.
 *  @return              0 on success, -1 otherwise.
 */
int addresses_add(address_t** addresses,
        const struct in6_addr* const inet6_address, time_t firstseen,
        time_t lastseen);

/** Frees a list of addresses.
 *  @param addresses The list to be released.
 */
void addresses_free(address_t** addresses);

/** Removes an IPv6 address from a list of IPv6 addresses.
 *  @param addresses The list to be used (call by reference).
 *  @param addr      The IPv6 address to be removed.
 *  @return          1 if an IPv6 address was removed,
 *                   0 if it was not found.
 */
int addresses_remove(address_t **addresses, const struct in6_addr* const addr);

/** Adds an ethernet address to a list of ethernet addresses.
 *  @param ethernets The list to be used (call by reference).
 *  @param address   The ethernet address to be added.
 *  @return          0 on success, -1 otherwise.
int ethernets_add(ethernet_t** ethernets, const struct ether_addr* const address);
 */
int ethernets_add(ethernet_t** ethernets, const struct ether_addr* address);

/** Frees a list of ethernet addresses.
 *  @param ethernets The list to be released (call by reference).
 */
void ethernets_free(ethernet_t** ethernets);

/** Removes an ethernet address from a list of ethernet addresses.
 *  @param ethernets The list to be used (call by reference).
 *  @param eth       The ethernet address to be removed.
 *  @return          1 if an ethernet address was removed,
 *                   0 if it was not found.
 */
int ethernets_remove(ethernet_t **ethernets, const struct ether_addr* eth);

/** Removes a neighbor from the given neighbor list.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor to be removed.
 *  @return     1 if a neighbor was deleted, 0 if an error occured.
 */
int del_neighbor(neighbor_list_t **list, const struct ether_addr* eth);

/** Updates the ethernet address of a neighbor.
 *  @param list    The neighbor list to be used.
 *  @param lla     The link local address of the neighbor.
 *  @param new_mac The new ethernet address.
 *  @return        1 if a neighbor was updated, 0 if an error occured (or the
 *                 neighbor was not found).
 */
int neighbor_update_mac(neighbor_list_t *list, const struct in6_addr* lla,
        const struct ether_addr* new_mac);
int neighbor_has_old_mac(const neighbor_list_t *list, const struct in6_addr* lla,
        const struct ether_addr* old_mac);


/** Sets the MAC vendor for a given neighbor.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param vendor The MAC vendor to set
 *  @return     1 if a MAC vendor was set, 0 if no such neighbor was found.
 */
#ifdef _MACRESOLUTION_
int set_neighbor_vendor(neighbor_list_t *list, const struct ether_addr* eth,
        const char * vendor);
#endif

/** Sets the link local address for a given neighbor.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param addr The link local address to be set.
 *  @return     1 if a LLA was set, 0 if no such neighbor was found.
 */
int set_neighbor_lla(neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* lla);

/** Checks if a given neighbor has the specified LLA.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param lla  The link local address.
 *  @return     0 if no such neighbor is found or if the given LLA does not
 *              match that of the neighbor; 1 otherwise.
 */
int neighbor_has_lla(const neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* lla);

int del_neighbor_old_mac(neighbor_list_t *list, const struct in6_addr* lla,
        const struct ether_addr* eth);
struct ether_addr neighbor_get_last_mac(neighbor_list_t *list,
        struct in6_addr lla);
int neighbor_set_last_mac(neighbor_list_t *list, const struct in6_addr* const lla,
        const struct ether_addr* const eth);

int neighbor_has_ip(const neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* addr);
/** Adds the given IPv6 global address to this neighbors address list.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param addr The IPv6 global address to be added.
 *  @return     1 if the address was added; 0 if the neighbor was not found,
 *              the address is multicast or another error occurred.
 */
int neighbor_ip_add(neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* addr);

/** Removes the given IPv6 global address to this neighbors address list.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param addr The IPv6 global address to be added.
 *  @return     1 if the address was added; 0 if the neighbor was not found,
 *              the address is multicast or another error occurred.
 */
int neighbor_ip_remove(neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* addr);



/** Checks if a neighbor with the given ethernet address exists.
 *  @param eth The ethernet address.
 *  @return    0 if the ethernet address was not found, 1 otherwise.
 */
int is_neighbor_by_mac(const neighbor_list_t *list,
        const struct ether_addr* eth);

/** Checks if a neighbor with the given link local address exists.
 *  @param lla The link local address.
 *  @return    0 if the link local address was not found, 1 otherwise.
 */
int is_neighbor_by_lla(const neighbor_list_t *list, const struct in6_addr* lla);

/** Checks if a neighbor with the given IPv6 global address exists.
 *  @param addr The IPv6 address.
 *  @return     0 if the IPv6 was not found, 1 otherwise.
 */
int is_neighbor_by_ip(const neighbor_list_t *list, const struct in6_addr* addr);

/** Retrieves a neighbor by its ethernet address.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address.
 *  @return     The neighbor list entry or NULL if the ethernet address was not
 *              found.
 */
const neighbor_list_t * get_neighbor_by_mac(const neighbor_list_t *list,
        const struct ether_addr* eth);

/** Retrieves a neighbor by its link local address.
 *  @param list The neighbor list to be used.
 *  @param lla  The link local address.
 *  @return     The neighbor list entry or NULL if the lla was not found.
 */
const neighbor_list_t * get_neighbor_by_lla(const neighbor_list_t *list,
        const struct in6_addr* lla);

/** Retrieves a neighbor by one of its IPv6 global addresses.
 *  @param list The neighbor list to be used.
 *  @param addr The IPv6 address.
 *  @return     The neighbor list entry or NULL if the ethernet address was not
 *              found.
 */
const neighbor_list_t * get_neighbor_by_ip(const neighbor_list_t *list,
        const struct in6_addr* addr);

/** Sets the lastseen timer for a given neighbor to the current time.
 *  Raises an alert if the neighbor has been inactive for more than six month.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @return     1 if a timer was set, 0 if no such neighbor was found.
 */
int reset_neighbor_timer(neighbor_list_t *list, const struct ether_addr* eth, const struct probe* probe);

/** Sets the lastseen timer for a given neighbor.
 *  @param list  The neighbor list to be used.
 *  @param eth   The ethernet address of the neighbor.
 *  @param value The new value of the timer.
 *  @return      1 if a timer was set, 0 if no such neighbor was found.
 */
int set_neighbor_timer(neighbor_list_t *list, const struct ether_addr* eth,
        time_t value);

/** Resets the lastseen timer for a global IPv6 address of a neighbor.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param addr The global IPv6 address to set the timer for.
 *  @return     1 of a timer was set, 0 if no such neighbor or address was
 *              found.
 */
int reset_neighbor_address_timer(neighbor_list_t *list,
        const struct ether_addr* eth, const struct in6_addr* addr);

/** Sets the lastseen timer for a global IPv6 address of a neighbor to a
 *  specific value.
 *  @param list  The neighbor list to be used.
 *  @param eth   The ethernet address of the neighbor.
 *  @param addr  The global IPv6 address to set the timer for.
 *  @param value The new value of the timer.
 *  @return     1 of a timer was set, 0 if no such neighbor or address was
 *              found.
 */
int
        set_neighbor_address_timer(neighbor_list_t *list,
                const struct ether_addr* eth, const struct in6_addr* addr,
                time_t value);

/** Sets the firstseen timer for a global IPv6 address of a neighbor to a
 *  specific value.
 *  @param list The neighbor list to be used.
 *  @param eth  The ethernet address of the neighbor.
 *  @param addr The global IPv6 address to set the timer for.
 *  @return     1 of a timer was set, 0 if no such neighbor or address was
 *              found.
 */
int
        set_neighbor_first_address_timer(neighbor_list_t *list,
                const struct ether_addr* eth, const struct in6_addr* addr,
                time_t value);

int nb_neighbor(neighbor_list_t *neighbors);
void print_neighbors(neighbor_list_t *list);

/** Free a given neighbor list.
 *  @param list The list to be released (call by reference).
 */
int neighbors_free(neighbor_list_t **list);

/** Loads a neighbor list from a XML DOM.
 *  @param element The XML element containing the "neighbor" nodes as children.
 *  @param list    Pointer to the list to be used (call by reference).
 *  @return 0 on success, -1 otherwise.
 */
int neighbor_list_load(xmlNodePtr element, neighbor_list_t **list);

/** Saves the given neighbor list to a XML DOM element.
 *  @param element The element to add the information to.
 *  @param list    The list to be saved.
 *  @return 0 on success, -1 otherwise.
 */
int neighbor_list_save(xmlNodePtr element, const neighbor_list_t *list);

/** Loads neighbor information from a given XML element to a
 *  neighbor data structure.
 *  @param element      XML DOM element to load the information from.
 *  @param new_neighbor Neighbor structure to save the information to.
 */
int neighbor_load(xmlNodePtr element, neighbor_list_t* new_neighbor);

/** Queues an event that contains the new neighbor data after a neighbor has been changed.
 *  @param key_mac If this is not NULL, the given ethernet address
 *                 may be used as a key to cache update actions (MAC constant).
 *  @param key_lla If this is not NULL, the given link local address may be
 *                 used as a key to cache update actions (LLA constant).
 *  @param new_neighbor_data The updated neighbor data.
 */
void neighbor_update(char* probe_name,
        const struct ether_addr* const key_mac,
        const struct in6_addr* const key_lla,
        const neighbor_list_t* new_neighbor_data);

/** Frees the data of an neighbor update event.
 *  @param neighbor_update The neighbor update to be freed.
 */
void neighbor_update_free(union event_data** neighbor_update);

int neighbor_update_save(xmlNodePtr element,
        const struct neighbor_update_info* neighbor_update);

int neighbor_save(xmlNodePtr neighbor_element, const neighbor_list_t* list);

/** Performs a deep copy of a given neighbor.
 *  @param destination Buffer to copy the neighbor to (must be allocated).
 *  @param source      Neighbor to copy.
 */
void neighbor_copy(neighbor_list_t* destination, const neighbor_list_t* source);

#endif
