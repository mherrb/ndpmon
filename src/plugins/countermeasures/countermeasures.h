#ifndef _COUNTERMEASURES_H_
#define _COUNTERMEASURES_H_

#include <stdio.h>
#include <stdint.h>
#include <libxml/tree.h>
#include "openssl/sha.h"
#include "../../core/routers.h"
#include "../../core/neighbors.h"
#include "icmp_lib.h"
#include "countermeasures_on_link.h"
#include "countermeasures_guard.h"

/** @file
    Interface to the countermeasures plugin.
*/

/** This initializes the countermeasures plugin.
    As the watch function are not aware of the interface
    they use, the interface must be set once during startup.
    @param p_interface The interface to be used for sending counter measures.

    To be changed if multiple interfaces shall be used.
*/
void cm_init();

/** Parses the countermeasures configuration from the XML configuration.
    @param element The XML element to load the configuration from.
    @param args    Optional arguments (not used).
*/
void cm_config_parse(xmlNodePtr element);

/** Stores the countermeasures configuration to a XML configuration DOM.
    @param element  The root element of the configuration DOM.
*/
int cm_config_store(xmlNodePtr countermeasures_element);

/** Called each time the ICMP packet level library sends a packet.
    @param packet Pointer to a pointer to the packet, including ETHERNET and IP header.
    @param packet_length Length of the packet.
*/
void cm_on_sending_hook(uint8_t** packet, int* packet_length);

/** If NDPMon detected a illegitimate router advertisment,
    we may send a zero lifetime RA for this router.
    This router advertisement does not need any ND options.
    @param router_mac Pointer to the ETHERNET address of the router.
    @param router_ip Pointer to the IP address of the router.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_illegitimate_router(const struct ether_addr *router_mac, const struct in6_addr *router_ip, const char* p_interface);

/** Sends a router advertisement for the given router and the given prefix,
    but sets the prefix valid and preferred lifetime to zero.
    Since we don't want to give false parameters for the legitimate router but just kill
    the wrong prefix, we must propagate the last known well-formed parameters for this router.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param wrong_prefix Pointer to the bogus prefix advertised.
    @param wrong_prefix_length Length of the bogus prefix.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_wrong_prefix(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_prefix, const int wrong_prefix_length, const char* p_interface);

/** Sends a router advertisement for the given router containing the params
    as they are currently stored in the router list.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_router_params(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface);


/** Sends a router advertisement for the given router containing the RFC6106 DNS option
    as they are currently stored in the router list.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_router_dns(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface);


/** Sends a router advertisement for the given router containing the RFC6106 RDNSS option to deprecate
    the wrong nameserver
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param wrong_nameserver Pointer to the IP address of the wrong nameserver
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_wrong_nameserver(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_nameserver, const char* p_interface); 


/** Sends a router advertisement for the given router containing the RFC6106 DNSSL option to deprecate
    the wrong domain
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param wrong_domain The wrong domain to deprecate
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_wrong_domain(router_list_t *router, const struct in6_addr *router_ip, const char *wrong_domain, const char* p_interface) ;


/** Sends an IMCP message to all-nodes multicast which indicates NDPMons presence on this link.
    @param p_interface The interface to be used for sending the counter measures.
*/
int cm_indicate_ndpmon_presence(const char* p_interface);

/** If a NDPMon presence indication is recieved, this watch function is called by the core's capture loopback.
    It prints out the contained information about the indicated NDPMon instance.
*/
int watch_ndpmon_present(
    char* buffer,
    const struct ether_header* ethernet_header,
    const struct ip6_hdr* ip6_header,
    const struct icmp6_hdr* icmp6_header,
    const uint8_t* packet,
    const int packet_length,
    uint16_t *watch_flags 
);

/** Sends a neighbor advertisement for the given neighbor with a target link layer address option
    indicating @c previous_mac from the given neighbor cache entry.
    @param neighbor Pointer to the neighbor cache entry.
    @param neighbor_ip The IP to be used as IP source and neighbor advertisement target IP.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_neighbor_mac(neighbor_list_t *neighbor, const struct in6_addr *neighbor_ip, const char* p_interface);


/** Sends a router advertisement for the given router containing the RFC4191 Route Info
    as they are currently stored in the router list.
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_propagate_router_routes(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface);

/** Sends a router advertisement for the given router containing the RFC4191 Route Info option to deprecate
    the wrong route
    @param router Pointer to the router list entry of this router containing the last known parameters.
    @param router_ip Pointer to the IP of the router to be used for the bogus prefix advertisement.
    @param wrong_prefix The wrong prefix to deprecate
    @param prefix_len The length of the wrong prefix
    @param p_interface The interface to be used for sending the counter measures.
    @return 0 on success, -1 otherwise.
*/
int cm_kill_wrong_route(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_prefix, const uint8_t prefix_len, const uint8_t param_pref_reserved, const char* p_interface);

#endif

