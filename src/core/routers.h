#ifndef _ROUTER_LIST_H_
#define _ROUTER_LIST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if 0
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif
#include <signal.h>
#include <time.h>

#include <libxml/tree.h>

#include "../ndpmon_defs.h"
#include "../ndpmon_netheaders.h"

#include "cache_types.h"
#include "print_packet_info.h"

router_list_t * router_get(router_list_t *list, struct in6_addr lla, struct ether_addr eth);

int is_router_lla_in(router_list_t *list, struct in6_addr lla);
int is_router_mac_in(router_list_t *list, struct ether_addr eth);
int router_has_router(router_list_t *list, struct in6_addr lla, struct ether_addr eth);

/** Adds a router to the list a routers.
    Changed in order to take the additional router parameters.
    @param list The list of routers.
    @param eth  Pointer to the ETHERNET address of the router.
    @param lla  Pointer to the link local address (not to be confused with link layer address).
    @param curhoplimit         RA Parameter: The current hop limit.
    @param flags_reserved      RA Parameter: M+O flag and reserved bits.
    @param router_lifetime     RA Parameter: Router lifetime.
    @param reachable_timer     RA Parameter: Reachable timer.
    @param retrans_timer RA Parameter: Retransmission timer.
*/
int router_add(router_list_t **list, const struct ether_addr* eth, const struct in6_addr* lla,
        uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer, uint32_t param_mtu, int params_volatile);

int router_add_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, uint8_t flags_reserved, uint32_t valid_lifetime, uint32_t preferred_lifetime);
int router_has_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);
prefix_t* router_get_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);

int router_has_nameserver(router_list_t *list, struct ether_addr eth, struct in6_addr addr, uint32_t lifetime);
int router_add_nameserver(router_list_t *list, struct ether_addr eth, struct in6_addr addr, uint32_t lifetime);

int router_has_domain(router_list_t *list, struct ether_addr eth, const char *domain, uint32_t lifetime);
int router_add_domain(router_list_t *list, struct ether_addr eth, const char *domain, uint32_t lifetime);


int router_has_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr);
int router_add_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr);


int router_add_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, uint8_t pref_reserved, uint32_t lifetime);
int router_has_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);
route_info_t* router_get_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask);


int nb_router(router_list_t *routers);
void print_routers(router_list_t *list);

int clean_router_prefixes(router_list_t **list, struct ether_addr eth);
int clean_router_addresses(router_list_t **list, struct ether_addr eth);
int clean_router_rdnss(router_list_t **list, struct ether_addr eth);
int clean_router_dnssl(router_list_t **list, struct ether_addr eth);
int clean_router_routes(router_list_t **list, struct ether_addr eth);
int clean_routers(router_list_t **list);

int router_list_parse(xmlNodePtr element, router_list_t** routers);
int router_list_store(xmlNodePtr routers_element, router_list_t* routers);

/** Performs a deep copy of the given router list entry.
 *  @param destination The router to copy to (must be allocated).
 *  @param source      The source to copy from.
 */
void router_copy(router_list_t* destination, router_list_t* source);

#endif
