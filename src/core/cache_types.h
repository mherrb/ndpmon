#ifndef _CACHE_TYPES_H_
#define _CACHE_TYPES_H_

#include "ndpmon_defs.h"
#include "../ndpmon_netheaders.h"

/** Maximum size of a probe name. */
#define PROBE_NAME_SIZE 100

typedef struct address
{
	/* the IPv6 address */
        struct in6_addr address;
	/* when the address was seen for the first and last time */
	time_t firstseen;
	time_t lastseen;
	struct address *next;
} address_t;


typedef struct ethernet
{
        struct ether_addr mac;
#ifdef _MACRESOLUTION_
	char vendor[MANUFACTURER_NAME_SIZE];
#endif
	struct ethernet *next;
} ethernet_t;


typedef struct neighbor_list
{
	struct ether_addr mac;
/* ADDED*/
	struct ether_addr first_mac_seen;
	int trouble;
/* END ADDED */
#ifdef _MACRESOLUTION_
	char vendor[MANUFACTURER_NAME_SIZE];
#endif
	struct ether_addr previous_mac;
	ethernet_t *old_mac;
	struct in6_addr lla;
	address_t *addresses;
	time_t timer;
	struct extinfo_list* extinfo;
	struct neighbor_list *next;
} neighbor_list_t;


/** Stores entries for the prefixes advertised by routers in the network.
    The structure members starting with param_ are used to determine
    whether the params of a RA prefix info option are valid.
*/
typedef struct prefix
{
        /** The prefix address.*/
        struct in6_addr prefix;
        /** The number of valid bits in the prefix address.*/
	uint8_t mask;
	/** RA param: Prefix preferred time.*/
	uint8_t param_flags_reserved;
	/** RA param: Prefix valid time.*/
	uint32_t param_valid_time;
	/** RA param: Prefix preferred time.*/
	uint32_t param_preferred_time;
        /** Pointer to the next prefix list entry.*/
	struct prefix *next;
} prefix_t;


/* RFC6106 related cache structures
 * Stores DNS Recursive name Servers addresses - RDNSS
 * and DNS Search list - DNSSL
 **/

/* Recursive DNS Servers list  */
typedef struct rdnss
{
        struct in6_addr address;
	uint32_t lifetime;
	struct rdnss *next;
} rdnss_t;

/* DNS Search List */
typedef struct dnssl
{
	char domain[MAX_DOMAINLEN];
	uint32_t lifetime;
	struct dnssl *next;
} dnssl_t;

/* RFC6106 */



/* RFC4191 related cache structures
 * Stores Route Information option²
 **/
typedef struct route_info
{
        struct in6_addr prefix;		/* the prefix for the route to add */
	uint8_t mask;			/* Prefix lenght */
	uint32_t lifetime;		/* Lifetime */
	uint8_t param_pref_reserved;	/* Reserved + route preference */
	struct route_info *next;
} route_info_t;

/* RFC4191 */



/** Stores entries for the legitimate routers in the network.
    The members starting with "param_" are used to determine whether
    the RA params are wellformed and to send faked RA in the counter measures plugin.
*/
typedef struct router_list
{
	/** The routers ETHERNET address.*/
	struct ether_addr mac;
	/** The router link local address.*/
	struct in6_addr lla;
	/** RA param: Current hop limit (default time to live).*/
	uint8_t  param_curhoplimit;
	/** RA param: M+O flag and reserved 6 bits.*/
	uint8_t  param_flags_reserved;
	/** RA param: Router lifetime.*/
	uint16_t param_router_lifetime;
	/** RA param: Reachable timer.*/
	uint32_t param_reachable_timer;
	/** RA param: Retransmission timer.*/
	uint32_t param_retrans_timer;
	/** RA param (optional): Maximum transmission unit.*/
	uint32_t param_mtu;
        /** Indicates whether the params of this router may change during operation.
	    If this is set to zero, NDPMon checks the params of captured RA (including prefix
	    lifetimes and the MTU option) against the values learned and stored in this list.
	*/
	int params_volatile;
	/** Pointer to the list of IP addresses for this router. */
	address_t *addresses;
	/** Pointer to the list of prefixes for this router. */
	prefix_t *prefixes;
	/** Pointer to the list of recursive DNS servers. */
	rdnss_t *nameservers;
	/** Pointer to the list of DNS search list. */
	dnssl_t *domains;
	/** Pointer to the list of routes advertised */
	route_info_t *routes;
	/** Pointer to the next router list entry.*/
	struct router_list *next;
} router_list_t;

enum probe_type
{
    /** Locally connected interface. */
    PROBE_TYPE_INTERFACE,
    /** Remote interface that is reporting to this NDPMon instance. */
    PROBE_TYPE_REMOTE
};

/** Holds all state information of a probe. */
struct probe 
{
    /** Capturing handle for this probe. */
    capture_handle_t capture_handle;
    /** The type of this probe. */
    enum probe_type type;
    /** Name of the probe, e.g. "eth0". */
    char name[PROBE_NAME_SIZE];
#ifdef _COUNTERMEASURES_
    /** Counter measures enabled or disabled for that probe **/
    int cm_enabled;
#endif
    /** Ethernet address of the probe. */
    struct ether_addr ethernet_address;
    /** IPv6 addresses of this probe. */
    address_t* addresses;
    /** Extinfo for this probe (plugin state information). */
    struct extinfo_list* extinfo;
    /** This probe's neighbor cache. */
    neighbor_list_t* neighbors;
    /** The router list of this probe. */
    router_list_t* routers;
};

#endif
