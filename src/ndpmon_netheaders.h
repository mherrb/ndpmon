#ifndef _NDPMON_NETHEADERS_H_
#define _NDPMON_NETHEADERS_H_

#include <sys/socket.h>
#include <arpa/inet.h>

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#endif

#ifdef _OPENBSD_
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#endif

#ifdef _LINUX_
#include <netinet/ether.h>
#include <net/ethernet.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h> 
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <netdb.h>


/* 
 * RFC6106 - RDNSS and DNSSL
 * Belongs in <netinet/icmp6.h> 
 **/

/* Recursive DNS Server */
#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
#endif
struct nd_opt_rdnss
{
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved;
	uint32_t nd_opt_rdnss_lifetime;
	/* followed by one or more (should not be more than MAXNS=3) IPv6 addresses */
	/* struct in6_addr nd_opt_rdnss_addr[3]; */
};

/* DNS Search List */
#ifndef ND_OPT_DNSSL
#define ND_OPT_DNSSL 31
#endif
struct nd_opt_dnssl
{
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved;
	uint32_t nd_opt_dnssl_lifetime;
	/* followed by one or more domain names */
};

/* RFC6106 - END */



/* RFC4191 Route info option
 * Belongs in <netinet/icmp6.h> 
 **/
#ifndef  ND_OPT_ROUTE_INFORMATION
#define  ND_OPT_ROUTE_INFORMATION	24
#endif

struct nd_opt_route_info
{
	uint8_t   nd_opt_ri_type;
	uint8_t   nd_opt_ri_len;
	uint8_t   nd_opt_ri_prefix_len;
	uint8_t   nd_opt_ri_pref_reserved;
	uint32_t  nd_opt_ri_lifetime;
	struct in6_addr  nd_opt_ri_prefix;
};

/* Route preference is set in the middle of the reserved field
 * i.e. 000XX000
 * Thus we define a mask 0x00011000 and shift value of 3 to read it
 **/
#define ND_OPT_RI_PREF_SHIFT	3
#define ND_OPT_RI_PREF_MASK	(3 << ND_OPT_RI_PREF_SHIFT)
#define ND_OPT_RI_PREF_HIGH	0x08 /* 00001000 */
#define ND_OPT_RI_PREF_MEDIUM	0x00 /* 00000000 */
#define ND_OPT_RI_PREF_LOW	0x18 /* 00011000 */
#define ND_OPT_RI_PREF_IGNOR	0x10 /* 00010000 */

/* RFC4191 - END */



/* WARNING : HOOK HERE 
 * because we shoulf only perform unions on structures with fixed size
 * 
 * With RFC6106  options we introduced option headers with dynamic length
 * thus if we leave  the next pointer at the end of the structure it overrides values
 * even if we do the right malloc, as the next field is placed after the union
 * which means after the size of the largest structure in the union
 * 
 * However, this means that EXTRA CARE MUST BE TAKEN WHEN INITIALIZING THE STRUCTURE
 * AND DOING THE MALLOC
 * Moreover, this can cause troubles for later extensions or for static code analysis
 *
 **/
struct nd_option_list 
{
	struct nd_option_list* next;
	union 
	{
		struct nd_opt_hdr option_header;
		struct 
		{
			struct nd_opt_hdr option_header;
			struct ether_addr ethernet_address;
		} linklayer;
		struct nd_opt_prefix_info prefix_info;
		struct nd_opt_mtu mtu;
		struct nd_opt_rdnss rdnss;
		struct nd_opt_dnssl dnssl;
		struct nd_opt_route_info route_info;
	} option_data;
};

#define nd_option_type option_data.option_header.nd_opt_type
#define nd_option_len  option_data.option_header.nd_opt_len

#endif
