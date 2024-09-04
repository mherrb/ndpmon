/********************************************************************************
  NDPMon - Neighbor Discovery Protocol Monitor
  Copyright (C) 2006 MADYNES Project, LORIA - INRIA Lorraine (France)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Author Info:
Name: Thibault Cholez
Mail: thibault.cholez@esial.uhp-nancy.fr

Maintainer:
Name: Frederic Beck
Mail: frederic.beck@loria.fr

MADYNES Project, LORIA-INRIA Lorraine, hereby disclaims all copyright interest in
the tool 'NDPMon' (Neighbor Discovery Protocol Monitor) written by Thibault Cholez.

Olivier Festor, Scientific Leader of the MADYNEs Project, 20 August 2006
 ***********************************************************************************/

#include "monitoring_na.h"


/*Test if the NA enable the router flag and if true
 *test if this neighbor is an official router
 */
int watch_R_flag(struct capture_info* const capture_info) 
{
	struct nd_neighbor_advert* neighbor_advert = (struct nd_neighbor_advert*) capture_info->icmp6_header;
	struct probe* locked_probe;

	/*Mask is used to select the R_FLAG from the NA*/
	int R_FLAG = (neighbor_advert->nd_na_flags_reserved)&ND_NA_FLAG_ROUTER;
	int ret = 0;

	if(DEBUG)
		fprintf(stderr, "NA flag router: %d\n", R_FLAG);

	if (R_FLAG)
	{

		char ip_address[IP6_STR_SIZE];
		char* mac_address = NULL;
		struct ether_addr *src_eth = (struct ether_addr *)capture_info->ethernet_header->ether_shost;
		int found_mac;
		int found_lla;

		/* critical section: */
		locked_probe = probe_lock(capture_info->probe->name);
		found_mac = is_router_mac_in(locked_probe->routers, *src_eth);
		found_lla = is_router_lla_in(locked_probe->routers, capture_info->ip6_header->ip6_src);
		locked_probe = NULL;
		probe_unlock(capture_info->probe->name);
		/* end critical section. */

		mac_address= (char*)ether_ntoa((struct ether_addr*) (capture_info->ethernet_header->ether_shost));
		ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);

		if(!found_mac)
		{
			snprintf (capture_info->message, NOTIFY_BUFFER_SIZE, "NA router flag %s %s", mac_address, ip_address);
			alert_raise(
					2, capture_info->probe,
					"NA router flag",
					capture_info->message,
					(struct ether_addr*) (capture_info->ethernet_header->ether_shost),
					NULL, &capture_info->ip6_header->ip6_src, NULL);
			return 2;
		}
		else
		{
			if(!found_lla)
			{
				int found_ip = 0;
				/* critical section: */
				locked_probe = probe_lock(capture_info->probe->name);
				if (router_has_address(locked_probe->routers, *src_eth, capture_info->ip6_header->ip6_src)) {
					found_ip = 1;
				}
				locked_probe = NULL;
				probe_unlock(capture_info->probe->name);
				/* end of critical section. */

				if( !found_ip)
				{
					snprintf (capture_info->message, NOTIFY_BUFFER_SIZE, "NA router flag %s %s", mac_address, ip_address);
					alert_raise(
							2, capture_info->probe,
							"NA router flag",
							capture_info->message,
							(struct ether_addr*) (capture_info->ethernet_header->ether_shost),
							NULL, &capture_info->ip6_header->ip6_src, NULL);
					return 2;
				}
			}
		}
	}  

	return ret;
}



/*Test if the NA is doing Duplicate Address Detection DOS
  Detect if a host is responding a wrong IPv6 not corresponding to its mac addr
  */
int watch_dad_dos(struct capture_info* const capture_info) 
{
	const struct in6_addr* wanted_addr=NULL;
	struct nd_neighbor_advert* neighbor_advert = (struct nd_neighbor_advert*) capture_info->icmp6_header;
	int new_eth = watchers_flags_isset(capture_info->watch_flags, WATCH_FLAG_NEW_ETHERNET_ADDRESS);
	struct probe* locked_probe;

	const struct ether_addr* ethernet_source = (struct ether_addr*) (capture_info->ethernet_header->ether_shost);
	neighbor_list_t** list;
	int found_mac;

	/* critical section: */
	locked_probe = probe_lock(capture_info->probe->name);
	wanted_addr = extinfo_list_get_data(locked_probe->extinfo, "last_dad_address");
	list = &locked_probe->neighbors;
	found_mac = is_neighbor_by_mac(*list, ethernet_source);
	probe_unlock(capture_info->probe->name);
	/* end of critical section. */

	if( !found_mac )
	{
		/* is it a DOS i.e. it is done by a station never seen before this NA */
		new_eth = 1;
	}

	if(wanted_addr!=NULL && IN6_ARE_ADDR_EQUAL(&neighbor_advert->nd_na_target, wanted_addr))
	{
		/* NA against the last NS for DAD :-/ */
		/* Is this response true ? */
		int find_mac = 0;
		int dos = 0;

		/*If DOS is done by a station never seen before this NA, it should be an attack*/
		if(new_eth)
		{
			dos=1;
		}
		else
		{
			const neighbor_list_t* neighbor;
			struct in6_addr neighbor_lla;
			int neighbor_has_na_ip = 0;
			struct ether_addr * src_eth = (struct ether_addr*)capture_info->ethernet_header->ether_shost;

			/*Is the mac addr in the neighbor list ?*/
			/* critical section: */
			locked_probe = probe_lock(capture_info->probe->name);
			neighbor = get_neighbor_by_mac(locked_probe->neighbors, src_eth);
			if (neighbor!=NULL) 
			{
				/* neighbor with given MAC exists: */
				find_mac = 1;
				memcpy(&neighbor_lla, &neighbor->lla, sizeof(struct in6_addr));
			}
			if (neighbor_has_ip(locked_probe->neighbors, src_eth, &neighbor_advert->nd_na_target)) 
			{
				/* neighbor has given ip (only if address is not LLA): */
				neighbor_has_na_ip = 1;
			}
			/* don't touch it further: */
			neighbor = NULL;
			probe_unlock(capture_info->probe->name);
			/* end of critical section. */

			if(find_mac == 1) 
			{
				if( !IN6_ARE_ADDR_EQUAL(&neighbor_advert->nd_na_target,&neighbor_lla))
				{
					char toto[INET6_ADDRSTRLEN];
					char ip_address[40];
					ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
					ipv6_ntoa(toto, neighbor_lla);
					if (neighbor_has_na_ip!=1)
					{
						dos = 1;
					}
				}
			}
		}

		if(dos)
		{
			char ip_address[40];

			fprintf(stderr,"[monitoring_na] New Ethernet DAD DoS\n");
			ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
			snprintf (capture_info->message, NOTIFY_BUFFER_SIZE, "dad dos %s %s", (char*)ether_ntoa((struct ether_addr*) (capture_info->ethernet_header->ether_shost)), ip_address);
			alert_raise(
					2, capture_info->probe,
					"dad dos",
					capture_info->message,
					(struct ether_addr*) (capture_info->ethernet_header->ether_shost),
					NULL, &capture_info->ip6_header->ip6_src, NULL);
			return 2;
		}
		else
			return 0;
	}
	else
		return 0;
}


/*
 * Test the NA target
 * Do not check the Target LLAddr because of NDP Proxies - RFC4389
 */
int watch_na_target(struct capture_info* const capture_info) 
{
	struct nd_neighbor_advert* neighbor_advert = (struct nd_neighbor_advert*) capture_info->icmp6_header;
	const struct nd_option_list* option_list = capture_info->option_list;
	int found_tgt_lladdr = 0;

	const struct ether_addr *ether_source = (struct ether_addr *)capture_info->ethernet_header->ether_shost;
	const struct in6_addr *ipv6_source = &(capture_info->ip6_header->ip6_src);
	const struct in6_addr *target_address = &(neighbor_advert->nd_na_target);

	char target_address_str[INET6_ADDRSTRLEN];		/* target addr in NA */
	char *ether_source_str = NULL;			/* source ethernet address */
	char ipv6_source_str[INET6_ADDRSTRLEN];		/* source IP address */

	char buffer[NOTIFY_BUFFER_SIZE];
	int ret = 0;

	/* Value of the Override flag */
	int Override = (neighbor_advert->nd_na_flags_reserved)&ND_NA_FLAG_OVERRIDE;

	/* String representations */
	ipv6_ntoa(target_address_str, *target_address);
	ether_source_str = (char*)ether_ntoa((struct ether_addr*) ether_source);
	ipv6_ntoa(ipv6_source_str, *ipv6_source);
#if 0		
	fprintf(stderr, "----->>> Received NA from %s %s with target %s\n", ether_source_str, ipv6_source_str, target_address);
#endif
	
	/* 
	 * RFC 4861 says  target address MUST NOT be a multicast address
	 * */
	if( IN6_IS_ADDR_MULTICAST(target_address) )
	{
		fprintf(stderr,"[monitoring_na] NA multicast target\n");
		if(DEBUG)
			fprintf(stderr, "NA multicast target %s %s %s\n", ether_source_str, ipv6_source_str, target_address_str);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "NA multicast target %s %s %s", ether_source_str,ipv6_source_str, target_address_str);
		alert_raise(2, capture_info->probe, "NA multicast target", buffer, ether_source, NULL, ipv6_source, NULL);

		ret = 2;
	}

	/* LLA in ipv6 source the same that LLA in target address
	 *
	 * RFC4861 section 7.2.4 says:
	 * "If the Target Address is either an anycast address or a unicast
	 *  address for which the node is providing proxy service, or the Target
	 *  Link-Layer Address option is not included, the Override flag SHOULD
	 *  be set to zero.  Otherwise, the Override flag SHOULD be set to one."
	 *
	 * This is valid for proxying issues as long as the Override flag is set to zero
	 * As NAT is about to become a reality in IPv6 this may raise a lot of false positives
	 * */
#if 0
	if( IN6_IS_ADDR_LINKLOCAL(ipv6_source) && IN6_IS_ADDR_LINKLOCAL(target_address) )
	{
		if( !IN6_ARE_ADDR_EQUAL(ipv6_source, target_address) )
		{
			/* Raise alert */
			fprintf(stderr,"[monitoring_na] NA LLA mismatch\n");
			if(DEBUG)
				fprintf(stderr, "NA LLA mismatch %s %s %s\n", ether_source_str, ipv6_source_str, target_address_str);
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "NA LLA mismatch %s %s %s", ether_source_str,ipv6_source_str, target_address_str);
			alert_raise(2, capture_info->probe, "NA LLA mismatch", buffer, ether_source, NULL, ipv6_source, NULL);

			ret = 2;

		}
	}
#endif

#if 0
fprintf(stderr,"IPv6 Source addr: %.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x\n", 
		ntohs(ipv6_source->s6_addr16[0]), ntohs(ipv6_source->s6_addr16[1]), ntohs(ipv6_source->s6_addr16[2]), ntohs(ipv6_source->s6_addr16[3]),
		ntohs(ipv6_source->s6_addr16[4]), ntohs(ipv6_source->s6_addr16[5]), ntohs(ipv6_source->s6_addr16[6]), ntohs(ipv6_source->s6_addr16[7]) );

fprintf(stderr,"Target addr: %.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x\n", 
		ntohs(target_address->s6_addr16[0]), ntohs(target_address->s6_addr16[1]), ntohs(target_address->s6_addr16[2]), ntohs(target_address->s6_addr16[3]),
		ntohs(target_address->s6_addr16[4]), ntohs(target_address->s6_addr16[5]), ntohs(target_address->s6_addr16[6]), ntohs(target_address->s6_addr16[7]) );
#endif

	/* Check the Override flag value  */
	/* Advertizing a different unicast or anycast address than IPv6 source, Override=0 */
	if( !IN6_ARE_ADDR_EQUAL(ipv6_source, target_address) )
	{
		/* anycast or unicast */
		if( IN6_IS_ADDR_ANYCAST(target_address)		/* anycast target */
		  || (!IN6_IS_ADDR_MULTICAST(target_address) 	/* not anycast, not multicast, not ::, not ::1, not mapped, it is unicast */
		     && !IN6_IS_ADDR_UNSPECIFIED(target_address) && !IN6_IS_ADDR_LOOPBACK(target_address) 
		     && !IN6_IS_ADDR_V4MAPPED(target_address)  && !IN6_IS_ADDR_V4COMPAT(target_address))
		  )
		{
			/* Override should be 0 */
			if( Override )
			{
				/* Raise alert */
				if(DEBUG)
					fprintf(stderr, "NA Override flag %s %s %s\n", ether_source_str, ipv6_source_str, target_address_str);
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "NA Override flag %s %s %s", ether_source_str,ipv6_source_str, target_address_str);
				alert_raise(1, capture_info->probe, "NA Override flag", buffer, ether_source, NULL, ipv6_source, NULL);

				ret = 2;
			}

		}
	}

	/* No Target link layer option, Override = 0 */
	while(option_list!=NULL)
	{
		/* Look in the option if it is the target link layer address */
		if(option_list->option_data.option_header.nd_opt_type ==  ND_OPT_TARGET_LINKADDR)
		{
			found_tgt_lladdr = 1;
		}
		option_list = option_list->next;
	}

	if(Override && !found_tgt_lladdr)
	{
		/* Raise alert */
		if(DEBUG)
			fprintf(stderr, "NA Override flag %s %s %s\n", ether_source_str, ipv6_source_str, target_address_str);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "NA Override flag %s %s %s", ether_source_str,ipv6_source_str, target_address_str);
		alert_raise(1, capture_info->probe, "NA Override flag", buffer, ether_source, NULL, ipv6_source, NULL);

		ret = 2;
	}

	return ret;
}


