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

#include "monitoring.h"


int watch_prepare_ethernet(struct capture_info* const capture_info)
{

	capture_info->ethernet_header = (struct ether_header *) capture_info->packet_data;
	if (DEBUG)
	{
		print_eth(capture_info->ethernet_header);
	}

	if (ntohs (capture_info->ethernet_header->ether_type) ==  ETHERTYPE_IPV6)
	{
		capture_info->ip6_header = (struct ip6_hdr*)(capture_info->packet_data + sizeof(struct ether_header));
		watchers_flags_set(&capture_info->watch_flags, WATCH_FLAG_IS_IP6);
	}

	return 0;
}

int watch_prepare_inet6(struct capture_info* const capture_info) 
{
	const struct ip6_hdr* ipptr=capture_info->ip6_header;
	/* for skipping extension headers: */
	int ipv6_next_header = ipptr->ip6_nxt;
	int offset = 0;

	if (DEBUG)
	{
		print_ip6hdr(capture_info->ip6_header);
	}

	if(!IN6_IS_ADDR_UNSPECIFIED(&(capture_info->ip6_header->ip6_src)))
	{
		watchers_flags_set(&capture_info->watch_flags, WATCH_FLAG_IP6_SRC_SPECIFIED);
	}

	/* if the next header field is one of...
	 * 0        HOPOPT (Hop-By-Hop Options)
	 * 43       IPv6-Route
	 * 44       IPv6-Frag
	 * 60       IPv6-Opts (Destination Options)
	 * ...the IPv6 header is followed by one or more extension headers
	 * that must be skipped in order to find the ICMPv6 message.
	 * [http://www.iana.org/assignments/protocol-numbers/]
	 */
	while (1)
	{
		struct ip6_ext* opt_hdr =
			(struct ip6_ext*) (capture_info->packet_data
					+ sizeof(struct ether_header) + sizeof(struct ip6_hdr)
					+ offset);

		/* search until end of packet is reached or unknown
		 * next header is found:
		 */
		if ((uint8_t*)opt_hdr > (capture_info->packet_data+capture_info->packet_length))
		{
			if (DEBUG)
			{
				fprintf(stderr, "    Reached end of packet.\n");
			}
			return 0;
		}

		/* check whether following headers are IPv6 extension headers: */
		switch (ipv6_next_header)
		{
			case IPPROTO_HOPOPTS:
				if (DEBUG)
					fprintf(stderr,
							"    Extension Header: Hop-By-Hop Options.\n");
				break;

			case IPPROTO_ROUTING:
				if (DEBUG)
					fprintf(stderr, "    Extension Header: Routing.\n");
				break;

			case IPPROTO_FRAGMENT:
				if (DEBUG)
					fprintf(stderr, "    Extension Header: Fragment.\n");
				break;

			case IPPROTO_DSTOPTS:
				if (DEBUG)
					fprintf(stderr,
							"    Extension Header: Destination Options.\n");
				break;

			case IPPROTO_ICMPV6:
				if (DEBUG)
					fprintf(stderr, "    Next Header ICMPv6.\n");

				capture_info->icmp6_header
					= (struct icmp6_hdr*) (capture_info->packet_data
							+ sizeof(struct ether_header)
							+ sizeof(struct ip6_hdr) + offset);

				watchers_flags_set(&capture_info->watch_flags,
						WATCH_FLAG_IS_ICMP6);
				return 0;

			default:
				/* no IPv6 extension header, not supported */
				if (DEBUG)
					fprintf(stderr, "    Unknown next header (%u).\n",
							ipv6_next_header);
				return 0;
		}

		/* next header is an IPv6 extension header: */
		ipv6_next_header = opt_hdr->ip6e_nxt;

		/* cf rfc 2460: opt_hdr->ip6e_len
		   8-bit unsigned integer.  Length of the extension
		   header in 8-octet units, not including the first
		   8 octets.
		 */
		offset = offset + (1 + opt_hdr->ip6e_len) * 8;
	}

	return 0;
}

int watch_prepare_icmp6(struct capture_info* const capture_info)
{
	struct nd_router_solicit* rsptr;  
	struct nd_router_advert* raptr;
	struct nd_neighbor_solicit* nsptr;
	struct nd_neighbor_advert* naptr;
	struct nd_redirect* rdptr;
	uint16_t* watch_flags=&capture_info->watch_flags;

	capture_info->icmp6_type = capture_info->icmp6_header->icmp6_type;

	if(DEBUG)
	{
		fprintf(stderr,"ND type: %d\n", capture_info->icmp6_header->icmp6_type);
	}

	switch (capture_info->icmp6_header->icmp6_type)
	{
		case ND_ROUTER_SOLICIT:
			watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
			fprintf(stderr,"----- ND_ROUTER_SOLICIT -----\n");
			if(DEBUG)
			{
				rsptr = (struct nd_router_solicit*) capture_info->icmp6_header;
				print_rs(*rsptr);
			}
			break;

		case ND_ROUTER_ADVERT:
			watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
			fprintf(stderr,"----- ND_ROUTER_ADVERT -----\n");
			raptr = (struct nd_router_advert*) capture_info->icmp6_header;
			if (DEBUG)
			{
				print_ra(*raptr);
			}
			break;

		case ND_NEIGHBOR_SOLICIT:
			watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
			fprintf(stderr,"----- ND_NEIGHBOR_SOLICIT -----\n");
			nsptr = (struct  nd_neighbor_solicit*)  capture_info->icmp6_header;
			if (DEBUG)
			{
				print_ns(*nsptr);
			}
			break;

		case ND_NEIGHBOR_ADVERT:
			watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
			fprintf(stderr,"----- ND_NEIGHBOR_ADVERT -----\n");
			naptr = (struct nd_neighbor_advert*) capture_info->icmp6_header;
			if (DEBUG)
			{
				print_na(*naptr);
			}
			break;

		case ND_REDIRECT:
			watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
			fprintf(stderr,"----- ND_REDIRECT -----\n");
			rdptr = (struct nd_redirect*)  capture_info->icmp6_header;
			print_rd(*rdptr);
			break;

#ifdef _COUNTERMEASURES_
		case ND_NDPMON_PRESENT:
			if (((struct nd_ndpmon_present*)capture_info->icmp6_header)->nd_np_code==ND_NP_CODE)
			{
				watchers_flags_set(watch_flags, WATCH_FLAG_IS_NDP);
				fprintf(stderr,"----- ND_NDPMON_PRESENT -----\n");
			}
			break;
#endif

		case 128:
			watchers_flags_unset(watch_flags, WATCH_FLAG_CONTINUE_CHECKING);
			printf ("Echo request: %d\n", capture_info->icmp6_header->icmp6_type);
			break;
		case 129:
			watchers_flags_unset(watch_flags, WATCH_FLAG_CONTINUE_CHECKING);
			printf ("Echo reply: %d\n", capture_info->icmp6_header->icmp6_type);
			break;

		case 1:
			watchers_flags_unset(watch_flags, WATCH_FLAG_CONTINUE_CHECKING);
			printf ("Address Unreachable: %d\n", capture_info->icmp6_header->icmp6_type);
			break;

		default:
			watchers_flags_unset(watch_flags, WATCH_FLAG_CONTINUE_CHECKING);
			printf ("Unknown ICMPv6 type: %d\n", capture_info->icmp6_header->icmp6_type);
	}

	return 0;
}

int watch_prepare_nd(struct capture_info* const capture_info)
{
	struct nd_option_list* option_list=NULL;
	struct nd_opt_hdr* optptr;
	int size;
	uint8_t* pos;

	/* get offset for the options: */
	switch (capture_info->icmp6_header->icmp6_type)
	{
		case ND_ROUTER_SOLICIT:
			size = sizeof(struct nd_router_solicit);
			break;
		case ND_ROUTER_ADVERT:
			size = sizeof(struct nd_router_advert);
			break;
		case ND_NEIGHBOR_SOLICIT:
			size = sizeof(struct nd_neighbor_solicit);
			break;
		case ND_NEIGHBOR_ADVERT:
			size = sizeof(struct nd_neighbor_advert);
			break;
		case ND_REDIRECT:
			size = sizeof(struct nd_redirect);
			break;
		default:
			/* no neighbor discovery message, contains no options. */
			return 0;
	}

	pos = (uint8_t*) capture_info->icmp6_header + size;
	optptr = (struct nd_opt_hdr*) ( pos );
	while (((u_char*) optptr < (capture_info->packet_data + capture_info->packet_length)) && (optptr->nd_opt_type != 0))
	{
		capture_nd_option_list_add(&option_list, optptr);
		pos += (optptr->nd_opt_len)*8;
		optptr = (struct nd_opt_hdr*) ( pos );
	}

	capture_info->option_list = option_list;

	if (DEBUG && capture_info->option_list!=NULL)
	{
		print_option_list(capture_info->option_list);
	}

	return 0;
}

/*Look for mismatch between the source link layer addr and the one anounced
 *in the icmp option*/
int watch_eth_mismatch(struct capture_info* const capture_info)
{
	char* buffer = capture_info->message;
	const struct ether_header* const ethernet_header = capture_info->ethernet_header;
	const struct ip6_hdr* const ip6_header = capture_info->ip6_header;
	const struct nd_option_list* option_list = capture_info->option_list;
	uint8_t  opt_type;
	struct ether_addr* addr1, *addr2;
	char str_ip[IP6_STR_SIZE];

	switch (capture_info->icmp6_header->icmp6_type)
	{
		case ND_ROUTER_SOLICIT :
		case ND_ROUTER_ADVERT:
		case ND_NEIGHBOR_SOLICIT:
			/* opt_type=1; */
			opt_type=ND_OPT_SOURCE_LINKADDR;
			break;
		case ND_NEIGHBOR_ADVERT:
			/* opt_type=2; */
			opt_type=ND_OPT_TARGET_LINKADDR;
			break;
		case ND_REDIRECT:
			return 0;
		default:
			return 0;
	}/*end switch*/


	/*We have to search the link layer option among the others options: */
	while(option_list!=NULL)
	{
		if(DEBUG)
			print_opt((struct nd_opt_hdr*)&option_list->option_data);

		if(option_list->option_data.option_header.nd_opt_type ==  opt_type)
		{
			addr1 = (struct ether_addr*) ethernet_header->ether_shost;
			addr2 = (struct ether_addr*) &option_list->option_data.linklayer.ethernet_address;
			ipv6_ntoa(str_ip, ip6_header->ip6_src);

			/*mac addr = 48bits: 6Bytes*8*/
			if(MEMCMP(addr1,addr2,6)!=0)
			{
				char eth1[ETH_ADDRSTRLEN];
				strlcpy( eth1, ether_ntoa(addr1), ETH_ADDRSTRLEN);
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "ethernet mismatch %s %s %s", ether_ntoa(addr2),eth1, str_ip);
				alert_raise(1, capture_info->probe, "ethernet mismatch", buffer, addr1, addr2, &capture_info->ip6_header->ip6_src, NULL);
				return 1;
			}
			else
			{
				return 0;
			}
		}
		option_list = option_list->next;
	}

	return 0;

}


/*Look if the source mac address is a broadcast addr or is all zeros*/
int watch_eth_broadcast(struct capture_info* const capture_info)
{
	char* buffer = capture_info->message;
	struct ether_addr* eth_addr = (struct ether_addr*) capture_info->ethernet_header->ether_shost;
	struct ether_addr* test = malloc(sizeof(struct ether_addr));
	char str_ip[IP6_STR_SIZE];
	int broad =0;

	bzero(test,6);

	if (MEMCMP(eth_addr, test,6) ==0)
		broad=1;
	else
	{
		memset(test,255,6);
		if(MEMCMP(eth_addr, test,6)==0)
			broad= 1; 
		else
		{
			char* test2= "33:33:0:0:0:1";
			if(strcmp(ether_ntoa(eth_addr), test2)==0)
				broad=1;
		}
	}

	if(broad)
	{
		ipv6_ntoa(str_ip, capture_info->ip6_header->ip6_src);
		snprintf (buffer, NOTIFY_BUFFER_SIZE,  "ethernet broadcast %s %s",ether_ntoa(eth_addr), str_ip);
		free(test);
		alert_raise(1, capture_info->probe, "ethernet broadcast", buffer, eth_addr, NULL, &capture_info->ip6_header->ip6_src, NULL);
		return 1;
	}
	else
	{
		free(test);
		return 0;	
	}

}


/*Look if the source ip address is a broadcast addr*/
int watch_ip_broadcast(struct capture_info* const capture_info)
{
	char* buffer = capture_info->message;
	struct ether_addr* eth_addr = (struct ether_addr*) capture_info->ethernet_header->ether_shost;
	const struct in6_addr* ip_addr = &(capture_info->ip6_header->ip6_src);
	char str_ip[IP6_STR_SIZE];

	ipv6_ntoa(str_ip, *ip_addr);

	if (IN6_IS_ADDR_MULTICAST(ip_addr))
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "ip multicast %s %s",ether_ntoa(eth_addr),str_ip);
		alert_raise(1, capture_info->probe, "ip multicast", buffer, eth_addr, NULL, &capture_info->ip6_header->ip6_src, NULL);
		return 1;
	}
	else
		return 0;
}


/*Look if the source ip address is local to the subnet*/
int watch_bogon(struct capture_info* const capture_info)
{
	char* buffer = capture_info->message;

	struct ether_addr* eth_addr = (struct ether_addr*) capture_info->ethernet_header->ether_shost;
	const struct in6_addr* ip_addr = &(capture_info->ip6_header->ip6_src);
	char str_ip[INET6_ADDRSTRLEN];
	router_list_t *tmp;
	struct probe* locked_probe;
	int find = 0;

	/* critical section: */
	locked_probe = probe_lock(capture_info->probe->name);
	tmp = locked_probe->routers;
	inet_ntop(AF_INET6, ip_addr, str_ip, INET6_ADDRSTRLEN);

	while( tmp != NULL)
	{
		prefix_t *ptmp = tmp->prefixes;
		while(ptmp != NULL)
		{
			if(IN6_ARE_PRE_EQUAL(ip_addr, &(ptmp->prefix)))
				find = 1;

			ptmp = ptmp->next;
		}
		tmp = tmp->next;
	}
	probe_unlock(capture_info->probe->name);
	/* end critical section. */

	if (!find && !IN6_IS_ADDR_UNSPECIFIED(ip_addr)&&!IN6_IS_ADDR_LINKLOCAL(ip_addr)&&!IN6_IS_ADDR_MULTICAST(ip_addr)&&!IN6_IS_ADDR_SITELOCAL(ip_addr))
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "bogon %s %s",ether_ntoa(eth_addr),str_ip);
		alert_raise(1, capture_info->probe, "bogon", buffer, eth_addr, NULL, ip_addr, NULL);
		return 1;
	}
	else
		return 0;
}


/* Look if the hop limit is set to 255 */
int watch_hop_limit(struct capture_info* const capture_info)
{
	char* buffer = capture_info->message;
	struct ether_addr* eth_addr = (struct ether_addr*) capture_info->ethernet_header->ether_shost;
	const struct in6_addr* ip_addr = &(capture_info->ip6_header->ip6_src);
	char str_ip[IP6_STR_SIZE];
	int hlim;

	ipv6_ntoa(str_ip, *ip_addr);

	hlim = capture_info->ip6_header->ip6_hlim;

	if(hlim != 255)
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "IPv6 Hop Limit %d", hlim);
		alert_raise(1, capture_info->probe, "wrong ipv6 hop limit", buffer, eth_addr, NULL, ip_addr, NULL);
		return 1;
	}

	return 0;
}

int new_station(struct capture_info* const capture_info)
{
	neighbor_list_t** list;
	char str_ip[INET6_ADDRSTRLEN];
	char buffer[NOTIFY_BUFFER_SIZE];
	int found_mac;
	int found_lla;
	int found_ip;
	int ret = 0;
	const struct ether_addr* ethernet_source = (struct ether_addr*) (capture_info->ethernet_header->ether_shost);
	const struct in6_addr*   ipv6_source     = &(capture_info->ip6_header->ip6_src);
	struct probe* locked_probe;

	/* first of all, check if it is IP multicast */
	if (IN6_IS_ADDR_MULTICAST(ipv6_source))
	{
		/* do not treat, it is malformed and alert is already raised */
		return ret;
	}

	/* this whole function is a CRITICAL SECTION due to its poor coding style.
	 * maybe it's a good idea to rewrite it sometime and use the locks more
	 * optimized. but now I will not focus on this.
	 * +thom
	 */
	locked_probe = probe_lock(capture_info->probe->name);
	/* retrieve neighbor list: */
	list = &locked_probe->neighbors;

	/* check if the different packet addresses can be found in the neighbor cache: */
	found_mac = is_neighbor_by_mac(*list, ethernet_source);
	found_lla = is_neighbor_by_lla(*list, ipv6_source);
	found_ip  = is_neighbor_by_ip(*list,  ipv6_source);
	inet_ntop(AF_INET6, ipv6_source, str_ip, INET6_ADDRSTRLEN);

	if(DEBUG)
	{
		fprintf(stderr,"[monitoring] new_station?: found_mac: %d found_lla: %d found_ip: %d\n", found_mac, found_lla, found_ip);
	}

	if( !found_mac )
	{
		/* new ethernet address discovered: */
#ifdef _MACRESOLUTION_
		/* Verify that the MAC address is from a known vendor */
		char vendor[MANUFACTURER_NAME_SIZE];
		strlcpy(vendor, get_manufacturer(manuf, ethernet_source), MANUFACTURER_NAME_SIZE);

		if( !strncmp(vendor, "unknown", MANUFACTURER_NAME_SIZE) )
		{
			/* the MAC address is not from a known vendor, may be a forged address */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "unknown mac vendor %s %s", ether_ntoa(ethernet_source),str_ip);
			alert_raise(1, capture_info->probe, "unknown mac vendor", buffer, ethernet_source, NULL, ipv6_source, NULL);
			ret = 1;
		}
#endif
		watchers_flags_set(&capture_info->watch_flags,WATCH_FLAG_NEW_ETHERNET_ADDRESS);
	}

	if( (found_mac == 0) && (found_lla == 0) && (found_ip == 0) )
	{
		/* new station */
		add_neighbor(list, ethernet_source);

		if( IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
			set_neighbor_lla(*list, ethernet_source, ipv6_source);
		else if( !IN6_IS_ADDR_MULTICAST(ipv6_source) )
			neighbor_ip_add(*list, ethernet_source, ipv6_source);

		snprintf(buffer, NOTIFY_BUFFER_SIZE, "new station %s %s", ether_ntoa(ethernet_source),str_ip);
		neighbor_update(capture_info->probe->name, NULL, NULL, get_neighbor_by_mac(*list, ethernet_source));
		alert_raise(1, capture_info->probe, "new station", buffer, ethernet_source,NULL, ipv6_source, NULL);
		ret = 1;
	}

	else if( (found_mac ==1) && (found_lla == 0) && IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
	{
		/* the neighbor is known, but not its LLA */
		set_neighbor_lla(*list, ethernet_source, ipv6_source);
		/* reset timer for host */
		reset_neighbor_timer(*list, ethernet_source, capture_info->probe);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "new lla %s %s\n", ether_ntoa(ethernet_source),str_ip);
		neighbor_update(capture_info->probe->name, ethernet_source, NULL, get_neighbor_by_mac(*list, ethernet_source));
		alert_raise(1, capture_info->probe, "new lla", buffer, ethernet_source, NULL, ipv6_source, NULL);
		ret = 1;
	}

	else if( (found_mac ==1) && (found_ip == 0) && !IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
	{
		/* the neighbor is known, but not this IP */
		if( !IN6_IS_ADDR_MULTICAST(ipv6_source) )
			neighbor_ip_add(*list, ethernet_source, ipv6_source);
		/* reset timer for host */
		reset_neighbor_timer(*list, ethernet_source, capture_info->probe);
		snprintf (buffer, NOTIFY_BUFFER_SIZE, "new IP %s %s\n", ether_ntoa(ethernet_source),str_ip);
		neighbor_update(capture_info->probe->name, ethernet_source, NULL, get_neighbor_by_mac(*list, ethernet_source));
		alert_raise(1, capture_info->probe, "new IP", buffer, ethernet_source, NULL, ipv6_source, NULL);
		ret = 1;
	}

	else if( (found_mac == 1) && ( (found_lla)||(found_ip) ) )
	{
		neighbor_list_t *tmp;
		int clean_addresses = 1;

		/* Verify that the source addresses
		 * i.e. that the couple MAC/LLA or MAC/IP is from the same host
		 */
		if(found_ip)
		{
			if( !IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
				if( !neighbor_has_ip(*list,ethernet_source,ipv6_source) )
				{
					/* MAC is from one host and IP SRC from another
					 * Maybe an error or not, remove the IP from the old host and assign it to the new one
					 * Raise a "changed ethernet" alert
					 */
					char temp[ETH_ADDRSTRLEN];
					struct ether_addr old_mac;

					clean_addresses = 0;	/* source addresses do not belong to the same host */

					tmp = (neighbor_list_t*) get_neighbor_by_ip(*list,ipv6_source);
					memcpy(&old_mac, &(tmp->mac), sizeof(struct ether_addr) );		/* Copy the MAC from the host with the IP */
					snprintf(temp, ETH_ADDRSTRLEN-1, "%s", ether_ntoa(&(tmp->mac)));	/* str copy as well */

					/* Remove the global address from the host that has it */
					neighbor_ip_remove(*list, &(tmp->mac), ipv6_source);

					/* Add the address to the host identified by the mac address */
					neighbor_ip_add(*list, ethernet_source, ipv6_source);

					/* Raise changed ethernet address */
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "changed ethernet address %s to %s %s", temp, ether_ntoa(ethernet_source),str_ip);
					if(DEBUG)
						fprintf (stderr, "changed ethernet address %s to %s %s\n", temp, ether_ntoa(ethernet_source),str_ip);
					alert_raise(1, capture_info->probe, "changed ethernet address", buffer, ethernet_source, &(old_mac), ipv6_source, NULL);

					ret = 2;
				}
		}
		else if(found_lla)
		{
			if( IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
				if( !neighbor_has_lla(*list,ethernet_source,ipv6_source) )
				{
					/* MAC is from one host and LLA from another
					 * wrong couple MAC / LLA SRC in ICMP6 
					 * ALERT: spoofed addresses in icmp6
					 * */
					char eth_str[ETH_ADDRSTRLEN];

					clean_addresses = 0;	/* source addresses do not belong to the same host */

					snprintf(eth_str, ETH_ADDRSTRLEN, "%s", ether_ntoa(ethernet_source));

					snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong couple MAC/LLA in icmp6 %s %s", eth_str, str_ip);
					if(DEBUG)
						fprintf (stderr, "wrong couple MAC/LLA in icmp6 %s %s\n", eth_str, str_ip);
					alert_raise(2, capture_info->probe, "wrong couple MAC/LLA", buffer, ethernet_source, NULL, ipv6_source, NULL);
				}
		}

		if(clean_addresses)
		{
			/* reset timer for host */
			reset_neighbor_timer(*list, ethernet_source, capture_info->probe);
			fprintf (stderr, "Reset timer for %s %s\n", ether_ntoa(ethernet_source),str_ip);

			/* if the IP exists, reset timer */
			if( found_ip == 1 )
			{
				reset_neighbor_address_timer(*list, ethernet_source, ipv6_source);
				fprintf (stderr, "Reset address timer for %s %s\n", ether_ntoa(ethernet_source),str_ip);
			}
			neighbor_update(capture_info->probe->name, ethernet_source, NULL, get_neighbor_by_mac(*list, ethernet_source));
		}
#if 0
		else
		{
			/* Ignored for the moment to avoid interpretation in alerts
			 * Stick to Arpwatch behavior
			 * */
			/* wrong couple MAC / IP SRC in ICMP6 
			 * ALERT: spoofed addresses in icmp6
			 * */
			char eth_str[ETH_ADDRSTRLEN];

			snprintf(eth_str, ETH_ADDRSTRLEN, "%s", ether_ntoa(ethernet_source));

			snprintf (buffer, NOTIFY_BUFFER_SIZE, "spoofed addresses in icmp6 %s %s", eth_str, str_ip);
			if(DEBUG)
				fprintf (stderr, "spoofed addresses in icmp6 %s %s", eth_str, str_ip);
			alert_raise(2, capture_info->probe, "spoofed addresses", buffer, ethernet_source, NULL, ipv6_source, NULL);

		}
#endif
	}

	else if( (found_mac == 0) && ( (found_lla)||(found_ip) ) )
	{
		struct in6_addr lla;
		neighbor_list_t *tmp;

		if( IN6_IS_ADDR_LINKLOCAL(ipv6_source) )
			memcpy(&lla, ipv6_source, sizeof(struct in6_addr));
		else
		{
			tmp = (neighbor_list_t*) get_neighbor_by_ip(*list,ipv6_source);
			lla = tmp->lla;
		}

		if( neighbor_has_old_mac(*list, &lla, ethernet_source) )
		{
			/* Flip Flop - Reused Ethernet Address */
			char temp[ETH_ADDRSTRLEN];
			struct ether_addr old_mac;
			struct ether_addr previous_mac = neighbor_get_last_mac(*list,lla);

			tmp = (neighbor_list_t*) get_neighbor_by_lla(*list,&lla);
			snprintf(temp, ETH_ADDRSTRLEN, "%s", ether_ntoa(&(tmp->mac)));
			memcpy(&old_mac, &(tmp->mac), sizeof(struct ether_addr) );		/* keep a copy of the old mac before updating neighbor */

			if(!MEMCMP(ethernet_source,&previous_mac, sizeof(struct ether_addr)))
			{
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "flip flop between %s and %s for %s", temp, ether_ntoa(ethernet_source), str_ip);
				if(DEBUG)
					fprintf (stderr, "flip flop between %s and %s for %s\n", temp, ether_ntoa(ethernet_source), str_ip);
				alert_raise(2, capture_info->probe, "flip flop", buffer, ethernet_source, &old_mac, ipv6_source, NULL);
			}
			else
			{
				sprintf (buffer, "reused old ethernet address %s instead of %s for %s", ether_ntoa(ethernet_source), temp, str_ip);
				if(DEBUG)
					fprintf (stderr, "reused old ethernet address %s instead of %s for %s\n", ether_ntoa(ethernet_source), temp, str_ip);
				alert_raise(2, capture_info->probe, "reused old ethernet address", buffer, ethernet_source, &old_mac, ipv6_source, NULL);
			}
			neighbor_update_mac(*list, &lla, ethernet_source);
			neighbor_update(capture_info->probe->name, NULL, &lla, get_neighbor_by_lla(*list, &lla));
			ret = 2;

#ifdef _COUNTERMEASURES_
			/* We only propagate a counter measure if the probe is  a local one */
			if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
			{
				/* we need to pass the interface on which 
				 * the countermeasure must be propagated as a parameter 
				 * i.e. the probe name */
				cm_propagate_neighbor_mac(tmp, ipv6_source, locked_probe->name);
			}
#endif
		}
		else
		{
			/* Changed Ethernet Address */
			char temp[ETH_ADDRSTRLEN];
			struct ether_addr old_mac;

			tmp = (neighbor_list_t*) get_neighbor_by_lla(*list,&lla);
			memcpy(&old_mac, &(tmp->mac), sizeof(struct ether_addr) );		/* keep a copy of the old mac before updating neighbor */
			snprintf(temp, ETH_ADDRSTRLEN-1, "%s", ether_ntoa(&(tmp->mac)));	/* str copy as well */

			neighbor_update_mac(*list, &lla, ethernet_source);			/* update the neighbor in the list */
			neighbor_update(capture_info->probe->name, NULL, &lla, get_neighbor_by_lla(*list, &lla));

			snprintf (buffer, NOTIFY_BUFFER_SIZE, "changed ethernet address %s to %s %s", temp, ether_ntoa(ethernet_source),str_ip);
			if(DEBUG)
				fprintf (stderr, "changed ethernet address %s to %s %s\n", temp, ether_ntoa(ethernet_source),str_ip);
			alert_raise(2, capture_info->probe, "changed ethernet address", buffer, ethernet_source, &(old_mac), ipv6_source, NULL);
			
			ret = 2;
		}
	}

	/* luckily you did the return in such a way that it does not leave
	 * a zombie lock when I only put the unlock stuff here... at least I hope...
	 * +thom
	 */
	probe_unlock(capture_info->probe->name);
	/* end of critical function ;) */
	return ret;
}
