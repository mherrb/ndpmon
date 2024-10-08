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


#include "print_packet_info.h"

/*Print eth header information*/ 
void print_eth(const struct ether_header* const eptr)
{
	fprintf(stderr,"    Source mac address: %s \n",ether_ntoa((struct ether_addr*) (eptr->ether_shost)));
	fprintf(stderr,"    Destination mac address: %s \n",ether_ntoa((struct ether_addr*)(eptr->ether_dhost)));
}

/*Print ip6 header information*/ 
void print_ip6hdr(const struct ip6_hdr* const ipptr)
{
	char buffer[IP6_STR_SIZE];

	ipv6_ntoa(buffer, ipptr->ip6_src);
	fprintf(stderr,"    Source IPv6 address: %s\n", buffer);
	ipv6_ntoa(buffer, ipptr->ip6_dst);
	fprintf(stderr,"    Destination IPv6 address: %s\n", buffer);
	fprintf(stderr,"    Next header type: %d\n", ipptr->ip6_nxt);
}


/*Print the ipv6 addr in a readable form*/
void ipv6_ntoa(char* buffer,struct in6_addr addr)
{
	sprintf (buffer, "%x:%x:%x:%x:%x:%x:%x:%x", 
		((addr).s6_addr[0] << 8) | (addr).s6_addr[1], 
		((addr).s6_addr[2] << 8) | (addr).s6_addr[3], 
		((addr).s6_addr[4] << 8) | (addr).s6_addr[5], 
		((addr).s6_addr[6] << 8) | (addr).s6_addr[7], 
		((addr).s6_addr[8] << 8) | (addr).s6_addr[9], 
		((addr).s6_addr[10] << 8) | (addr).s6_addr[11], 
		((addr).s6_addr[12] << 8) | (addr).s6_addr[13], 
		((addr).s6_addr[14] << 8) | (addr).s6_addr[15]);
}


/*Print the ipv6 prefix in a readable form*/
void ipv6pre_ntoa(char* buffer,struct in6_addr addr)
{
	sprintf (buffer, "%x:%x:%x:%x", 
		((addr).s6_addr[0] << 8) | (addr).s6_addr[1], 
		((addr).s6_addr[2] << 8) | (addr).s6_addr[3], 
		((addr).s6_addr[4] << 8) | (addr).s6_addr[5], 
		((addr).s6_addr[6] << 8) | (addr).s6_addr[7]);
}


/*Print information of the Neighbor Discovery message*/
void print_ra(struct nd_router_advert raptr)
{
	fprintf(stderr,"Router Advertisement: \n");
	fprintf(stderr,"    Router Lifetime: %d \n", ntohs(raptr.nd_ra_hdr.icmp6_data16[1]));
	fprintf(stderr,"    Reachable Time: %d\n",  raptr.nd_ra_reachable);
	fprintf(stderr,"    Restransmission timer: %d\n",  raptr.nd_ra_retransmit);
}

void print_rs(struct nd_router_solicit rsptr)
{
	fprintf(stderr,"Router Solicitation \n");
}

void print_na(struct nd_neighbor_advert naptr)
{
	char buffer[IP6_STR_SIZE];
	fprintf(stderr,"Neighbor Advertisement: \n");
	ipv6_ntoa(buffer, naptr.nd_na_target);
	fprintf(stderr,"    Target Address: %s \n", buffer);
}

void print_ns(struct nd_neighbor_solicit nsptr)
{
	char buffer[IP6_STR_SIZE];
	fprintf(stderr,"Neighbor Solicitation: \n");
	ipv6_ntoa(buffer, nsptr.nd_ns_target);
	fprintf(stderr,"    Target Address: %s \n", buffer);
}

void print_rd(struct nd_redirect rdptr)
{
	char buffer[IP6_STR_SIZE];
	fprintf(stderr,"Redirect Message: \n");
	ipv6_ntoa(buffer, rdptr.nd_rd_target);
	fprintf(stderr,"    Target Address: %s \n", buffer);
	ipv6_ntoa(buffer, rdptr.nd_rd_dst);
	fprintf(stderr,"    Destination Address: %s \n", buffer);
}

void print_option_list(const struct nd_option_list* option_list) 
{
	while (option_list!=NULL) 
	{
		struct nd_opt_rdnss *option_rdnss = NULL;
		int nb_ns = -1;
		struct in6_addr *addr = NULL;
		uint8_t *pos = (uint8_t *)option_list;

		switch (option_list->nd_option_type) 
		{
			case ND_OPT_SOURCE_LINKADDR:
				fprintf(stderr, "    Option Source Link Layer: %s\n", ether_ntoa( &(option_list->option_data.linklayer.ethernet_address) ) );
				break;

			case ND_OPT_TARGET_LINKADDR:
				fprintf(stderr, "    Option Target Link Layer: %s\n", ether_ntoa(&(option_list->option_data.linklayer.ethernet_address)));
				break;

			case ND_OPT_RDNSS:
				option_rdnss = (struct nd_opt_rdnss *) option_list;
				nb_ns = (option_rdnss->nd_opt_rdnss_len -1)/2;
				fprintf(stderr, "    Option RDNSS with %d NS\n", nb_ns);
				/* first member in the structure is a pointer to the enxt one in the list
				 * need to add the according offset
				 **/
				addr = (struct in6_addr *) (pos + sizeof(struct nd_opt_rdnss *) + 8);
				while(nb_ns > 0)
				{
					char  ns_addr_str[IP6_STR_SIZE];
					ipv6_ntoa(ns_addr_str, *addr);
					fprintf(stderr, "      ---> NS %s\n", ns_addr_str);
					addr++;
					nb_ns--;
				}

				break;
		}
		option_list = option_list->next;
	}
}


void print_opt(const struct nd_opt_hdr* const optptr)
{
	fprintf(stderr,"    Option type: %d\n", optptr->nd_opt_type);
	fprintf(stderr,"    Option length: %d\n", optptr->nd_opt_len);
}


