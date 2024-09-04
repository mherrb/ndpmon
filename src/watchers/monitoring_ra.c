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

#include "monitoring_ra.h"
#include "monitoring.h"

int watch_ra(struct capture_info* const capture_info) 
{
	int ret = 0;
	struct ether_addr *src_eth;
	char  eth[ETH_ADDRSTRLEN], ip_address[IP6_STR_SIZE];
	char * buffer                            = capture_info->message;
	const struct nd_option_list* option_list = capture_info->option_list;
	router_list_t** routers;
	router_list_t* router;
	struct probe* locked_probe;

	src_eth = (struct ether_addr *) capture_info->ethernet_header->ether_shost;
	ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
	strncpy(eth,ether_ntoa(src_eth), ETH_ADDRSTRLEN);

	/* whole function is critical section: */
	locked_probe = probe_lock(capture_info->probe->name);
	routers = &locked_probe->routers;
	router = router_get(*routers, capture_info->ip6_header->ip6_src, *src_eth);

	/* Learning phase, just populate the routers list */
	if(learning) 
	{
		struct nd_opt_prefix_info* option_prefix = NULL;
		struct nd_opt_mtu* option_mtu = NULL;
		char prefix[INET6_ADDRSTRLEN];
		struct nd_opt_rdnss *option_rdnss = NULL;
		struct nd_opt_dnssl *option_dnssl = NULL;
		struct nd_opt_route_info* option_route = NULL;
		int nb = -1;
		uint32_t lifetime =  0;
		uint32_t nd_opt_len = 0;
		uint8_t * pos = 0;
		struct in6_addr *addr =  NULL;
		char *search = NULL;
		uint8_t route_pref_reserved = 0, route_prefix_len = 0;

		prefix_t* router_prefix=NULL;
		rdnss_t *rdnss = NULL;
		rdnss_t *tmp_rdnss = NULL;
		dnssl_t *dnssl = NULL;
		dnssl_t *tmp_dnssl = NULL;

		route_info_t *routes = NULL;
		route_info_t *tmp_routes = NULL;

		/* Retrieve the Router Advertisement to get the RA params. */
		struct nd_router_advert *router_advert = (struct nd_router_advert*) (capture_info->icmp6_header);

		/* We have to search the prefix and mtu option among the others RA options: */
		while (option_list!=NULL) 
		{
			struct nd_opt_hdr* optptr = (struct nd_opt_hdr*) &option_list->option_data;
			switch (option_list->option_data.option_header.nd_opt_type) 
			{
				case ND_OPT_PREFIX_INFORMATION:
					option_prefix = (struct nd_opt_prefix_info*) optptr;
					ipv6pre_ntoa(prefix, option_prefix->nd_opt_pi_prefix);
					break;

				case ND_OPT_MTU:
					option_mtu = (struct nd_opt_mtu*) optptr;
					break;

				case ND_OPT_RDNSS: /* RFC6106 RDNSS option */
					option_rdnss = (struct nd_opt_rdnss *) optptr;
					nb = (option_rdnss->nd_opt_rdnss_len -1)/2;
					lifetime =  ntohl(option_rdnss->nd_opt_rdnss_lifetime);
					pos = (uint8_t *)optptr;

					/* Look for all addresses declared */
					for (addr = (struct in6_addr *) (pos+8); nb > 0; addr++, nb--)
					{
						/* add new entry in list */
						rdnss_t *new;
						if( (new = (rdnss_t *)malloc(sizeof(struct rdnss))) == NULL)
						{
							perror("malloc for new RDNSS");
							break;
						}

						new->lifetime = lifetime;
						memcpy( &new->address, addr, sizeof(struct in6_addr));
						new->next = NULL;

						tmp_rdnss = rdnss;
						if(tmp_rdnss == NULL)
							rdnss = new;
						else
						{
							while( tmp_rdnss->next != NULL )
								tmp_rdnss = tmp_rdnss->next;

							tmp_rdnss->next = new;
						}
					}
					break;

				case ND_OPT_DNSSL: /* RFC6106 DNSSL option */
					option_dnssl = (struct nd_opt_dnssl *) optptr;
					lifetime =  ntohl(option_dnssl->nd_opt_dnssl_lifetime);
					nd_opt_len = option_dnssl->nd_opt_dnssl_len;
					pos = (uint8_t *)optptr;

					/* Payload lenght in Bytes
					 * Length of domains to search
					 **/
					nd_opt_len = (nd_opt_len - 1) * 8;

					/* set pointer to domains at the first position */
					search = (char *)(pos + 8);
					while (nd_opt_len > 0)
					{
						char domain[MAX_DOMAINLEN];
						uint32_t domain_len = 0;
						int stop = 0;
						dnssl_t *new = NULL;

						/* look for a domain to search */
						while(*search != '\0')
						{
							/* Make sure we do not have a domain larger than the max size */
							if(domain_len>=MAX_DOMAINLEN)
							{
								/* Domain too long */
								stop = 1;
								break;
							}

							domain[domain_len] = *search;
							domain_len++;
							search++;
							nd_opt_len--;
						}

						/* Make sure we do not have a domain larger than the max size */
						if(domain_len>=MAX_DOMAINLEN)
							stop = 1;

						/* Domain name too long, stop with the option header */
						if(stop)
							break;

						/* inc one last time for \0 */
						domain[domain_len] = *search;
						domain_len++;
						search++;
						nd_opt_len--;

						/* do not treat padding */
						if( !strncmp(domain, "", 1) )
							continue;

						/* Add new search domain */
						if( (new = (dnssl_t *)malloc(sizeof(struct dnssl))) == NULL)
						{
							perror("malloc for new DNSSL");
							break;
						}
						new->lifetime = lifetime;
						strncpy( new->domain, domain, MAX_DOMAINLEN);
						new->next = NULL;

						tmp_dnssl = dnssl;
						if(tmp_dnssl == NULL)
							dnssl = new;
						else
						{
							while( tmp_dnssl->next != NULL )
								tmp_dnssl = tmp_dnssl->next;

							tmp_dnssl->next = new;
						}
					}
					break;

				case ND_OPT_ROUTE_INFORMATION: /* RFC4191 Route Information */
					option_route = (struct nd_opt_route_info*) optptr;
					route_pref_reserved   = option_route->nd_opt_ri_pref_reserved;
					lifetime              = ntohl(option_route->nd_opt_ri_lifetime);
					route_prefix_len      = option_route->nd_opt_ri_prefix_len;
					/* option_route->nd_opt_ri_prefix) */

					if(route_pref_reserved != 16)	/* should not be ignored */
					{
						route_info_t *new;
						if( (new = (route_info_t *)malloc(sizeof(struct route_info))) == NULL)
						{
							perror("malloc for new Route Info");
							break;
						}
						
						memcpy( &new->prefix, &option_route->nd_opt_ri_prefix, sizeof(struct in6_addr));
						new->mask = route_prefix_len;
						new->lifetime = lifetime;
						new->param_pref_reserved = route_pref_reserved;
						new->next = NULL;

						tmp_routes = routes;
						if(tmp_routes == NULL)
							routes = new;
						else
						{
							while( tmp_routes->next != NULL )
								tmp_routes = tmp_routes->next;

							tmp_routes->next = new;
						}
					}

					break;

				default:
					break;
			}
			/* If all supported options were found skip remaining options: 
			 * Do not stop if option rdnss, dnssl or route info are not NULL
			 * as we can have several ones
			 **/
			if (option_prefix!=NULL && option_mtu!=NULL) 
			{
				break;
			}
			/* Next option field*/
			option_list = option_list->next;
		}

		if (!option_prefix) 
		{
			/*if there is no prefix information:*/
			probe_unlock(capture_info->probe->name);
			return 0;
		}

		if(router==NULL) /* router not seen before */
		{
			router_add(
					routers, src_eth, &capture_info->ip6_header->ip6_src,
					router_advert->nd_ra_curhoplimit,
					router_advert->nd_ra_flags_reserved,
					ntohs(router_advert->nd_ra_router_lifetime),
					ntohl(router_advert->nd_ra_reachable),
					ntohl(router_advert->nd_ra_retransmit),
					option_mtu==NULL?0:ntohl(option_mtu->nd_opt_mtu_mtu),
					1 /* params are by default volatile (they may change).  */
				  );
			router_add_prefix(
					*routers, capture_info->ip6_header->ip6_src, *src_eth,
					option_prefix->nd_opt_pi_prefix,
					option_prefix->nd_opt_pi_prefix_len,
					option_prefix->nd_opt_pi_flags_reserved,
					ntohl(option_prefix->nd_opt_pi_valid_time),
					ntohl(option_prefix->nd_opt_pi_preferred_time)
					);

			/* Add RDNSS info */
			tmp_rdnss = rdnss;
			while(tmp_rdnss != NULL)
			{
				router_add_nameserver(*routers, *src_eth, tmp_rdnss->address, tmp_rdnss->lifetime);
				tmp_rdnss = tmp_rdnss->next;
			}

			/* Add DNSSL info */
			tmp_dnssl = dnssl;
			while(tmp_dnssl != NULL)
			{
				router_add_domain(*routers, *src_eth, tmp_dnssl->domain, tmp_dnssl->lifetime);
				tmp_dnssl = tmp_dnssl->next;
			}

			/* Add Route Info */
			tmp_routes = routes;
			while(tmp_routes != NULL)
			{
				router_add_route(*routers, capture_info->ip6_header->ip6_src, *src_eth, tmp_routes->prefix, tmp_routes->mask, tmp_routes->param_pref_reserved, tmp_routes->lifetime);
				tmp_routes = tmp_routes->next;
			}

		}
		else /* router already learned */
		{
			/* Update router values: */
			router->param_curhoplimit     = router_advert->nd_ra_curhoplimit;
			router->param_flags_reserved  = router_advert->nd_ra_flags_reserved;
			router->param_router_lifetime = ntohs(router_advert->nd_ra_router_lifetime);
			router->param_reachable_timer = ntohl(router_advert->nd_ra_reachable);
			router->param_retrans_timer   = ntohl(router_advert->nd_ra_retransmit);

			if (option_mtu!=NULL) 
			{
				router->param_mtu = ntohl(option_mtu->nd_opt_mtu_mtu);
			}

			router_prefix = router_get_prefix(*routers, capture_info->ip6_header->ip6_src, *src_eth, option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len);
			if( router_prefix == NULL ) 
			{
				/* If there is a new prefix advertised add it to the list of prefixes.*/
				router_add_prefix(
						*routers, capture_info->ip6_header->ip6_src, *src_eth,
						option_prefix->nd_opt_pi_prefix,
						option_prefix->nd_opt_pi_prefix_len,
						option_prefix->nd_opt_pi_flags_reserved,
						ntohl(option_prefix->nd_opt_pi_valid_time),
						ntohl(option_prefix->nd_opt_pi_preferred_time)
						);
			} 
			else 
			{
				/* If the prefix is already in the list update values: */
				router_prefix->param_valid_time     = ntohl(option_prefix->nd_opt_pi_valid_time);
				router_prefix->param_preferred_time = ntohl(option_prefix->nd_opt_pi_preferred_time);
			}

			/* Add RDNSS info */
			tmp_rdnss = rdnss;
			while(tmp_rdnss != NULL)
			{
				router_add_nameserver(*routers, *src_eth, tmp_rdnss->address, tmp_rdnss->lifetime);
				tmp_rdnss = tmp_rdnss->next;
			}

			/* Add DNSSL info */
			tmp_dnssl = dnssl;
			while(tmp_dnssl != NULL)
			{
				router_add_domain(*routers, *src_eth, tmp_dnssl->domain, tmp_dnssl->lifetime);
				tmp_dnssl = tmp_dnssl->next;
			}

			/* Add Route Info */
			tmp_routes = routes;
			while(tmp_routes != NULL)
			{
				router_add_route(*routers, capture_info->ip6_header->ip6_src, *src_eth, tmp_routes->prefix, tmp_routes->mask, tmp_routes->param_pref_reserved, tmp_routes->lifetime);
				tmp_routes = tmp_routes->next;
			}
		}
		probe_unlock(capture_info->probe->name);
print_routers(*routers);
		return 0;
	}

	/* if the router is not known */
	if(router==NULL)
	{
		int found_mac = is_router_mac_in(*routers, *src_eth);
		int found_lla = is_router_lla_in(*routers, capture_info->ip6_header->ip6_src);

		if( found_mac && found_lla)
		{
			/* valid MAC and IP, but not together */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong couple IP/MAC %s %s in RA", (char*)ether_ntoa(src_eth), ip_address);
			alert_raise(2, capture_info->probe, "wrong couple IP/MAC", buffer, src_eth, NULL, &capture_info->ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else if( found_mac && !found_lla)
		{
			/* wrong IP */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong router ip %s %s", (char*)ether_ntoa(src_eth), ip_address);
			alert_raise(2, capture_info->probe, "wrong router ip", buffer, src_eth, NULL, &capture_info->ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else if( !found_mac && found_lla)
		{
			/* wrong MAC */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong router mac %s %s", (char*)ether_ntoa(src_eth), ip_address);
			alert_raise(2, capture_info->probe, "wrong router mac", buffer, src_eth, NULL, &capture_info->ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else
		{
			/* wrong ipv6 router: both mac and lla are fantasist */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong ipv6 router %s %s", (char*)ether_ntoa(src_eth), ip_address);
			alert_raise(2, capture_info->probe, "wrong ipv6 router", buffer, src_eth, NULL, &capture_info->ip6_header->ip6_src, NULL);
			ret = 2;
		}

#ifdef _COUNTERMEASURES_
		/* We only propagate a counter measure if the probe is  a local one */
		if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
		{
			/* we need to pass the interface on which 
			 * the countermeasure must be propagated as a parameter 
			 * i.e. the probe name */
			cm_kill_illegitimate_router(src_eth, &capture_info->ip6_header->ip6_src, locked_probe->name);
		}
#endif
	}
	/* The router is valid, check options */
	else
	{
		const struct ether_header* ethernet_header = capture_info->ethernet_header;
		struct nd_router_advert *ra = (struct nd_router_advert *) capture_info->icmp6_header;
		unsigned int managed_flag, other_flag;
		char prefix[INET6_ADDRSTRLEN];
		/* ADDED param spoofing detection */
		uint8_t curhoplimit, flags_reserved;
		uint16_t router_lifetime;
		uint32_t reachable_timer, retrans_timer;
		char param_mismatched_list[RA_PARAM_MISMATCHED_LIST_SIZE], param_mismatched[RA_PARAM_MISMATCHED_SIZE];
		int param_mismatch = 0;
		int dns_option_error = 0;
		/* END ADDED */
#ifdef _COUNTERMEASURES_
		int param_spoofing_detected = 0;
		int route_option_error = 0;
#endif
		/* Check RA parameters */
		managed_flag = (ra->nd_ra_flags_reserved)&ND_RA_FLAG_MANAGED;
		other_flag = (ra->nd_ra_flags_reserved)&ND_RA_FLAG_OTHER;

		/* expecting 
		 * M ==1 and O == 1
		 * M == 0 and O == 1
		 * M == 0 and 0 == 0
		 * if M == 1 and O == 0 there is a problem
		 * */
		if( managed_flag && !other_flag)
		{
			char ip_address[IP6_STR_SIZE];
			ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA flags: M=1 and O=0");
			alert_raise(2, capture_info->probe, "wrong RA flags", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
			ret = 2;
		}

		/* ADDED : param spoofing detection */
		/* Only perform checks if params are configured not to change: */
		if (router->params_volatile==0) 
		{
			/* fetch RA params from RA */
			curhoplimit     = ra->nd_ra_curhoplimit;
			flags_reserved  = ra->nd_ra_flags_reserved;
			router_lifetime = ntohs(ra->nd_ra_router_lifetime);
			reachable_timer = ntohl(ra->nd_ra_reachable);
			retrans_timer   = ntohl(ra->nd_ra_retransmit);
		
			/* compare params to those stored in the router list
			 * optional parameters are only checked if neither the learned nor the advertised value
			 * is zero, because zero means unspecified. flags are always checked.
			 * WRONG: 0 means unspecified, we MUST verify that it is 0
			   */
			memset(param_mismatched_list, 0, RA_PARAM_MISMATCHED_LIST_SIZE);
			/* if (curhoplimit!=0 && router->param_curhoplimit!=0 && curhoplimit != router->param_curhoplimit) */
			if (curhoplimit != router->param_curhoplimit) 
			{
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "curhoplimit=%u;", curhoplimit);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}

			if (flags_reserved != router->param_flags_reserved)
			{
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "flags=%u;", flags_reserved);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}

			/* if (router_lifetime!=0 && router->param_router_lifetime!=0 && router_lifetime != router->param_router_lifetime) */
			if (router_lifetime != router->param_router_lifetime) 
			{
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "router_lifetime=%u;", router_lifetime);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}

			/* if (reachable_timer!=0 && router->param_reachable_timer!=0 && reachable_timer != router->param_reachable_timer) */
			if (reachable_timer != router->param_reachable_timer) 
			{
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "reachable_timer=%u;", reachable_timer);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}

			/* if (retrans_timer!=0 && router->param_retrans_timer!=0 && retrans_timer != router->param_retrans_timer) */
			if (retrans_timer != router->param_retrans_timer) 
			{
				memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
				snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "retrans_timer=%u;", retrans_timer);
				strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
				param_mismatch++;
			}

			if (param_mismatch>0) 
			{ /* we might tune the level of reaction here */
				snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA params: %s", param_mismatched_list);
				alert_raise(2, capture_info->probe, "wrong RA params", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
				param_spoofing_detected = 1;
#endif
			}
		}
		/* END ADDED */



		/******************************
		 * Check RA options 
		 ******************************/
		/*We have to search the prefix and other options among the others RA options*/
		while(option_list!=NULL) 
		{
			struct nd_opt_hdr* optptr = (struct nd_opt_hdr* ) &option_list->option_data;
			if(optptr->nd_opt_type ==  ND_OPT_PREFIX_INFORMATION) 
			{
				struct nd_opt_prefix_info* option_prefix = (struct nd_opt_prefix_info*) optptr;
				uint8_t prefix_flags_reserved;
				uint32_t prefix_valid_time, prefix_preferred_time, prefix_reserved2;
				/* ADDED param spoofing detection: */
				prefix_t* router_prefix=NULL;
				/* END ADDED */

				prefix_flags_reserved = option_prefix->nd_opt_pi_flags_reserved;
				prefix_reserved2      = ntohl(option_prefix->nd_opt_pi_reserved2);
				prefix_valid_time     = ntohl(option_prefix->nd_opt_pi_valid_time);
				prefix_preferred_time = ntohl(option_prefix->nd_opt_pi_preferred_time);
				ipv6pre_ntoa(prefix, option_prefix->nd_opt_pi_prefix);
				
				/* Check prefix */
				router_prefix = router_get_prefix(*routers, capture_info->ip6_header->ip6_src, *src_eth, option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len);
				if (router_prefix==NULL) /* prefix not found*/
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong prefix %s %s %s", prefix,(char*)ether_ntoa((struct ether_addr*) (ethernet_header->ether_shost)), ip_address);
					alert_raise(2, capture_info->probe, "wrong prefix", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					ret = 2;
#ifdef _COUNTERMEASURES_
					/* We only propagate a counter measure if the probe is  a local one */
					if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
					{
						/* we need to pass the interface on which 
						 * the countermeasure must be propagated as a parameter 
						 * i.e. the probe name */
						cm_kill_wrong_prefix(router, &capture_info->ip6_header->ip6_src, &option_prefix->nd_opt_pi_prefix, option_prefix->nd_opt_pi_prefix_len, locked_probe->name);
					}
#endif
				}
				
				/* check the lifetimes  - RFC2462 */
				/* valid should always be > to preferred - RFC2462 */
				if (prefix_preferred_time > prefix_valid_time)
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "RA preferred lifetime %d longer than valid lifetime %d",prefix_valid_time, prefix_preferred_time );
					alert_raise(2, capture_info->probe, "wrong RA prefix option lifetimes", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					ret = 2;
				}
				
				/* valid lifetime should always be more than 2 hours - RFC2462 */
				if (prefix_valid_time < 7200)
				{
					char ip_address[IP6_STR_SIZE];
					ipv6_ntoa(ip_address, capture_info->ip6_header->ip6_src);
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "RA prefix option valid lifetime %d < 2 hours", prefix_valid_time );
					alert_raise(2, capture_info->probe, "RA prefix option valid lifetime too short", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					ret = 2;
				}
				
				/* param spoofing detection in prefix option */
				if (router_prefix != NULL && router->params_volatile==0) 
				{
					/* reset previous flag value */
					param_mismatch = 0;

					/* Checking value against those learned. prefix params cannot be zero. all are checked. */
					memset(param_mismatched_list, 0, RA_PARAM_MISMATCHED_LIST_SIZE);

					if (prefix_flags_reserved != router_prefix->param_flags_reserved) 
					{
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "flags=%u;", prefix_flags_reserved);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (prefix_reserved2 != 0) 
					{
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf(param_mismatched, RA_PARAM_MISMATCHED_SIZE, "reserved2=%u;", prefix_reserved2);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (prefix_valid_time != router_prefix->param_valid_time) 
					{
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "valid_time=%u;", prefix_valid_time);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (prefix_preferred_time != router_prefix->param_preferred_time) 
					{
						memset(param_mismatched, 0, RA_PARAM_MISMATCHED_SIZE);
						snprintf (param_mismatched, RA_PARAM_MISMATCHED_SIZE, "preferred_time=%u;", prefix_preferred_time);
						strncat(param_mismatched_list,param_mismatched,RA_PARAM_MISMATCHED_SIZE);
						param_mismatch++;
					}
					if (param_mismatch>0) 
					{
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA prefix option params: %s", param_mismatched_list);
						alert_raise(2, capture_info->probe, "wrong RA prefix option params", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
						param_spoofing_detected = 1;
#endif
					}	
				}
				/* END ADDED */
			}
			
			/* Verify that the Source Link Option matches the Ethernet source addr of the packet
			   REMOVED this because this is already done by watch_eth_mismatch.
			   */
#if 0
			else if(optptr->nd_opt_type ==  ND_OPT_SOURCE_LINKADDR)
			{
				uint8_t *mac;
				mac = (uint8_t *)(pos+2);

				if( (mac[0]!=ethernet_header->ether_shost[0]) || (mac[1]!=ethernet_header->ether_shost[1]) || (mac[2]!=ethernet_header->ether_shost[2]) || (mac[3]!=ethernet_header->ether_shost[3]) || (mac[4]!=ethernet_header->ether_shost[4]) || (mac[5]!=ethernet_header->ether_shost[5]) )
				{
					char  eth_opt[ETH_ADDRSTRLEN];
					struct ether_addr * adv_eth = NULL;

					adv_eth = (struct ether_addr *) mac;
					strncpy(eth_opt,ether_ntoa(adv_eth), ETH_ADDRSTRLEN);
					snprintf (buffer, NOTIFY_BUFFER_SIZE-1, "source link address %s different from ethernet source %s", eth_opt, eth );
					alert_raise(2, "wrong source link address option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					ret = 2;
				}
			}
#endif
			
			/* Checking MTU option against the value learned. 
			 * A value learned = 0 means option not learned, thus unspecified
			 * if a value is set here and is different from the expected, raise an alert
			 * this implies that if the option is set when not expected an alert is raised
			 **/
			else if(optptr->nd_opt_type ==  ND_OPT_MTU) 
			{
				uint32_t mtu;
				struct nd_opt_mtu *option_mtu = (struct nd_opt_mtu*) optptr;
				mtu = ntohl(option_mtu->nd_opt_mtu_mtu);
				
				/* if (router != NULL && router->params_volatile==0 && router->param_mtu!=0 && mtu != router->param_mtu) */
				if (router != NULL && router->params_volatile==0)
					/* Alert if Adv MTU != learned MTU 
					 * of if none expected (router->param_mtu == 0) and Adv MTU == zero 
					 **/
					if( (mtu != router->param_mtu) || (mtu == 0) )
					{
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA mtu option: mtu=%u", mtu);
						alert_raise(2, capture_info->probe, "wrong RA mtu option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
						param_spoofing_detected=1;
#endif
					}
				/* END ADDED*/				
			}


			/* RFC6106 RDNSS option */
			else if(optptr->nd_opt_type == ND_OPT_RDNSS)
			{
				/* Cast the option to the right header */
				struct nd_opt_rdnss *option_rdnss = (struct nd_opt_rdnss *) optptr;
				/* number of Ns advertised */
				int nb_ns = (option_rdnss->nd_opt_rdnss_len -1)/2;
				/* lifetime of these NS */
				uint32_t lifetime =  ntohl(option_rdnss->nd_opt_rdnss_lifetime);
				/* pointer to the first Ns addr */
				uint8_t * pos = (uint8_t *)optptr;
				 /* struct in6_addr *addr = (struct in6_addr *) (pos + 8); */
				struct in6_addr *addr =  NULL;

#if 0
fprintf(stderr, "Recursive DNS nameServer option with %d NS and lifetime %u!!!\n", nb_ns, lifetime );
#endif
				if(nb_ns<=0)
				{
					/* option set but no nameserver is given */
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA RDNSS option: empty nameservers list");
					alert_raise(2, capture_info->probe, "wrong RA RDNSS option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					dns_option_error = 1;
					ret = 2;
				}
				for (addr = (struct in6_addr *) (pos+8); nb_ns > 0; addr++, nb_ns --)
				{
					/* check that the router has the couple lifetime / NS in his nameservers list */
					if( !router_has_nameserver(*routers, *src_eth, *addr, lifetime) )
					{
						char  ns_addr_str[IP6_STR_SIZE];
						ipv6_ntoa(ns_addr_str, *addr);
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA RDNSS option: %s %u", ns_addr_str, lifetime);
						alert_raise(2, capture_info->probe, "wrong RA RDNSS option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);

#ifdef _COUNTERMEASURES_
						/* We only propagate a counter measure if the probe is  a local one */
						if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
						{
							cm_kill_wrong_nameserver(router, &capture_info->ip6_header->ip6_src, addr, locked_probe->name);
						}
#endif

						dns_option_error = 1;
						ret = 2;
					}
				}

			}

			/* RFC6106 DNSSL option */
			else if(optptr->nd_opt_type == ND_OPT_DNSSL)
			{
				/* Cast the option to the right header */
				struct nd_opt_dnssl *option_dnssl = (struct nd_opt_dnssl *) optptr;
				/* lifetime of these NS */
				uint32_t lifetime =  ntohl(option_dnssl->nd_opt_dnssl_lifetime);
				/* Length of the option in word of 8 Bytes */
				uint32_t nd_opt_len = option_dnssl->nd_opt_dnssl_len;
				/* Position in the domains list */
				char *search = NULL;
				/* pointer within the option */
				uint8_t * pos = (uint8_t *)optptr;

				/* Payload lenght in Bytes
				 * Length of domains to search
				 **/
				nd_opt_len = (nd_opt_len - 1) * 8;

#if 0
fprintf(stderr, "DNS Search List option with lifetime %u of length %u !!!\n", lifetime, nd_opt_len );
#endif

				/* set pointer to domains at the first position */
				search = (char *)(pos + 8);
				while (nd_opt_len > 0)
				{
					char domain[MAX_DOMAINLEN];
					uint32_t domain_len = 0;
					int stop = 0;

					/* look for a domain to search */
					while(*search != '\0')
					{
						/* Make sure we do not have a domain larger than the max size */
						if(domain_len>=MAX_DOMAINLEN)
						{
							/* Domain too long */
							snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA DNSSL option: search domain too long");
							alert_raise(2, capture_info->probe, "wrong RA DNSSL option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
							dns_option_error = 1;
							ret = 2;
							stop = 1;
						}


						domain[domain_len] = *search;
						domain_len++;
						search++;
						nd_opt_len--;
					}

					/* Make sure we do not have a domain larger than the max size */
					if(domain_len>=MAX_DOMAINLEN)
					{
						/* Domain too long */
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA DNSSL option: search domain too long");
						alert_raise(2, capture_info->probe, "wrong RA DNSSL option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);

						dns_option_error = 1;
						ret = 2;
						stop = 1;
					}

					/* Domain name too long, stop with the option header */
					if(stop)
						break;

					/* inc one last time for \0 */
					domain[domain_len] = *search;
					domain_len++;
					search++;
					nd_opt_len--;

					/* do not treat padding */
					if( !strncmp(domain, "", 1) )
						continue;


#if 0
fprintf(stderr, "    ---> Search domain %s\n", domain);
#endif
					/* check that the router has the couple lifetime / domain in his search list */
					if( !router_has_domain(*routers, *src_eth, domain, lifetime) )
					{
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA DNSSL option: %s %u", domain, lifetime);
						alert_raise(2, capture_info->probe, "wrong RA DNSSL option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);

#ifdef _COUNTERMEASURES_
					/* We only propagate a counter measure if the probe is  a local one */
					if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
					{
						cm_kill_wrong_domain(router, &capture_info->ip6_header->ip6_src, domain, locked_probe->name);
					}
#endif

						dns_option_error = 1;
						ret = 2;
					}

				}

			}

			/* RFC4191 Route Information */
			else if(optptr->nd_opt_type ==  ND_OPT_ROUTE_INFORMATION) 
			{
				struct nd_opt_route_info* option_route = (struct nd_opt_route_info*) optptr;
				uint8_t route_pref_reserved, route_prefix_len;
				uint32_t lifetime;
				route_info_t *rinfo = NULL;

				route_pref_reserved   = option_route->nd_opt_ri_pref_reserved;
				lifetime              = ntohl(option_route->nd_opt_ri_lifetime);
				route_prefix_len      = option_route->nd_opt_ri_prefix_len;
				ipv6pre_ntoa(prefix, option_route->nd_opt_ri_prefix);

				/* Is the preference OK ? */
				if(route_pref_reserved == ND_OPT_RI_PREF_IGNOR)
				{
					/* Should not happen */
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA Route Info option: route preference ignor");
					alert_raise(2, capture_info->probe, "wrong RA Route Info option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
					/* route_option_error = 1; */
#endif
					ret = 2;
				}

				/* does this route exist ? */
				if( (rinfo=router_get_route(*routers, capture_info->ip6_header->ip6_src, *src_eth, option_route->nd_opt_ri_prefix, route_prefix_len)) == NULL)
				{
					/* Wrong route */
					snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA Route Info option %s/%u", prefix, route_prefix_len);
					alert_raise(2, capture_info->probe, "wrong RA Route Info option", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
					ret = 2;

#ifdef _COUNTERMEASURES_
					route_option_error = 1;
					/* We only propagate a counter measure if the probe is  a local one */
					if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
					{
						cm_kill_wrong_route(router, &capture_info->ip6_header->ip6_src, &option_route->nd_opt_ri_prefix, route_prefix_len, route_pref_reserved, locked_probe->name);
					}
#endif

				}
				else
				{
					/* Lifetime and preference OK ? */
					if(lifetime != rinfo->lifetime)
					{
						/* Wrong route */
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA Route Info Lifetime %s/%u %u", prefix, route_prefix_len, lifetime);
						alert_raise(2, capture_info->probe, "wrong RA Route Info lifetime", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
						route_option_error = 1;
#endif
						ret = 2;
					}

					if(route_pref_reserved != rinfo->param_pref_reserved)
					{
						/* Wrong route */
						snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong RA Route Info preference %s/%u %u", prefix, route_prefix_len, route_pref_reserved);
						alert_raise(2, capture_info->probe, "wrong RA Route Info preference", buffer, (struct ether_addr*) (ethernet_header->ether_shost), NULL, &capture_info->ip6_header->ip6_src, NULL);
#ifdef _COUNTERMEASURES_
						route_option_error = 1;
#endif
						ret = 2;
					}
				}
				
				
			}


			/*Next option field*/
			option_list = option_list->next;
		} 
		/******************************
		 * end options
		 ******************************/

#ifdef _COUNTERMEASURES_
		/* We only propagate a counter measure if the probe is  a local one */
		if( (locked_probe->type == PROBE_TYPE_INTERFACE) && (locked_probe->cm_enabled == 1) )
		{
			/* we need to pass the interface on which 
			 * the countermeasure must be propagated as a parameter 
			 * i.e. the probe name */
			if (param_spoofing_detected!=0) 
			{
				/* Try to restore params in the network. */
				cm_propagate_router_params(router, &capture_info->ip6_header->ip6_src, locked_probe->name);
			}

			if(dns_option_error != 0)
			{
				/* Try to restore DNS params in the network. */
				cm_propagate_router_dns(router, &capture_info->ip6_header->ip6_src, locked_probe->name);
			}
			
			if(route_option_error != 0)
			{
				/* Try to restore route params in the network. */
				cm_propagate_router_routes(router, &capture_info->ip6_header->ip6_src, locked_probe->name);
			}

		}
#endif

	} /* end valid router*/

	probe_unlock(capture_info->probe->name);

	return ret;
}
