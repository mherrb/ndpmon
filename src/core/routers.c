#include "routers.h"

/* HELPERS */
int is_router_lla_in(router_list_t *list, struct in6_addr lla)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

int is_router_mac_in(router_list_t *list, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			return 1;

		tmp = tmp->next;
	}

	return 0;
}

router_list_t * router_get(router_list_t *list, struct in6_addr lla, struct ether_addr eth)
{
	router_list_t *tmp = list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
			if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
				return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

int router_has_router(router_list_t *list, struct in6_addr lla, struct ether_addr eth) 
{
	if (router_get(list, lla, eth)==NULL) 
	{
		/* Not found */
		return 0;
	}

	/* Found */
	return 1;
}

int router_add(router_list_t **list, const struct ether_addr* eth, const struct in6_addr* lla,
	uint8_t curhoplimit, uint8_t flags_reserved, uint16_t router_lifetime, uint32_t reachable_timer, uint32_t retrans_timer,
	uint32_t mtu, int p_volatile)
{
	router_list_t *tmp = *list,*new=NULL;

	if(router_has_router(*list,*lla,*eth))
	{
		fprintf(stderr,"Router already in list\n");
		return 0;
	}

	if( (new=(router_list_t *)malloc(sizeof(router_list_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	memcpy(&new->mac, eth, sizeof(struct ether_addr));
	memcpy(&new->lla, lla, sizeof(struct in6_addr));
	new->param_curhoplimit     = curhoplimit;
	new->param_flags_reserved  = flags_reserved;
	new->param_router_lifetime = router_lifetime;
	new->param_reachable_timer = reachable_timer;
	new->param_retrans_timer   = retrans_timer;
	new->param_mtu   = mtu;
	new->params_volatile = p_volatile;
	new->addresses = NULL;
	new->prefixes = NULL;
	new->nameservers = NULL;
	new->domains = NULL;
	new->routes = NULL;
	new->next = NULL;

	if(*list != NULL)
	{
		while(tmp->next != NULL)
			tmp=tmp->next;
		tmp->next=new;
	}
	else
		*list = new;

	return 1;
}
/* HELPERS */



/*PREFIXES */
int router_add_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, 
	uint8_t flags_reserved, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
	router_list_t *tmp = list;
	prefix_t *new, *ptmp = NULL;

	if( (new=(prefix_t *)malloc(sizeof(prefix_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->prefix               = prefix;
	new->mask                 = mask;
	new->param_flags_reserved = flags_reserved;
	new->param_valid_time     = valid_lifetime;
	new->param_preferred_time = preferred_lifetime;
	new->next=NULL;

	tmp = router_get(list,  lla, eth);
	if (tmp==NULL) return 0;

	ptmp = tmp->prefixes;
	if(ptmp == NULL) {
		tmp->prefixes = new;
	} else {
		while(ptmp->next != NULL) {
			ptmp=ptmp->next;
		}
		ptmp->next=new;
	}
	return 1;
}

prefix_t* router_get_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask)
{
	router_list_t* router = router_get(list, lla, eth);
	prefix_t *ptmp;

	if (router==NULL) {
		return NULL;
	}
	ptmp = router->prefixes;
	while(ptmp != NULL) {
		if( (ptmp->mask == mask) && (IN6_ARE_ADDR_EQUAL(&prefix,&(ptmp->prefix))) ) {
			return ptmp;
		}
		ptmp = ptmp->next;
	}
	return NULL;
}

int router_has_prefix(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask) 
{
        if (router_get_prefix(list, lla, eth, prefix, mask)==NULL) 
	{
		return 0;
	}
	return 1;
}
/*PREFIXES */



/* RFC6106 - RDNSS */
int router_add_nameserver(router_list_t *list, struct ether_addr eth, struct in6_addr addr, uint32_t lifetime)
{
	router_list_t *tmp = list;
	rdnss_t *new = NULL;

	/* Already in list ? */
	if( router_has_nameserver(list, eth, addr, lifetime) )
	{
		fprintf(stderr,"[router_add_nameserver] Nameserver already in list\n");
		return 0;
	}
	
	/* Add a new one */
	if( (new=(rdnss_t *)malloc(sizeof(rdnss_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}
	new->address = addr;
	new->lifetime = lifetime;
	new->next = NULL;

	/* find the router and append the nameserver */
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				rdnss_t *ntmp = tmp->nameservers;
				if(ntmp == NULL)
				{
					/* First element */
					tmp->nameservers = new;
				}
				else
				{
					/* Got to the end and append it */
					while(ntmp->next != NULL)
						ntmp = ntmp->next;
					ntmp->next = new;
				}
				return 1;
		}
		else
			tmp = tmp->next;
	}
	
	return 0;
}

int router_has_nameserver(router_list_t *list, struct ether_addr eth, struct in6_addr addr, uint32_t lifetime)
{
	router_list_t *tmp = list;
	/* Find the router */
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				rdnss_t *ntmp = tmp->nameservers;
				/* check in nameservers list if it is present or not */
				while(ntmp != NULL)
				{
					if( (IN6_ARE_ADDR_EQUAL(&addr,&(ntmp->address))) && (ntmp->lifetime == lifetime) )
						return 1;

					ntmp = ntmp->next;
				}
				return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}
/* RFC6106 - RDNSS */



/* RFC6106 - DNSSL */
int router_has_domain(router_list_t *list, struct ether_addr eth, const char *domain, uint32_t lifetime)
{
	router_list_t *tmp = list;
	/* Find the router */
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				dnssl_t *dtmp = tmp->domains;
				/* check in domains list if it is present or not */
				while(dtmp != NULL)
				{
					if( !STRNCMP(domain, dtmp->domain, MAX_DOMAINLEN) && (dtmp->lifetime == lifetime) )
						return 1;

					dtmp = dtmp->next;
				}
				return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}

int router_add_domain(router_list_t *list, struct ether_addr eth, const char *domain, uint32_t lifetime)
{
	router_list_t *tmp = list;
	dnssl_t *new = NULL;

	/* Already in list ? */
	if( router_has_domain(list, eth, domain, lifetime) )
	{
		fprintf(stderr,"[router_add_domain] Domain already in list\n");
		return 0;
	}
	
	/* Add a new one */
	if( (new=(dnssl_t *)malloc(sizeof(dnssl_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}
	
	strncpy(new->domain, domain, MAX_DOMAINLEN);
	new->lifetime = lifetime;
	new->next = NULL;

	/* find the router and append the domain */
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				dnssl_t *dtmp = tmp->domains;
				if(dtmp == NULL)
				{
					/* First element */
					tmp->domains = new;
				}
				else
				{
					/* Got to the end and append it */
					while(dtmp->next != NULL)
						dtmp = dtmp->next;
					dtmp->next = new;
				}
				return 1;
		}
		else
			tmp = tmp->next;
	}
	
	return 0;
}
/* RFC6106 - DNSSL */



/* RFC4191 - Route Info */
int router_add_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask, uint8_t pref_reserved, uint32_t lifetime)
{
	router_list_t *tmp = list;
	route_info_t *new_route, *rtmp = NULL;

	if( (new_route=(route_info_t *)malloc(sizeof(route_info_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new_route->prefix              = prefix;
	new_route->mask                = mask;
	new_route->param_pref_reserved = pref_reserved;
	new_route->lifetime            = lifetime;
	new_route->next=NULL;

	tmp = router_get(list,  lla, eth);
	if (tmp==NULL) 
		return 0;

	rtmp = tmp->routes;
	if(rtmp == NULL) 
	{
		tmp->routes = new_route;
	} 
	else 
	{
		while(rtmp->next != NULL) 
		{
			rtmp=rtmp->next;
		}
		rtmp->next=new_route;
	}

	return 1;
}

int router_has_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask)
{
	if (router_get_route(list, lla, eth, prefix, mask)==NULL) 
	{
		return 0;
	}

	return 1;
}

route_info_t* router_get_route(router_list_t *list, struct in6_addr lla, struct ether_addr eth, struct in6_addr prefix, int mask)
{
	router_list_t* router = router_get(list, lla, eth);
	route_info_t *rtmp;

	if (router==NULL) 
	{
		return NULL;
	}

	rtmp = router->routes;
	while(rtmp != NULL) 
	{
		if( (rtmp->mask == mask) && (IN6_ARE_ADDR_EQUAL(&prefix,&(rtmp->prefix))) ) 
		{
			return rtmp;
		}
		rtmp = rtmp->next;
	}

	return NULL;
}

/* RFC4191 - Route Info */



/* ADDRESSES */
int router_add_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr)
{
	router_list_t *tmp = list;
	address_t *new = NULL;

	
	if(router_has_address(list,eth,addr))
	{
		fprintf(stderr,"Address already in list\n");
		return 0;
	}
	

	if( (new=(address_t *)malloc(sizeof(address_t))) == NULL)
	{
		perror("malloc");
		return 0;
	}

	new->address = addr;
	new->next=NULL;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				address_t *atmp = tmp->addresses;
				if(atmp == NULL)
					tmp->addresses = new;
				else
				{
					while(atmp->next != NULL)
						atmp=atmp->next;
					atmp->next=new;
				}
				return 1;
		}
		else
			tmp = tmp->next;
	}
	
	return 0;
}

int router_has_address(router_list_t *list, struct ether_addr eth, struct in6_addr addr)
{
	router_list_t *tmp = list;
	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
				address_t *atmp = tmp->addresses;
				while(atmp != NULL)
				{
					if( IN6_ARE_ADDR_EQUAL(&addr,&(atmp->address)) )
						return 1;

					atmp = atmp->next;
				}
				return 0;
		}
		tmp = tmp->next;
	}
	return 0;
}
/* ADDRESSES */



/* UTILS */
int nb_router(router_list_t *routers)
{
	int n = 0;
	router_list_t *tmp = routers;

	while(tmp != NULL)
	{
		n++;
		tmp=tmp->next;
	}

	return n;
}

void router_copy(router_list_t* destination, router_list_t* source) 
{
	address_t* tmp_addresses = source->addresses;

	prefix_t* tmp_prefixes   = source->prefixes;
	prefix_t* current_prefix_end = NULL;		/* pointer to current copied list end */

	rdnss_t *tmp_nameservers = source->nameservers;
	rdnss_t *current_nameservers_end = NULL;	/* pointer to current copied list end */

	dnssl_t *tmp_domains = source->domains;
	dnssl_t *current_domains_end = NULL;		/* pointer to current copied list end */

	route_info_t *tmp_routes = source->routes;
	route_info_t *current_route_end = NULL;		/* pointer to current copied list end */

	memcpy(&destination->lla, &source->lla, sizeof(struct in6_addr));
	memcpy(&destination->mac, &source->mac, sizeof(struct ether_addr));

	/* copy params: */
	destination->param_curhoplimit = source->param_curhoplimit;
	destination->param_flags_reserved = source->param_flags_reserved;
	destination->param_mtu = source->param_mtu;
	destination->param_reachable_timer = source->param_reachable_timer;
	destination->param_retrans_timer = source->param_retrans_timer;
	destination->param_router_lifetime = source->param_router_lifetime;
	destination->params_volatile = source->params_volatile;
	destination->next = NULL;

	/* copy addresses: */
	destination->addresses = NULL;
	while (tmp_addresses!=NULL) 
	{
		addresses_add(&destination->addresses, &tmp_addresses->address, tmp_addresses->firstseen, tmp_addresses->lastseen);
		tmp_addresses = tmp_addresses->next;
	}

	/* copy prefixes: */
	destination->prefixes = NULL;
	while (tmp_prefixes!=NULL) 
	{
		prefix_t* prefix_cp;
		if ((prefix_cp=malloc(sizeof(prefix_t)))==NULL) 
		{
			perror("[routers] malloc failed.");
			exit(1);
		}
		prefix_cp->mask = tmp_prefixes->mask;
		prefix_cp->next = NULL;
		prefix_cp->param_flags_reserved = tmp_prefixes->param_flags_reserved;
		prefix_cp->param_preferred_time = tmp_prefixes->param_preferred_time;
		prefix_cp->param_valid_time     = tmp_prefixes->param_valid_time;
		memcpy(&prefix_cp->prefix, &tmp_prefixes->prefix, sizeof(struct in6_addr));
		if (current_prefix_end==NULL) 
		{
			current_prefix_end = prefix_cp;
			destination->prefixes = current_prefix_end;
		} 
		else 
		{
			current_prefix_end->next = prefix_cp;
			current_prefix_end = prefix_cp;
		}
		tmp_prefixes = tmp_prefixes->next;
	}

	/* copy RFC6106 RDNSS */
	destination->nameservers = NULL;
	while(tmp_nameservers != NULL) 
	{
		rdnss_t *nameserver_cp;
		if ((nameserver_cp=malloc(sizeof(rdnss_t))) == NULL) 
		{
			perror("[routers] malloc failed for nameserver_cp.");
			exit(1);
		}
		nameserver_cp->lifetime = tmp_nameservers->lifetime;
		nameserver_cp->next = NULL;

		memcpy(&nameserver_cp->address, &tmp_nameservers->address, sizeof(struct in6_addr));
		if (current_nameservers_end==NULL) 
		{
			/* empty list, add first element */
			current_nameservers_end = nameserver_cp;
			destination->nameservers = nameserver_cp;
		} 
		else 
		{
			/* Append to the list */
			current_nameservers_end->next = nameserver_cp;
			current_nameservers_end = nameserver_cp;
		}

		tmp_nameservers = tmp_nameservers->next;
	}


	/* copy RFC6106 DNSSL */
	destination->domains = NULL;
	while(tmp_domains != NULL) 
	{
		dnssl_t *domain_cp;
		if ((domain_cp=malloc(sizeof(dnssl_t))) == NULL) 
		{
			perror("[routers] malloc failed for domain_cp.");
			exit(1);
		}
		domain_cp->lifetime = tmp_domains->lifetime;
		domain_cp->next = NULL;

		strncpy(domain_cp->domain, tmp_domains->domain, MAX_DOMAINLEN);
		if (current_domains_end==NULL) 
		{
			/* empty list, add first element */
			current_domains_end = domain_cp;
			destination->domains = domain_cp;
		} 
		else 
		{
			/* Append to the list */
			current_domains_end->next = domain_cp;
			current_domains_end = domain_cp;
		}

		tmp_domains = tmp_domains->next;
	}


	/* copy RFC4191 Route Info: */
	destination->routes = NULL;
	while (tmp_routes!=NULL) 
	{
		route_info_t* route_cp;
		if ((route_cp=malloc(sizeof(route_info_t)))==NULL) 
		{
			perror("[routers] malloc failed for route_info_t.");
			exit(1);
		}

		route_cp->mask = tmp_routes->mask;
		route_cp->next = NULL;
		route_cp->param_pref_reserved = tmp_routes->param_pref_reserved;
		route_cp->lifetime = tmp_routes->lifetime;
		memcpy(&route_cp->prefix, &tmp_routes->prefix, sizeof(struct in6_addr));

		if (current_route_end==NULL) 
		{
			current_route_end = route_cp;
			destination->routes = current_route_end;
		} 
		else 
		{
			current_route_end->next = route_cp;
			current_route_end = route_cp;
		}

		tmp_routes = tmp_routes->next;
	}

}

void print_routers(router_list_t *list)
{
	router_list_t *tmp = list;
	while(tmp != NULL)
	{
		char eth[ETH_ADDRSTRLEN+1], lla[INET6_ADDRSTRLEN+1];
		prefix_t *ptmp = tmp->prefixes;
		address_t *atmp = tmp->addresses;
		rdnss_t *ntmp = tmp->nameservers;
		dnssl_t *dtmp = tmp->domains;
		route_info_t *rtmp = tmp->routes;

		ipv6_ntoa(lla,tmp->lla);
		strncpy(eth,ether_ntoa(&(tmp->mac)), ETH_ADDRSTRLEN);
		fprintf(stderr,"Router (%s,%s) :\n", eth, lla);
		fprintf(stderr,"    RA params:\n");
		fprintf(stderr,"        curhoplimit:     %u\n", tmp->param_curhoplimit);
		fprintf(stderr,"        flags:           [");
		if (tmp->param_flags_reserved&ND_RA_FLAG_MANAGED) {
			fprintf(stderr,"MANAGED ");
		}
		if (tmp->param_flags_reserved&ND_RA_FLAG_OTHER) {
			fprintf(stderr,"OTHER ");
		}
#ifndef _FREEBSD_
		if (tmp->param_flags_reserved&ND_RA_FLAG_HOME_AGENT) {
			fprintf(stderr,"HOME_AGENT ");
		}
#endif
		fprintf(stderr,"]\n");
		fprintf(stderr,"        router lifetime: %u\n", tmp->param_router_lifetime);
		fprintf(stderr,"        reachable timer: %u\n", tmp->param_reachable_timer);
		fprintf(stderr,"        retrans timer:   %u\n", tmp->param_retrans_timer);
		if (tmp->param_mtu>0) {
			fprintf(stderr,"        mtu:             %u\n", tmp->param_mtu);
		}
		if (tmp->params_volatile==0) {
			fprintf(stderr,"        Parameters of future Router Advertisements will be\n");
			fprintf(stderr,"        checked against those stored in the router list.\n");			
		}

		fprintf(stderr,"    Address(es):\n");
		while(atmp != NULL)
		{
			char addr[48];
			ipv6_ntoa(addr,atmp->address);
			fprintf(stderr,"        %s\n", addr);
			atmp=atmp->next;
		}

		fprintf(stderr,"    Prefix(es):\n");
		while(ptmp != NULL)
		{
			char prefix[64];
			ipv6_ntoa(prefix,ptmp->prefix);
			sprintf(prefix,"%s/%d", prefix,ptmp->mask);
			fprintf(stderr,"        %s\n", prefix);
			fprintf(stderr,"            flags:          [");
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_ONLINK) {
				fprintf(stderr,"ONLINK ");
			}
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_AUTO) {
				fprintf(stderr,"AUTO ");
			}
#ifndef _FREEBSD_
			if (ptmp->param_flags_reserved&ND_OPT_PI_FLAG_RADDR) {
				fprintf(stderr,"RADDR ");
			}
#endif
			fprintf(stderr,"]\n");
			fprintf(stderr,"            valid time:     %u\n", ptmp->param_valid_time);
			fprintf(stderr,"            preferred time: %u\n", ptmp->param_preferred_time);
			ptmp=ptmp->next;
		}

		fprintf(stderr,"    Nameserver(s):\n");
		while(ntmp != NULL)
		{
			char ns[INET6_ADDRSTRLEN];
			ipv6_ntoa(ns,ntmp->address);
			fprintf(stderr,"        NS %s - lifetime %us\n", ns, ntmp->lifetime);
			ntmp=ntmp->next;
		}

		fprintf(stderr,"    Search domain(s):\n");
		while(dtmp != NULL)
		{
			fprintf(stderr,"        Search %s - lifetime %us\n", dtmp->domain, dtmp->lifetime);
			dtmp=dtmp->next;
		}

		
		fprintf(stderr,"    Route(s):\n");
		while(rtmp != NULL)
		{
			char prefix[64];
			
			ipv6_ntoa(prefix,rtmp->prefix);
			sprintf(prefix,"%s/%d", prefix,rtmp->mask);
			fprintf(stderr,"        %s", prefix);

			fprintf(stderr,"  Pref: ");
			switch( (rtmp->param_pref_reserved & ND_OPT_RI_PREF_MASK) >> ND_OPT_RI_PREF_SHIFT )
			{
				case 1:
					fprintf(stderr,"HIGH");
					break;

				case 2:
					fprintf(stderr,"IGNOR");
					break;

				case 3:
					fprintf(stderr,"LOW");
					break;

				case 0:
				default:
					fprintf(stderr,"MEDIUM");
					break;
			}
			
			fprintf(stderr,"  Lifetime: %us\n", rtmp->lifetime);
			
			rtmp=rtmp->next;
		}


		fprintf(stderr,"\n");
		tmp=tmp->next;
	}
}
/* UTILS */



/*CLEAN */
int clean_router_prefixes(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			prefix_t *ptmp = tmp->prefixes, *ptodel = NULL;

			while( ptmp != NULL)
			{
				ptodel = ptmp;
				ptmp = ptmp->next;
				free(ptodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_router_routes(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			route_info_t *rtmp = tmp->routes, *rtodel = NULL;

			while( rtmp != NULL)
			{
				rtodel = rtmp;
				rtmp = rtmp->next;
				free(rtodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_router_rdnss(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			rdnss_t *ntmp = tmp->nameservers, *ntodel = NULL;

			while( ntmp != NULL)
			{
				ntodel = ntmp;
				ntmp = ntmp->next;
				free(ntodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_router_dnssl(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			dnssl_t *dtmp = tmp->domains, *dtodel = NULL;

			while( dtmp != NULL)
			{
				dtodel = dtmp;
				dtmp = dtmp->next;
				free(dtodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_router_addresses(router_list_t **list, struct ether_addr eth)
{
	router_list_t *tmp = *list;

	while(tmp != NULL)
	{
		if(!MEMCMP(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			address_t *atmp = tmp->addresses, *atodel = NULL;

			while( atmp != NULL)
			{
				atodel = atmp;
				atmp = atmp->next;
				free(atodel);
			}

			return 1;
		}

		tmp = tmp->next;
	}

	return 0;
}

int clean_routers(router_list_t **list)
{
	router_list_t *tmp = *list, *rtodel = NULL;

	while(tmp != NULL)
	{
		/* do not call  clean_router_* on the list passed as a parameter
		 * it causes a seg fault with more than one router
		 * as the list head is freed
		 * Call it on &tmp
		 **/
		rtodel = tmp;
		clean_router_addresses(&tmp,tmp->mac);
		clean_router_prefixes(&tmp,tmp->mac);
		clean_router_rdnss(&tmp,tmp->mac);
		clean_router_dnssl(&tmp,tmp->mac);
		clean_router_routes(&tmp,tmp->mac);
		tmp = tmp->next;
		free(rtodel);
	}

	return 1;
}
/*CLEAN */



/* CONFIG */
int router_list_parse (xmlNodePtr element, router_list_t** routers) 
{
	xmlNodePtr router = element->children;
	char *text;

	while(router != NULL) 
	{
		if (router->type == XML_ELEMENT_NODE && STRCMP(router->name,"router")==0) 
		{
			struct ether_addr mac;
			struct in6_addr lla;
			uint8_t  param_curhoplimit=0;
			uint8_t  param_flags_reserved=0;
			uint16_t param_router_lifetime=0;
			uint32_t param_reachable_timer=0;
			uint32_t param_retrans_timer=0;
			uint32_t param_mtu=0;
			int params_volatile=1;
			prefix_t* tmp_prefix = NULL;
			address_t* tmp_address = NULL;
			rdnss_t *tmp_nameservers = NULL;
			dnssl_t *tmp_domains = NULL;
			route_info_t *tmp_routes = NULL;
			xmlNode *param = router->children;

			while(param != NULL) 
			{
				/* XML Element ? */
				if (param->type != XML_ELEMENT_NODE) 
				{
					param = param->next;
					continue;
				}

				/* router MAC+ LLA */
				if( !STRCMP(param->name,"mac") ) 
				{
					memcpy(&mac,ether_aton((char *)XML_GET_CONTENT(param->children)),sizeof(struct ether_addr));
				}
				else if( !STRCMP(param->name,"lla") ) 
				{
					inet_pton(AF_INET6,(char *)XML_GET_CONTENT(param->children), &lla);
				}

				/* Generic parameters */
				else if( !STRCMP(param->name,"param_curhoplimit") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_curhoplimit = atoi(text!=NULL?text:"0");
				}
				else if( !STRCMP(param->name,"param_flags_reserved") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_flags_reserved = atoi(text!=NULL?text:"0");
				}
				else if( !STRCMP(param->name,"param_router_lifetime") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_router_lifetime = atoi(text!=NULL?text:"0");
				}
				else if( !STRCMP(param->name,"param_reachable_timer") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_reachable_timer = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"param_retrans_timer") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_retrans_timer = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"param_mtu") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					param_mtu = strtoul(text!=NULL?text:"0", NULL, 10);
				}
				else if( !STRCMP(param->name,"params_volatile") ) 
				{
					text = (char*)XML_GET_CONTENT(param->children);
					params_volatile = atoi(text!=NULL?text:"1");
				}

				/* IPv6 global addresses */
				else if( !STRCMP(param->name,"addresses") ) 
				{
					xmlNode *address = param->children;
					while(address != NULL) 
					{
						if (address->type == XML_ELEMENT_NODE &&  STRCMP(address->name,"address")==0 ) 
						{
							/* Read address: */
							address_t* new_address = malloc(sizeof(address_t));
							if (new_address==NULL) 
							{
								fprintf(stderr, "malloc failed.");
							}
							inet_pton(AF_INET6,(char *)XML_GET_CONTENT(address->children), &new_address->address);
							/* Add address to tmp address list: */
							new_address->next = tmp_address;
							tmp_address = new_address;
						}
						/* Fetch next address node: */
						address = address->next;
					}
				} /* end addresses */

				/* Adv Prefixes */
				else if( !STRCMP(param->name,"prefixes") ) 
				{
					xmlNode *prefix = param->children;
					while(prefix != NULL) 
					{
						if (prefix->type == XML_ELEMENT_NODE && STRCMP(prefix->name,"prefix")==0) 
						{
							/* Read prefix params: */
							xmlNode *prefix_param = prefix->children;
							prefix_t* new_prefix = malloc(sizeof(prefix_t));
							char buffer[INET6_ADDRSTRLEN];
							if (new_prefix==NULL) 
							{
								fprintf(stderr, "malloc failed.");
							}
							memset(&new_prefix->prefix, 0, sizeof(struct in6_addr));
							new_prefix->mask = 0;
							new_prefix->param_valid_time = 0;
							new_prefix->param_preferred_time = 0;
							while(prefix_param != NULL) 
							{
								if (prefix_param->type != XML_ELEMENT_NODE) 
								{
									prefix_param = prefix_param->next;
									continue;
								}
								/* We have an XML Element: */
								if (STRCMP(prefix_param->name,"address")==0) 
								{
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									strncpy(buffer,text, INET6_ADDRSTRLEN);
									inet_pton(AF_INET6,buffer, &new_prefix->prefix);
								}
								else if (STRCMP(prefix_param->name,"mask")==0) 
								{
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->mask = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(prefix_param->name,"param_flags_reserved")==0) 
								{
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_flags_reserved = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(prefix_param->name,"param_valid_time")==0) 
								{
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_valid_time = strtoul(text!=NULL?text:"0", NULL, 10);
								}
								else if (STRCMP(prefix_param->name,"param_preferred_time")==0) 
								{
									text=(char *)XML_GET_CONTENT(prefix_param->children);
									new_prefix->param_preferred_time = strtoul(text!=NULL?text:"0", NULL, 10);
								}
								prefix_param = prefix_param->next;
							}

							/* Add prefix to tmp list:*/
							new_prefix->next = tmp_prefix;
							tmp_prefix = new_prefix;
						}
						/* Fetch next prefix node: */
						prefix = prefix->next;
					}
				} /* end prefixes */

				/* RFC6106 RDNSS */
				else if( !STRCMP(param->name,"rdnss") ) 
				{
					xmlNode *nameserver = param->children;
					while(nameserver != NULL) 
					{
						if (nameserver->type == XML_ELEMENT_NODE &&  STRCMP(nameserver->name,"nameserver")==0 ) 
						{
							/* nameserver tag */
							rdnss_t* new = malloc(sizeof(rdnss_t));
							if (new == NULL) 
							{
								fprintf(stderr, "[router_list_parse] malloc failed for new nameserver.");
							}
							/* read address */
							inet_pton(AF_INET6,(char *)XML_GET_CONTENT(nameserver->children), &new->address);
							/* read lifetime */
							new->lifetime = atoi( (char *)xmlGetProp(nameserver, BAD_CAST "lifetime") );
							/* Add nameserver to tmp list: */
							new->next = tmp_nameservers;
							tmp_nameservers = new;
						}
						/* Fetch next nameserver node: */
						nameserver = nameserver->next;
					}
				} /* end rdnss */

				/* RFC6106 DNSSL */
				else if( !STRCMP(param->name,"dnssl") ) 
				{
					xmlNode *domain = param->children;
					xmlChar *domain_name;
					while(domain != NULL) 
					{
						if (domain->type == XML_ELEMENT_NODE &&  STRCMP(domain->name,"domain")==0 ) 
						{
							/* domain tag */
							dnssl_t* new = malloc(sizeof(dnssl_t));
							if (new == NULL) 
							{
								fprintf(stderr, "[router_list_parse] malloc failed for new domain.");
							}
							/* read domain */
							domain_name = XML_GET_CONTENT(domain->children);
							memcpy(&new->domain, domain_name, MAX_DOMAINLEN);
							/* read lifetime */
							new->lifetime = atoi( (char *)xmlGetProp(domain, BAD_CAST "lifetime") );
							/* Add domain to tmp list: */
							new->next = tmp_domains;
							tmp_domains = new;
						}
						/* Fetch next domain node: */
						domain = domain->next;
					}
				} /* end rdnss */

				
				/* RFC4191 Route Info */
				else if( !STRCMP(param->name,"routes") ) 
				{
					xmlNode *route = param->children;

					while(route != NULL) 
					{
						if (route->type == XML_ELEMENT_NODE &&  STRCMP(route->name,"route")==0 ) 
						{
							/* route tag */
							xmlNode *route_param = route->children;
							char buffer[INET6_ADDRSTRLEN];

							route_info_t* new = malloc(sizeof(route_info_t));
							if (new == NULL) 
							{
								fprintf(stderr, "[router_list_parse] malloc failed for new route.");
							}
							memset(&new->prefix, 0, sizeof(struct in6_addr));
							new->mask = 0;
							new->param_pref_reserved = 0;
							new->lifetime = 0;
							
							while(route_param != NULL) 
							{
								if (route_param->type != XML_ELEMENT_NODE) 
								{
									route_param = route_param->next;
									continue;
								}
								/* We have an XML Element: */
								if (STRCMP(route_param->name,"address")==0) 
								{
									text=(char *)XML_GET_CONTENT(route_param->children);
									strncpy(buffer,text, INET6_ADDRSTRLEN);
									inet_pton(AF_INET6,buffer, &new->prefix);
								}
								else if (STRCMP(route_param->name,"mask")==0) 
								{
									text=(char *)XML_GET_CONTENT(route_param->children);
									new->mask = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(route_param->name,"param_pref_reserved")==0) 
								{
									text=(char *)XML_GET_CONTENT(route_param->children);
									new->param_pref_reserved = atoi(text!=NULL?text:0);
								}
								else if (STRCMP(route_param->name,"lifetime")==0) 
								{
									text=(char *)XML_GET_CONTENT(route_param->children);
									new->lifetime = strtoul(text!=NULL?text:"0", NULL, 10);
								}
								
								route_param = route_param->next;
							}

							/* Add route to tmp list: */
							new->next = tmp_routes;
							tmp_routes = new;
						}
						/* Fetch next route node: */
						route = route->next;
					}
				} /* end route info */

				/* Next router parameter */
				param = param->next;
			} /* end router parameters */

			/* Add router to the router list: */
			router_add( routers, &mac, &lla, param_curhoplimit, param_flags_reserved, 
					param_router_lifetime, param_reachable_timer, param_retrans_timer, 
					param_mtu, params_volatile);

			/* Add prefixes */
			while (tmp_prefix!=NULL) 
			{
				prefix_t* current=tmp_prefix;
				router_add_prefix( *routers, lla, mac,
						current->prefix, current->mask,	current->param_flags_reserved,
						current->param_valid_time, current->param_preferred_time);

				tmp_prefix = current->next;
				free(current);
			}

			/* Add addresses */
			while (tmp_address!=NULL) 
			{
				address_t* current=tmp_address;
				router_add_address(*routers, mac, current->address);
				tmp_address = current->next;
				free(current);
			}

			/* Add nameservers */
			while (tmp_nameservers!=NULL) 
			{
				rdnss_t* current = tmp_nameservers;
				router_add_nameserver(*routers, mac, current->address, current->lifetime);
				tmp_nameservers = current->next;
				free(current);
			}

			/* Add domains */
			while (tmp_domains!=NULL) 
			{
				dnssl_t* current = tmp_domains;
				router_add_domain(*routers, mac, current->domain, current->lifetime);
				tmp_domains = current->next;
				free(current);
			}

			/* Add routes */
			while (tmp_routes!=NULL) 
			{
				route_info_t *current = tmp_routes;
				router_add_route(*routers, lla, mac, current->prefix, current->mask, current->param_pref_reserved, current->lifetime);
				tmp_routes = current->next;
				free(current);
			}


		} /* end is XML element and router */

		/* Fetch next router node: */
		router = router->next;
	}

	return 0;
}

int router_list_store(xmlNodePtr routers_element, router_list_t* routers) 
{
	router_list_t* tmp_routers=routers;

	/* add all routers to the DOM: */
	while (tmp_routers!=NULL) 
	{
		xmlNodePtr router_element;
		xmlNodePtr router_addresses_element;
		xmlNodePtr router_prefixes_element;
		xmlNodePtr router_nameservers_element;
		xmlNodePtr router_domains_element;
		xmlNodePtr router_routes_element;

		char router_lla_str[INET6_ADDRSTRLEN];
		address_t* router_addresses;
		prefix_t *router_prefixes;
		rdnss_t *router_nameservers;
		dnssl_t *router_domains;
		route_info_t *router_routes;
		char temp[100];

		/* create a "router" element and add information for this router: */
		router_element = xmlNewChild(routers_element, NULL, BAD_CAST "router", NULL);
		xmlNewChild(router_element, NULL, BAD_CAST "mac", BAD_CAST ether_ntoa(&tmp_routers->mac));
		inet_ntop(AF_INET6, &tmp_routers->lla, router_lla_str, INET6_ADDRSTRLEN);
		xmlNewChild(router_element, NULL, BAD_CAST "lla", BAD_CAST router_lla_str);
		snprintf(temp, 100, "%u", tmp_routers->param_curhoplimit);
		xmlNewChild(router_element, NULL, BAD_CAST "param_curhoplimit", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->param_flags_reserved);
		xmlNewChild(router_element, NULL, BAD_CAST "param_flags_reserved", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->param_router_lifetime);
		xmlNewChild(router_element, NULL, BAD_CAST "param_router_lifetime", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->param_reachable_timer);
		xmlNewChild(router_element, NULL, BAD_CAST "param_reachable_timer", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->param_retrans_timer);
		xmlNewChild(router_element, NULL, BAD_CAST "param_retrans_timer", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->param_mtu);
		xmlNewChild(router_element, NULL, BAD_CAST "param_mtu", BAD_CAST temp);
		snprintf(temp, 100, "%u", tmp_routers->params_volatile);
		xmlNewChild(router_element, NULL, BAD_CAST "params_volatile", BAD_CAST temp);

		/* add all global ipv6 addresses to the router: */
		router_addresses_element = xmlNewChild(router_element, NULL, BAD_CAST "addresses", NULL);
		router_addresses = tmp_routers->addresses;
		while (router_addresses!=NULL) 
		{
			char router_global_ipv6_str[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, &router_addresses->address, router_global_ipv6_str, INET6_ADDRSTRLEN);
			xmlNewChild(router_addresses_element, NULL, BAD_CAST "address", NULL);
			/* fetch next address: */
			router_addresses = router_addresses->next;
		}

		/* add all prefixes to the router: */
		router_prefixes_element = xmlNewChild(router_element, NULL, BAD_CAST "prefixes", NULL);
		router_prefixes = tmp_routers->prefixes;
		while (router_prefixes!=NULL) 
		{
			xmlNodePtr router_prefix_element;
			char router_prefix_str[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, &router_prefixes->prefix, router_prefix_str, INET6_ADDRSTRLEN);
			router_prefix_element = xmlNewChild(router_prefixes_element, NULL, BAD_CAST "prefix", NULL);
			xmlNewChild(router_prefix_element, NULL, BAD_CAST "address", BAD_CAST router_prefix_str);
			snprintf(temp, 100, "%u", router_prefixes->mask);
			xmlNewChild(router_prefix_element, NULL, BAD_CAST "mask", BAD_CAST temp);
			snprintf(temp, 100, "%u", router_prefixes->param_flags_reserved);
			xmlNewChild(router_prefix_element, NULL, BAD_CAST "param_flags_reserved", BAD_CAST temp);
			snprintf(temp, 100, "%u", router_prefixes->param_valid_time);
			xmlNewChild(router_prefix_element, NULL, BAD_CAST "param_valid_time", BAD_CAST temp);
			snprintf(temp, 100, "%u", router_prefixes->param_preferred_time);
			xmlNewChild(router_prefix_element, NULL, BAD_CAST "param_preferred_time", BAD_CAST temp);
			/* fetch next prefix: */
			router_prefixes = router_prefixes->next;
		}

		/* add all recurive nameservers */
		router_nameservers = tmp_routers->nameservers;
		if( router_nameservers != NULL )
		{
			router_nameservers_element = xmlNewChild(router_element, NULL, BAD_CAST "rdnss", NULL);
			while (router_nameservers!=NULL) 
			{
				char ns_addr_str[INET6_ADDRSTRLEN];
				xmlNodePtr router_nameserver_element;

				inet_ntop(AF_INET6, &router_nameservers->address, ns_addr_str, INET6_ADDRSTRLEN);
				router_nameserver_element = xmlNewChild(router_nameservers_element, NULL, BAD_CAST "nameserver", BAD_CAST ns_addr_str);

				snprintf(temp, 100, "%u", router_nameservers->lifetime);
				xmlNewProp(router_nameserver_element, BAD_CAST "lifetime", BAD_CAST temp);

				/* fetch next NS */
				router_nameservers = router_nameservers->next;
			}
		}

		/* add all search domains */
		router_domains = tmp_routers->domains;
		if( router_domains != NULL )
		{
			router_domains_element = xmlNewChild(router_element, NULL, BAD_CAST "dnssl", NULL);
			while (router_domains!=NULL) 
			{
				xmlNodePtr router_domain_element;

				router_domain_element = xmlNewChild(router_domains_element, NULL, BAD_CAST "domain", BAD_CAST router_domains->domain);

				snprintf(temp, 100, "%u", router_domains->lifetime);
				xmlNewProp(router_domain_element, BAD_CAST "lifetime", BAD_CAST temp);

				/* fetch next NS */
				router_domains = router_domains->next;
			}
		}

		/* add all routes */
		router_routes = tmp_routers->routes;
		if( router_routes != NULL )
		{
			router_routes_element = xmlNewChild(router_element, NULL, BAD_CAST "routes", NULL);
			while (router_routes!=NULL) 
			{
				/* <!ELEMENT route (address, mask, param_pref_reserved, lifetime)> */
				char addr_str[INET6_ADDRSTRLEN];
				xmlNodePtr router_route_element;
				router_route_element = xmlNewChild(router_routes_element, NULL, BAD_CAST "route", NULL);

				inet_ntop(AF_INET6, &router_routes->prefix, addr_str, INET6_ADDRSTRLEN);
				xmlNewChild(router_route_element, NULL, BAD_CAST "address", BAD_CAST addr_str);

				snprintf(temp, 100, "%u", router_routes->mask);
				xmlNewChild(router_route_element, NULL, BAD_CAST "mask", BAD_CAST temp);

				snprintf(temp, 100, "%u", router_routes->param_pref_reserved);
				xmlNewChild(router_route_element, NULL, BAD_CAST "param_pref_reserved", BAD_CAST temp);

				snprintf(temp, 100, "%u", router_routes->lifetime);
				xmlNewChild(router_route_element, NULL, BAD_CAST "lifetime", BAD_CAST temp);

				/* fetch next NS */
				router_routes = router_routes->next;
			}
		}

		/* fetch next router: */
		tmp_routers = tmp_routers->next;
	}
	return 0;
}
/* CONFIG */

