
#include "countermeasures.h"

/* All counter measures that are currently on link and have not yet been captured. */
static struct cm_on_link_list* cm_on_link;

/* the guards for each counter measure
 * i.e. their politic
 **/
struct cm_guard cm_guard_kill_illegitimate_router;
struct cm_guard cm_guard_kill_wrong_prefix;
struct cm_guard cm_guard_propagate_router_params;
struct cm_guard cm_guard_propagate_router_dns;
struct cm_guard cm_guard_propagate_router_routes;
struct cm_guard cm_guard_propagate_neighbor_mac;
struct cm_guard cm_guard_indicate_ndpmon_presence;

void cm_guard_init(struct cm_guard* guard, char* config) 
{
	unsigned int criteria=0;
	guard->calls = 0;
	if (strncmp(config, "RESPOND", CM_GUARD_REPRESENTATION_SIZE)==0) 
	{
		guard->strategy_type = CM_GUARD_STRATEGY_TYPE_RESPOND;
		guard->strategy_criteria = 0;
	} 
	else if (strncmp(config, "LAUNCH AFTER ", 13)==0) 
	{
		if (sscanf(config, "LAUNCH AFTER %u", &criteria)!=EOF) 
		{
			guard->strategy_type = CM_GUARD_STRATEGY_TYPE_LAUNCH;
			guard->strategy_criteria = criteria;
		} 
		else 
		{
			/* Failure, wrong format: */
			guard->strategy_type = CM_GUARD_STRATEGY_TYPE_SUPPRESS;
			guard->strategy_criteria = 0;
			fprintf(stderr, "[countermeasures]: Error: Wrong format in guard configuration \"%s\"\n", config);
			fprintf(stderr, "                   Affected countermeasure will be suppressed.\n");
		}
	} 
	else if (strncmp(config, "CEASE AFTER ", 12)==0) 
	{
		if (sscanf(config, "CEASE AFTER %u", &criteria)!=EOF) 
		{
			guard->strategy_type = CM_GUARD_STRATEGY_TYPE_CEASE;
			guard->strategy_criteria = criteria;
		} 
		else 
		{
			/* Failure, wrong format: */
			guard->strategy_type = CM_GUARD_STRATEGY_TYPE_SUPPRESS;
			guard->strategy_criteria = 0;
			fprintf(stderr, "[countermeasures]: Error: Wrong format in guard configuration \"%s\"\n", config);
			fprintf(stderr, "                   Affected countermeasure will be suppressed.\n");
		}
	} 
	else 
	{ /* If unknown type, always suppress.*/
		guard->strategy_type = CM_GUARD_STRATEGY_TYPE_SUPPRESS;
		guard->strategy_criteria = 0;
	}
}

void cm_guard_init_all(
		char* config_kill_illegitimate_router,
		char* config_kill_wrong_prefix,
		char* config_propagate_router_params,
		char* config_propagate_router_dns,
		char* config_propagate_router_routes,
		char* config_propagate_neighbor_mac,
		char* config_indicate_ndpmon_presence
		) 
{
	if (config_kill_illegitimate_router!=NULL) cm_guard_init(&cm_guard_kill_illegitimate_router, config_kill_illegitimate_router);
	if (config_kill_wrong_prefix!=NULL)        cm_guard_init(&cm_guard_kill_wrong_prefix,        config_kill_wrong_prefix);
	if (config_propagate_router_params!=NULL)  cm_guard_init(&cm_guard_propagate_router_params,  config_propagate_router_params);
	if (config_propagate_router_dns!=NULL)     cm_guard_init(&cm_guard_propagate_router_dns,     config_propagate_router_dns);
	if (config_propagate_router_routes!=NULL)  cm_guard_init(&cm_guard_propagate_router_routes,  config_propagate_router_routes);
	if (config_propagate_neighbor_mac!=NULL)   cm_guard_init(&cm_guard_propagate_neighbor_mac,   config_propagate_neighbor_mac);
	if (config_indicate_ndpmon_presence!=NULL) cm_guard_init(&cm_guard_indicate_ndpmon_presence, config_indicate_ndpmon_presence);
}

void cm_guard_to_representation(struct cm_guard* guard, char* config) 
{
	switch (guard->strategy_type) 
	{
		case CM_GUARD_STRATEGY_TYPE_RESPOND:
			strlcpy(config, "RESPOND", CM_GUARD_REPRESENTATION_SIZE);
			return;
		case CM_GUARD_STRATEGY_TYPE_LAUNCH:
			snprintf(config, CM_GUARD_REPRESENTATION_SIZE, "LAUNCH AFTER %u", guard->strategy_criteria);
			return;
		case CM_GUARD_STRATEGY_TYPE_CEASE:
			snprintf(config, CM_GUARD_REPRESENTATION_SIZE, "CEASE AFTER %u", guard->strategy_criteria);
			return;
		case CM_GUARD_STRATEGY_TYPE_SUPPRESS:
		default:
			strlcpy(config, "SUPPRESS", CM_GUARD_REPRESENTATION_SIZE);
			return;
	}
}

void cm_guard_all_to_representation(
		char* config_kill_illegitimate_router,
		char* config_kill_wrong_prefix,
		char* config_propagate_router_params,
		char* config_propagate_router_dns,
		char* config_propagate_router_routes,
		char* config_propagate_neighbor_mac,
		char* config_indicate_ndpmon_presence
		) 
{
	cm_guard_to_representation(&cm_guard_kill_illegitimate_router, config_kill_illegitimate_router);
	cm_guard_to_representation(&cm_guard_kill_wrong_prefix,        config_kill_wrong_prefix);
	cm_guard_to_representation(&cm_guard_propagate_router_params,  config_propagate_router_params);
	cm_guard_to_representation(&cm_guard_propagate_router_dns,  config_propagate_router_dns);
	cm_guard_to_representation(&cm_guard_propagate_router_routes,  config_propagate_router_routes);
	cm_guard_to_representation(&cm_guard_propagate_neighbor_mac,   config_propagate_neighbor_mac);
	cm_guard_to_representation(&cm_guard_indicate_ndpmon_presence, config_indicate_ndpmon_presence);
}

int cm_is_welcome(struct cm_guard* guard) 
{
	if (guard->calls < UINT8_MAX) 
	{
		guard->calls++;
	}

	switch (guard->strategy_type) 
	{
		case CM_GUARD_STRATEGY_TYPE_RESPOND: /* respond on each call */
			return 1;
		case CM_GUARD_STRATEGY_TYPE_CEASE: /* after (criteria) stop responding on each call */
			if (guard->calls <= guard->strategy_criteria) 
			{
				return 1;
			}
			return 0;
		case CM_GUARD_STRATEGY_TYPE_LAUNCH: /* after (criteria) calls start responding on each call */
			if (guard->calls > guard->strategy_criteria) 
			{
				return 1;
			}
			return 0;
		case CM_GUARD_STRATEGY_TYPE_SUPPRESS: /* never respond to a call */
		default:
			return 0;
	}
}

int cm_on_link_add(const uint8_t* packet, int packet_length) 
{
	cm_on_link_hash_t* hash_ptr=cm_on_link_create_hash_for_packet(packet, packet_length);
	struct cm_on_link_list* new;
	if ((new = malloc(sizeof(struct cm_on_link_list)))==NULL) 
	{
		return -1;
	}
	memcpy(&new->hash, hash_ptr, sizeof(cm_on_link_hash_t));
	new->next = cm_on_link;
	cm_on_link = new;
	free(hash_ptr);
	return 0;
}

int cm_on_link_remove(const uint8_t* packet, int packet_length) 
{
	cm_on_link_hash_t* hash_ptr=NULL;
	struct cm_on_link_list *current_old=NULL, *current_new=NULL, *new=NULL;
	int found = 0;

	if (cm_on_link==NULL) 
	{
		return 0;
	}
	hash_ptr = cm_on_link_create_hash_for_packet(packet, packet_length);
	current_old = cm_on_link;
	while (current_old!=NULL) 
	{
		/* If the hashs match we do not change the new list.*/
		if (memcmp(&current_old->hash, hash_ptr, sizeof(cm_on_link_hash_t))==0) 
		{
			found = 1;
			/* If the new list is empty a first entry will be created. */
		} else if (new==NULL) {
			new = (current_new = current_old);
			/* If the new list contains entries we append a new one.*/
		} 
		else 
		{
			current_new = (current_new->next = current_old);
		}
		current_old = current_old->next;
		/* If not emtpy, the new list must be kept null-terminated.*/
		if (current_new!=NULL)
			current_new->next = NULL;
	}
	cm_on_link = new;
	free(hash_ptr);
	return found;    
}

cm_on_link_hash_t* cm_on_link_create_hash_for_packet(const uint8_t* packet, int packet_length) 
{
	cm_on_link_hash_t* hash_ptr = NULL;
	if ((hash_ptr=malloc(sizeof(cm_on_link_hash_t)))==NULL) 
	{
		return NULL;
	}
	SHA1 (packet, packet_length, (unsigned char*) hash_ptr);
	return hash_ptr;
}

void cm_on_link_free_all() 
{
	while (cm_on_link!=NULL) 
	{
		struct cm_on_link_list* current = cm_on_link;
		cm_on_link = cm_on_link->next;
		free(current);
	}
}

void cm_init() 
{
	/* set icmp_lib callback hook to store sent counter measure hashs. */
	set_on_sending_hook(&cm_on_sending_hook);
	/* initialize guards to have defaults if XML config tags are omitted. */
	cm_guard_init_all(
			"SUPPRESS",
			"SUPPRESS",
			"SUPPRESS",
			"SUPPRESS",
			"SUPPRESS",
			"SUPPRESS",
			"SUPPRESS"
			);
}

void cm_config_parse(xmlNodePtr element) 
{
	char	*config_kill_illegitimate_router=NULL,
		*config_kill_wrong_prefix=NULL,
		*config_propagate_router_params=NULL,
		*config_propagate_router_dns=NULL,
		*config_propagate_router_routes=NULL,
		*config_propagate_neighbor_mac=NULL,
		*config_indicate_ndpmon_presence=NULL;
	xmlNodePtr countermeasure=element->children;

	while (countermeasure!=NULL) 
	{
		if (countermeasure->type!=XML_ELEMENT_NODE) 
		{
			countermeasure = countermeasure->next;
			continue;
		}

		/* we have an XML element: */
		if (!strncmp((const char *)countermeasure->name, "kill_illegitimate_router", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_kill_illegitimate_router = (char*)XML_GET_CONTENT(countermeasure->children);
		} 
		else if (!strncmp((const char *)countermeasure->name, "kill_wrong_prefix", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_kill_wrong_prefix        = (char*)XML_GET_CONTENT(countermeasure->children);
		} 
		else if (!strncmp((const char *)countermeasure->name, "propagate_router_params", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_propagate_router_params  = (char*)XML_GET_CONTENT(countermeasure->children);
		} 
		else if (!strncmp((const char *)countermeasure->name, "propagate_router_dns", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_propagate_router_dns  = (char*)XML_GET_CONTENT(countermeasure->children);
		}
		else if (!strncmp((const char *)countermeasure->name, "propagate_router_routes", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_propagate_router_routes  = (char*)XML_GET_CONTENT(countermeasure->children);
		}
		else if (!strncmp((const char *)countermeasure->name, "indicate_ndpmon_presence", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_indicate_ndpmon_presence = (char*)XML_GET_CONTENT(countermeasure->children);
		}
		else if (!strncmp((const char *)countermeasure->name, "propagate_neighbor_mac", CM_GUARD_REPRESENTATION_SIZE)) 
		{
			config_propagate_neighbor_mac = (char*)XML_GET_CONTENT(countermeasure->children);
		}

		countermeasure = countermeasure->next;
	}

	cm_guard_init_all(
			config_kill_illegitimate_router,
			config_kill_wrong_prefix,
			config_propagate_router_params,
			config_propagate_router_dns,
			config_propagate_router_routes,
			config_propagate_neighbor_mac,
			config_indicate_ndpmon_presence
			);
}

int cm_config_store(xmlNodePtr countermeasures_element) 
{
	char config_kill_illegitimate_router[CM_GUARD_REPRESENTATION_SIZE];
	char config_kill_wrong_prefix[CM_GUARD_REPRESENTATION_SIZE];
	char config_propagate_router_params[CM_GUARD_REPRESENTATION_SIZE];
	char config_propagate_router_dns[CM_GUARD_REPRESENTATION_SIZE];
	char config_propagate_router_routes[CM_GUARD_REPRESENTATION_SIZE];
	char config_propagate_neighbor_mac[CM_GUARD_REPRESENTATION_SIZE];
	char config_indicate_ndpmon_presence[CM_GUARD_REPRESENTATION_SIZE];

	cm_guard_all_to_representation(
			config_kill_illegitimate_router,
			config_kill_wrong_prefix,
			config_propagate_router_params,
			config_propagate_router_dns,
			config_propagate_router_routes,
			config_propagate_neighbor_mac,
			config_indicate_ndpmon_presence
			);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "kill_illegitimate_router", BAD_CAST config_kill_illegitimate_router);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "kill_wrong_prefix", BAD_CAST config_kill_wrong_prefix);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "propagate_router_params", BAD_CAST config_propagate_router_params);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "propagate_router_dns", BAD_CAST config_propagate_router_dns);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "propagate_router_routes", BAD_CAST config_propagate_router_routes);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "propagate_neighbor_mac", BAD_CAST config_propagate_neighbor_mac);
	xmlNewChild(countermeasures_element, NULL, BAD_CAST "indicate_ndpmon_presence", BAD_CAST config_indicate_ndpmon_presence);
	return 0;
}

void dump_cm_list() 
{
	struct cm_on_link_list* current=cm_on_link;
	int x=0;
	while (current != NULL) 
	{
		x=0;
		while (x<20) 
		{
			fprintf(stderr, "%u ", current->hash[x]);
			x++;
		}
		fprintf(stderr, "\n");
		current = current->next;
	}
}

void cm_on_sending_hook(uint8_t** packet, int* packet_length) 
{
	cm_on_link_add(*packet, *packet_length);
	/*dump_cm_list();*/
}

int cm_kill_illegitimate_router(const struct ether_addr *router_mac, const struct in6_addr *router_ip, const char* p_interface) 
{
	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	int result=0;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_kill_illegitimate_router)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router_mac==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			64, /*curhoplimit*/
			0,  /*flags_reserved, m and o not set*/
			0,  /*ROUTER LIFETIME*/
			0,0 /*reachable and retrans timer, not specified*/
			);

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing zero lifetime RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,router_mac,iphdr,(struct icmp6_hdr*)routeradv,NULL)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent zero lifetime advertisement for illegitimate router.\n");
	}

	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	return result;
}

int cm_kill_wrong_prefix(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_prefix, const int wrong_prefix_length, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct nd_opt_prefix_info* prefix_info=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_kill_wrong_prefix)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing prefix zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);
	prefix_info = create_nd_opt_prefix_info(
			wrong_prefix,
			wrong_prefix_length,
			ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
			0, 0 /* preferred and valid time */
			);
	if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)prefix_info)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while adding prefix info option.\n");
		goto error;
	}

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL || prefix_info == NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing prefix zero lifetime RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent prefix zero lifetime advertisement for wrong prefix.\n");
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	prefix_info=NULL;
	free_icmp_nd_opt_list(&nd_options);
	return result;
}

int cm_propagate_router_params(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct nd_opt_prefix_info *option_prefix_info=NULL;
	struct nd_opt_mtu *option_mtu=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;
	prefix_t *router_prefix;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_params)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing prefix zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data: Header and parameters: */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);
	/* Prepare RA data: Options: */
	router_prefix = router->prefixes;
	while (router_prefix!=NULL) 
	{
		option_prefix_info = create_nd_opt_prefix_info(
				&router_prefix->prefix,
				router_prefix->mask,
				router_prefix->param_flags_reserved,
				router_prefix->param_valid_time,
				router_prefix->param_preferred_time
				);
		if (option_prefix_info==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA prefix option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_prefix_info)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding prefix info option.\n");
			goto error;
		}
		router_prefix = router_prefix->next;
	}
	option_prefix_info = NULL; /* will be released with option list */
	if (router->param_mtu!=0) 
	{
		option_mtu = create_nd_opt_mtu(0, router->param_mtu);
		if (option_mtu==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA mtu option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_mtu)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding mtu option.\n");
			goto error;
		}
		option_mtu = NULL; /* will be released with option list */
	}

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent propagate params router advertisement for wrong params.\n");
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	free_icmp_nd_opt_list(&nd_options);
	return result;
}

int cm_indicate_ndpmon_presence(const char* p_interface) 
{
	struct in6_addr *dst_ip=NULL, *src_ip=NULL;
	struct ether_addr *dst_mac=NULL, *src_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_ndpmon_present *ndpmon_present=NULL;
	uint8_t flags = 0;
	int result=0;

	/* Ask guard whether to indicate presence or not.*/
	if (cm_is_welcome(&cm_guard_indicate_ndpmon_presence)==0) 
	{
		return 0;
	}

	/* Prepare RA data. */
	src_ip  = create_in6_addr_for_interface((char *)p_interface);
	src_mac = create_mac_for_interface((char *)p_interface);
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, src_ip);
	if (learning) 
	{
		flags = flags | ND_NP_FLAG_LEARNING_PHASE;
	}
#ifdef _MACRESOLUTION_
	flags = flags | ND_NP_FLAG_MAC_RESOLV;
#endif
	flags = flags | ND_NP_FLAG_COUNTER_MEASURES;
	ndpmon_present = create_icmp_ndpmon_present(1,3,5,flags);

	/* Checking data. */
	if (src_ip==NULL || src_mac==NULL || dst_ip==NULL || dst_mac==NULL || iphdr==NULL || ndpmon_present==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing ndpmon presence indication message (malloc failed?).\n");
		goto error;
	}
	/* Sending NP */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,src_mac,iphdr,(struct icmp6_hdr*)ndpmon_present,NULL)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending NP.\n");
		goto error;
	} 
	else
	{
		fprintf(stderr, "[countermeasures]: Sent ndpmon presence indication message.\n");
	}

	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(ndpmon_present);
	return result;
}

int watch_ndpmon_present(
		char* buffer,
		const struct ether_header* ethernet_header,
		const struct ip6_hdr* ip6_header,
		const struct icmp6_hdr* icmp6_header,
		const uint8_t* packet,
		const int packet_length,
		uint16_t *watch_flags 
		) 
{
	struct nd_ndpmon_present* ndpmon_present = (struct nd_ndpmon_present*) icmp6_header;
	char version[12];
	uint8_t flags = ndpmon_present->nd_np_flags;
	fprintf(stderr, "NDPMon instance detected:\n");
	snprintf((char*)&version, 12, "%u.%u.%u", ndpmon_present->nd_np_version_major, ndpmon_present->nd_np_version_minor, ndpmon_present->nd_np_version_build);
	fprintf(stderr, "    version: %s\n", version);

	if (flags&ND_NP_FLAG_LEARNING_PHASE) 
	{
		fprintf(stderr, "    is in learning phase.\n");
	}
	
	if (flags&ND_NP_FLAG_COUNTER_MEASURES) 
	{
		fprintf(stderr, "    is configured with counter measures.\n");
	}
	
	if (flags&ND_NP_FLAG_MAC_RESOLV) 
	{
		fprintf(stderr, "    is configured with mac resolution.\n");
	}
	
	return 0;
}

int cm_propagate_neighbor_mac(neighbor_list_t *neighbor, const struct in6_addr *neighbor_ip, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_neighbor_advert *neighboradv=NULL;
	struct nd_opt_link_layer_addr* link_layer=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;
	char mac[ETH_ADDRSTRLEN];

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_neighbor_mac)==0) 
	{ 
		fprintf(stderr, "[countermeasures]: cm_propagate_neighbor_mac - Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (neighbor==NULL || neighbor_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing propagate neighbor mac NA (insufficient params from watch function).\n");   
		goto error;
	}

	snprintf(mac, ETH_ADDRSTRLEN, "%s", ether_ntoa(&neighbor->first_mac_seen));

	/* Prepare NA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, neighbor_ip);
	neighboradv = create_icmp_neighbor_advertisement(
			ND_NA_FLAG_OVERRIDE,
			(struct in6_addr *) neighbor_ip
			);			/* to avoid warning in gcc */
	link_layer = create_nd_opt_link_layer(
			ND_OPT_TARGET_LINKADDR,
			&neighbor->first_mac_seen
			);
	if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)link_layer)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while adding source link layer option.\n");
		goto error;
	}
	link_layer=NULL; /* released with option list. */

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || neighboradv==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing propagate neighbor mac NA (malloc failed?).\n");
		goto error;
	}
	/* Sending NA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&neighbor->first_mac_seen,iphdr,(struct icmp6_hdr*)neighboradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending NA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent neighbor advertisement propagating %s.\n", mac);
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(neighboradv);
	free_icmp_nd_opt_list(&nd_options);
	return result;
}



int cm_propagate_router_dns(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct nd_opt_prefix_info *option_prefix_info=NULL;
	struct nd_opt_mtu *option_mtu=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;
	prefix_t *router_prefix = NULL;
	rdnss_t *tmp_rdnss = NULL;
	struct icmp_nd_opt_rdnss *option_rdnss;
	dnssl_t *tmp_dnssl = NULL;
	struct icmp_nd_opt_dnssl *option_dnssl;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_dns)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing DNS options RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data: Header and parameters: */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);

	/* Prepare RA data: Options: */
	router_prefix = router->prefixes;
	while (router_prefix!=NULL) 
	{
		option_prefix_info = create_nd_opt_prefix_info(
				&router_prefix->prefix,
				router_prefix->mask,
				router_prefix->param_flags_reserved,
				router_prefix->param_valid_time,
				router_prefix->param_preferred_time
				);
		if (option_prefix_info==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA prefix option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_prefix_info)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding prefix info option.\n");
			goto error;
		}
		router_prefix = router_prefix->next;
	}
	option_prefix_info = NULL; /* will be released with option list */

	if (router->param_mtu!=0) 
	{
		option_mtu = create_nd_opt_mtu(0, router->param_mtu);
		if (option_mtu==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA mtu option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_mtu)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding mtu option.\n");
			goto error;
		}
		option_mtu = NULL; /* will be released with option list */
	}

	/* RFC 6106 DNS options */
	tmp_rdnss = router->nameservers;
	while (tmp_rdnss!=NULL) 
	{
		option_rdnss = create_nd_opt_rdnss( &tmp_rdnss->address, htonl(tmp_rdnss->lifetime) );

		if (option_rdnss == NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate dns RDNSS option (malloc failed?).\n");
			goto error;
		}

		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_rdnss)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding RDNSS option.\n");
			goto error;
		}

		tmp_rdnss = tmp_rdnss->next;
	}
	option_rdnss = NULL;

	tmp_dnssl = router->domains;
	while (tmp_dnssl!=NULL) 
	{
		option_dnssl = create_nd_opt_dnssl( tmp_dnssl->domain, htonl(tmp_dnssl->lifetime) );

		if (option_dnssl == NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate dns DNSSL option (malloc failed?).\n");
			goto error;
		}

		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_dnssl)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding DNSSL option.\n");
			goto error;
		}

		tmp_dnssl = tmp_dnssl->next;
	}
	option_dnssl = NULL;


	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA (malloc failed?).\n");
		goto error;
	}

	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA for wrong DNS options.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent propagate params RA for wrong DNS options.\n");
	}


	goto finally;

error:
	result = -1;

finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	free_icmp_nd_opt_list(&nd_options);
	return result;
}

int cm_kill_wrong_nameserver(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_nameserver, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct icmp_nd_opt_rdnss* option_rdnss=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_dns)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing RDNSS zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);

	/* Advertise the wrong nameserver as deprecated */
	option_rdnss = create_nd_opt_rdnss( wrong_nameserver, 0 );

	if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_rdnss)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while adding rdnss option.\n");
		goto error;
	}

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL || option_rdnss == NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing RDNSS zero lifetime RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent zero lifetime RA for wrong nameserver.\n");
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	option_rdnss=NULL;
	free_icmp_nd_opt_list(&nd_options);
	return result;
}

int cm_kill_wrong_domain(router_list_t *router, const struct in6_addr *router_ip, const char *wrong_domain, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct icmp_nd_opt_dnssl* option_dnssl=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_dns)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing DNSSL zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);

	/* Advertise the wrong domain as deprecated */
	option_dnssl = create_nd_opt_dnssl( wrong_domain, 0 );

	if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_dnssl)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while adding DNSSL option.\n");
		goto error;
	}

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL || option_dnssl == NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing DNSSL zero lifetime RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent zero lifetime RA for wrong domain.\n");
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	option_dnssl=NULL;
	free_icmp_nd_opt_list(&nd_options);
	return result;
}



int cm_propagate_router_routes(router_list_t *router, const struct in6_addr *router_ip, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct nd_opt_prefix_info *option_prefix_info=NULL;
	struct nd_opt_mtu *option_mtu=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;
	prefix_t *router_prefix = NULL;
	route_info_t *tmp_routes = NULL;
	struct icmp_nd_opt_route_info *option_rinfo;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_routes)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing Route Info options RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data: Header and parameters: */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);

	/* Prepare RA data: Options: */
	router_prefix = router->prefixes;
	while (router_prefix!=NULL) 
	{
		option_prefix_info = create_nd_opt_prefix_info(
				&router_prefix->prefix,
				router_prefix->mask,
				router_prefix->param_flags_reserved,
				router_prefix->param_valid_time,
				router_prefix->param_preferred_time
				);
		if (option_prefix_info==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA prefix option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_prefix_info)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding prefix info option.\n");
			goto error;
		}
		router_prefix = router_prefix->next;
	}
	option_prefix_info = NULL; /* will be released with option list */

	if (router->param_mtu!=0) 
	{
		option_mtu = create_nd_opt_mtu(0, router->param_mtu);
		if (option_mtu==NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate params RA mtu option (malloc failed?).\n");
			goto error;
		}
		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_mtu)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding mtu option.\n");
			goto error;
		}
		option_mtu = NULL; /* will be released with option list */
	}


	/* RFC 4191 route Info options */
	tmp_routes = router->routes;
	while (tmp_routes!=NULL) 
	{
		option_rinfo = create_nd_opt_route_info( &tmp_routes->prefix, tmp_routes->mask, tmp_routes->param_pref_reserved, htonl(tmp_routes->lifetime) );

		if (option_rinfo == NULL) 
		{
			fprintf(stderr, "[countermeasures]: Error while preparing propagate Route Info option (malloc failed?).\n");
			goto error;
		}

		if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_rinfo)==FAILURE) 
		{
			fprintf(stderr, "[countermeasures]: Error while adding Route Info option.\n");
			goto error;
		}

		tmp_routes = tmp_routes->next;
	}
	option_rinfo = NULL;


	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing propagate Route Info RA (malloc failed?).\n");
		goto error;
	}

	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA for wrong Route Info options.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent propagate params RA for wrong Route Info options.\n");
	}


	goto finally;

error:
	result = -1;

finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	free_icmp_nd_opt_list(&nd_options);
	return result;
}

int cm_kill_wrong_route(router_list_t *router, const struct in6_addr *router_ip, const struct in6_addr *wrong_prefix, const uint8_t prefix_len, const uint8_t param_pref_reserved, const char* p_interface) 
{
	int result=0;

	struct in6_addr *dst_ip=NULL;
	struct ether_addr *dst_mac=NULL;
	struct ip6_hdr *iphdr=NULL;
	struct nd_router_advert *routeradv=NULL;
	struct icmp_nd_opt_route_info* option_rinfo=NULL;
	struct icmp_nd_opt_list* nd_options = NULL;

	/* Ask guard whether to react or not.*/
	if (cm_is_welcome(&cm_guard_propagate_router_routes)==0) 
	{
		fprintf(stderr, "[countermeasures]: Reaction suppressed according to configuration.\n");
		return 0;
	}

	/* Checking input */
	if (router==NULL || router_ip==NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing Route Info zero lifetime RA (insufficient params from watch function).\n");   
		goto error;
	}

	/* Prepare RA data. */
	dst_ip  = create_in6_addr("FF02::1");
	dst_mac = create_multicast_mac_for_ip(dst_ip);
	iphdr   = create_ip6_hdr(dst_ip, router_ip);
	routeradv = create_icmp_router_advertisement(
			router->param_curhoplimit,
			router->param_flags_reserved,  
			router->param_router_lifetime, 
			router->param_reachable_timer,
			router->param_retrans_timer
			);

	/* Advertise the wrong route as deprecated */
	option_rinfo = create_nd_opt_route_info( wrong_prefix, prefix_len, param_pref_reserved, 0 );

	if (add_icmp_nd_opt(&nd_options, (struct nd_opt_hdr*)option_rinfo)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while adding route info option.\n");
		goto error;
	}

	/* Checking data. */
	if (dst_ip==NULL || dst_mac==NULL || iphdr==NULL || routeradv==NULL || option_rinfo == NULL) 
	{
		fprintf(stderr, "[countermeasures]: Error while preparing Route Info zero lifetime RA (malloc failed?).\n");
		goto error;
	}
	/* Sending RA */
	if (compose_and_send_icmp_packet((char *)p_interface,dst_mac,&router->mac,iphdr,(struct icmp6_hdr*)routeradv,nd_options)==FAILURE) 
	{
		fprintf(stderr, "[countermeasures]: Error while sending RA.\n");
		goto error;
	} 
	else 
	{
		fprintf(stderr, "[countermeasures]: Sent zero lifetime RA for wrong route.\n");
	}


	goto finally;
error:
	result = -1;
finally:
	free(dst_mac);
	free(dst_ip);
	free(iphdr);
	free(routeradv);
	option_rinfo=NULL;
	free_icmp_nd_opt_list(&nd_options);
	return result;
}


