#include "probes.h"

static struct probe_list* probes;

pthread_mutex_t probes_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef _COUNTERMEASURES_
int probe_cm_enabled(const char* probe_name)
{
	struct probe_list* tmp_probes = probes;

	/* find the probe */
	while (tmp_probes!=NULL) 
	{
		if (strncmp(probe_name, tmp_probes->entry.name, PROBE_NAME_SIZE)==0) 
		{
			break;
		}
		tmp_probes = tmp_probes->next;
	}

	/* if found, return the value */
	if (tmp_probes!=NULL) 
	{
		return tmp_probes->entry.cm_enabled;
	}

	/* Not found, return -1 */
	return -1;
}
#endif



void probe_copy(struct probe *destination, const struct probe *source)
{
	address_t* tmp_addresses               = source->addresses;
	neighbor_list_t* tmp_neighbors         = source->neighbors;
	neighbor_list_t* current_neighbors_end = NULL;
	router_list_t* tmp_routers             = source->routers;
	router_list_t* current_routers_end     = NULL;

	destination->extinfo = NULL; /* TODO copy extinfo? */
	memcpy(&destination->ethernet_address, &source->ethernet_address, sizeof(struct ether_addr));
	strlcpy(destination->name, source->name, PROBE_NAME_SIZE);
	destination->type = source->type;
#ifdef _COUNTERMEASURES_
	destination->cm_enabled = source->cm_enabled;
#endif
	/* copy addresses: */
	destination->addresses = NULL;
	while(tmp_addresses!=NULL) 
	{
		addresses_add(&destination->addresses, &tmp_addresses->address, tmp_addresses->firstseen, tmp_addresses->lastseen);
		tmp_addresses = tmp_addresses->next;
	}
	/* copy neighbors: */
	destination->neighbors = NULL;
	while (tmp_neighbors!=NULL) 
	{
		neighbor_list_t* neighbor_cp;
		if ((neighbor_cp=malloc(sizeof(neighbor_list_t)))==NULL) 
		{
			perror("[probes] malloc failed.");
			exit(1);
		}
		neighbor_copy(neighbor_cp, tmp_neighbors);
		if (current_neighbors_end==NULL) 
		{
			current_neighbors_end = neighbor_cp;
			destination->neighbors = current_neighbors_end;
		} 
		else 
		{
			current_neighbors_end->next = neighbor_cp;
			current_neighbors_end = neighbor_cp;
		}
		tmp_neighbors = tmp_neighbors->next;
	}
	/* copy routers: */
	destination->routers = NULL;
	while (tmp_routers!=NULL) 
	{
		router_list_t* router_cp;
		if ((router_cp=malloc(sizeof(router_list_t)))==NULL) 
		{
			perror("[probes] malloc failed.");
			exit(1);
		}
		router_copy(router_cp, tmp_routers);
		if (current_routers_end==NULL) 
		{
			current_routers_end = router_cp;
			destination->routers = current_routers_end;
		} 
		else 
		{
			current_routers_end->next = router_cp;
			current_routers_end = router_cp;
		}
		tmp_routers = tmp_routers->next;
	}

}


#ifdef _COUNTERMEASURES_
int probe_load_config(xmlNodePtr element, char* name, enum probe_type* type,
        struct extinfo_list** extinfo, router_list_t** routers,
        int load_remote_config, int *cm_enabled)
#else
int probe_load_config(xmlNodePtr element, char* name, enum probe_type* type,
        struct extinfo_list** extinfo, router_list_t** routers,
        int load_remote_config)
#endif
{
	xmlNodePtr probe_child = element->children;
	xmlChar* device_prop = xmlGetProp(element, BAD_CAST "name");
	xmlChar* type_prop   = xmlGetProp(element, BAD_CAST "type");

	if (device_prop==NULL) 
	{
		fprintf(stderr, "[probes] missing probe name.\n");
		return -1;
	}

	strlcpy(name, (char*)device_prop, PROBE_NAME_SIZE);
	xmlFree(device_prop);

	if (type_prop!=NULL && STRCMP(type_prop, "interface")==0) 
	{
		*type = PROBE_TYPE_INTERFACE;
	} 
	else if (type_prop!=NULL && STRCMP(type_prop, "remote")==0) 
	{
		*type = PROBE_TYPE_REMOTE;
		if (load_remote_config==0) 
		{
			/* load no configuration for remote probes, is just informational: */
			*extinfo = NULL;
			*routers = NULL;
			xmlFree(type_prop);
			return 0;
		}
	} 
	else 
	{
		fprintf(stderr, "[probes] ERROR: unknown interface type %s", (char*) type_prop);
		xmlFree(type_prop);
		return -1;
	}
	xmlFree(type_prop);

	while (probe_child!=NULL) 
	{
		if (probe_child->type!=XML_ELEMENT_NODE) 
		{
			probe_child = probe_child->next;
			continue;
		}

#ifdef _COUNTERMEASURES_
		if (STRCMP(probe_child->name, "countermeasures_enabled")==0)
		{
			*cm_enabled = atoi( (const char *)probe_child->children->content );
		}
		else 
#endif
		if (STRCMP(probe_child->name, "routers")==0) 
		{
			if (*type== PROBE_TYPE_INTERFACE && router_list_parse(probe_child, routers)==-1) 
			{
				return -1;
			}
		}
		probe_child = probe_child->next;
	}
	/* loading other information: */
	if (extinfo_list_load(element, extinfo)==-1) 
	{
		return -1;
	}
	if (name==NULL) 
	{
		fprintf(stderr, "[probes] ERROR: Name for the probe required.\n");
		return -1;
	}
	/* all tags read, add probe: */

	return 0;
}

int probe_load_neighbors(xmlNodePtr element, struct probe* probe,
        int load_remote_neighbors)
{
#if 0
	xmlChar* type_prop = xmlGetProp(element, BAD_CAST "type");
	enum probe_type probe_type;


	if (type_prop!=NULL && STRCMP(type_prop, "remote")==0) {
		probe_type = PROBE_TYPE_REMOTE;
	} else if (type_prop!=NULL && STRCMP(type_prop, "interface")==0) {
		probe_type = PROBE_TYPE_INTERFACE;
	} else {
		fprintf(stderr, "[probes] Unknown probe type in neighbor cache.\n");
		xmlFree(type_prop);
		return -1;
	}
	xmlFree(type_prop);
	if (probe_type != probe->type) {
		fprintf(stderr, "[probes] Neighbor cache probe type does not match referenced probe type.\n");
		return -1;
	}
#endif

	if (probe->type == PROBE_TYPE_REMOTE && load_remote_neighbors==1) 
	{
		/* loading a message recieved from remote, so load addresses
		 * as we are not aware of them otherwise:
		 */
		xmlNodePtr address_child=element->children;
		xmlChar* mac_prop = xmlGetProp(element, BAD_CAST "mac");
		if (mac_prop!=NULL) 
		{
			struct ether_addr mac;
			ether_aton_r((char*)mac_prop, &mac);
			memcpy(&probe->ethernet_address, &mac, sizeof(struct ether_addr));
		}
		probe->addresses = NULL;
		while (address_child!=NULL) 
		{
			if ( (address_child->type == XML_ELEMENT_NODE) && (STRCMP(address_child->name, "address")==0)) 
			{
				struct in6_addr address;
				time_t current = time(NULL);

				inet_pton(AF_INET6, (char*) address_child->children->content, &address);
				addresses_add(&probe->addresses, &address, current, current);
			}
			address_child = address_child->next;
		}
	}

	if (probe->type == PROBE_TYPE_REMOTE && load_remote_neighbors==0) 
	{
		/* reading local neighbor cache, remote probe cache entries are
		 * just informational, do not load them: */
		return 0;
	}

	if (neighbor_list_load(element, &probe->neighbors) == -1) 
	{
		return -1;
	}
	return 0;
}

struct probe* probe_lock(const char* probe_name)
{
	struct probe_list* tmp_probes;

	pthread_mutex_lock(&probes_lock);
	tmp_probes = probes;
	while (tmp_probes!=NULL) 
	{
		if (strncmp(probe_name, tmp_probes->entry.name, PROBE_NAME_SIZE)==0) 
		{
			break;
		}
		tmp_probes = tmp_probes->next;
	}
	if (tmp_probes!=NULL) 
	{
		pthread_mutex_lock(&tmp_probes->lock);
		pthread_mutex_unlock(&probes_lock);
		return &tmp_probes->entry;
	}
	pthread_mutex_unlock(&probes_lock);
	return NULL;
}

#ifdef _COUNTERMEASURES_
int probe_list_add(char* const name, enum probe_type type,
        struct extinfo_list* const extinfo, neighbor_list_t* neighbors,
        router_list_t* routers, int cm_enabled)
#else
int probe_list_add(char* const name, enum probe_type type,
        struct extinfo_list* const extinfo, neighbor_list_t* neighbors,
        router_list_t* routers)
#endif
{
	struct probe_list* tmp_probes = probes;
	struct probe_list* new;

	while (tmp_probes!=NULL) 
	{
		if (strncmp(tmp_probes->entry.name, name, PROBE_NAME_SIZE)==0) 
		{
			fprintf(stderr, "[probes] ERROR: Probe with the given name %s already exists.", name);
			return -1;
		}
		tmp_probes = tmp_probes->next;
	}
	/* name not found, create probe: */
	if ((new=malloc(sizeof(struct probe_list)))==NULL) 
	{
		perror("[probes] malloc");
		return -1;
	}
	memset(new, 0, sizeof(struct probe_list));
	strlcpy(new->entry.name, name, PROBE_NAME_SIZE);
	new->entry.type = type;
#ifdef _COUNTERMEASURES_
	new->entry.cm_enabled = cm_enabled;
#endif
	new->entry.extinfo = extinfo;
	new->entry.neighbors = neighbors;
	new->entry.routers = routers;
	pthread_mutex_init(&new->lock, NULL);
	new->next = NULL;
	if (probes==NULL) 
	{
		/* if the list is empty, the entry will be the new list: */
		probes = new;
	} 
	else 
	{
		/* else walk to the end of the list and append: */
		tmp_probes = probes;
		while (tmp_probes->next != NULL) 
		{
			tmp_probes = tmp_probes->next;
		}
		tmp_probes->next = new;
	}
	return 0;
}


void probe_list_free()
{
	while (probes!=NULL) 
	{
		struct probe_list* current = probes;
		probes = probes->next;
		addresses_free(&current->entry.addresses);
		extinfo_list_free(&current->entry.extinfo);
		neighbors_free(&current->entry.neighbors);
		clean_routers(&current->entry.routers);
		free(current);
	}
}

const struct probe* probe_list_get(char* name)
{
	struct probe_list* tmp_probes=probes;

	while(tmp_probes!=NULL) 
	{
		if (strncmp(name, tmp_probes->entry.name, PROBE_NAME_SIZE)==0) 
		{
			return &tmp_probes->entry;
		}
		tmp_probes = tmp_probes->next;
	}
	return NULL;
}

int probe_list_load_config(xmlNodePtr element) 
{ 
	/* TODO extract probe_load() */
	xmlNodePtr probe_element = element->children;

	while (probe_element != NULL) 
	{
		if (probe_element->type == XML_ELEMENT_NODE
				&& (STRCMP(probe_element->name, "probe") == 0) )
		{
			char name[PROBE_NAME_SIZE];
			enum probe_type type;
#ifdef _COUNTERMEASURES_
			/* do not enable by default */
			int cm_enabled = 0;
#endif
			struct extinfo_list* extinfo = NULL;
			router_list_t* routers = NULL;

#ifdef _COUNTERMEASURES_
			if (probe_load_config(probe_element, name, &type, &extinfo, &routers, 0, &cm_enabled) == 1 )
#else
			if (probe_load_config(probe_element, name, &type, &extinfo, &routers, 0) == 1 )
#endif
			{
				return -1;
			}
#ifdef _COUNTERMEASURES_
			probe_list_add(name, type, extinfo, NULL, routers, cm_enabled);
#else
			probe_list_add(name, type, extinfo, NULL, routers);
#endif
		}
		probe_element = probe_element->next;
	}
	return 0;
}

int probe_list_load_neighbors(xmlNodePtr root_element)
{
	xmlNodePtr element = root_element->children;

	while (element!=NULL) 
	{
		if (element->type != XML_ELEMENT_NODE) 
		{
			element = element->next;
			continue;
		}

		/* XML element found, check if it is a probe reference: */
		if (STRCMP(element->name, "probe")==0) 
		{
			xmlChar* probe_name = xmlGetProp(element, BAD_CAST "name");
			struct probe* probe;

			probe = (struct probe*) probe_list_get((char*) probe_name);
			if (probe==NULL) 
			{
				fprintf(stderr, "[parser] ERROR: XML neighbor cache is refering to unknown probe name %s.\n", (char*) probe_name);
				return -1;
			}

			if (probe_load_neighbors(element, probe, 0)==-1) 
			{
				return -1;
			}

			xmlFree(probe_name);
		} 
		else 
		{
			fprintf(stderr, "[parser] WARNING: Unknown XML element %s\n", (char*) element->name);
		}

		element = element->next;
	}
	return 0;
}

struct probe_list** probe_list_lock()
{
	pthread_mutex_lock(&probes_lock);
	return &probes;
}

void probe_list_print()
{
	struct probe_list* tmp_probes=probes;
	fprintf(stderr, "[probes] All probes:\n");

	while(tmp_probes!=NULL) 
	{
		char ether_addr_str[ETH_ADDRSTRLEN];
		address_t* tmp_addresses=tmp_probes->entry.addresses;

		fprintf(stderr, "    ---- State information for probe %s ----\n", tmp_probes->entry.name);
		ether_ntoa_r(&tmp_probes->entry.ethernet_address, ether_addr_str);
		fprintf(stderr, "    Ethernet address: %s\n", ether_addr_str);
		while (tmp_addresses!=NULL) 
		{
			char in6_addr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &tmp_addresses->address, in6_addr_str, INET6_ADDRSTRLEN);
			fprintf(stderr, "    IPv6 address: %s\n", in6_addr_str);
			tmp_addresses = tmp_addresses->next;
		}
		print_routers(tmp_probes->entry.routers);
		print_neighbors(tmp_probes->entry.neighbors);
		extinfo_list_print(tmp_probes->entry.extinfo);
		tmp_probes = tmp_probes->next;
	}
}

int probe_list_save_config(xmlNodePtr element)
{
	/* TODO extract probe_save() */
	/* TODO have different version for ...save_config() and save_neighbors() */
	struct probe_list* tmp_probes=probes;

	while (tmp_probes!=NULL) 
	{
		xmlNodePtr probe_element;

		probe_element = xmlNewChild(element, NULL, BAD_CAST "probe", NULL);
		probe_save_config(probe_element, &tmp_probes->entry);
		tmp_probes = tmp_probes->next;
	}
	return 0;
}

int probe_list_save_neighbors(xmlNodePtr element)
{
	struct probe_list* tmp_probes=probes;

	while (tmp_probes!=NULL) 
	{
		xmlNodePtr probe_element;

		probe_element = xmlNewChild(element, NULL, BAD_CAST "probe", NULL);
		probe_save_neighbors(probe_element, &tmp_probes->entry);
		/* Here write the discovery stats down if the module is activated
		   need to addthe discovery path to the file in the probes structure def
		   need to add the module in the configure
		   and rewrite the scripts to generate the graphics
		   */
		tmp_probes = tmp_probes->next;
	}
	return 0;
}

void probe_list_send_down_event()
{
	struct probe_list* tmp_probes=probes;

	while (tmp_probes!=NULL) 
	{
		if (tmp_probes->entry.type == PROBE_TYPE_INTERFACE) 
		{
			fprintf(stderr, "Send down event...\n");
			probe_updown(PROBE_UPDOWN_STATE_DOWN, &tmp_probes->entry);
		}
		tmp_probes = tmp_probes->next;
	}
}

int probe_list_set_addresses()
{
	struct probe_list** locked_probes;
	struct probe_list* tmp_probes;

	locked_probes = probe_list_lock();
	tmp_probes = *locked_probes;
	while (tmp_probes!=NULL) 
	{
		if (probe_set_addresses(&tmp_probes->entry)==-1) 
		{
			probe_list_unlock();
			return -1;
		}
		tmp_probes = tmp_probes->next;
	}
	probe_list_unlock();
	return 0;
}

void probe_list_unlock()
{
	pthread_mutex_unlock(&probes_lock);
}

int probe_save_config(xmlNodePtr element, const struct probe* probe)
{
	xmlNodePtr routers_element;
	struct extinfo_list* extinfo = probe->extinfo;
#ifdef _COUNTERMEASURES_
	char cm_flag[2];

	/* size = 2 for int flag + \0 */
	snprintf(cm_flag, 2, "%d", probe->cm_enabled);
	xmlNewChild(element, NULL, BAD_CAST "countermeasures_enabled", BAD_CAST cm_flag );
#endif

	routers_element = xmlNewChild(element, NULL, BAD_CAST "routers", NULL);
	xmlNewProp(element, BAD_CAST "name", BAD_CAST probe->name);
	if (probe->type == PROBE_TYPE_INTERFACE) 
	{
		xmlNewProp(element, BAD_CAST "type", BAD_CAST "interface");
	} 
	else 
	{
		xmlNewProp(element, BAD_CAST "type", BAD_CAST "remote");
	}

	router_list_store(routers_element, probe->routers);
	if (extinfo_list_save(element, extinfo)==-1) 
	{
		return -1;
	}

	return 0;
}

int probe_save_neighbors(xmlNodePtr element, const struct probe* probe)
{
	char ether_addr_str[ETH_ADDRSTRLEN];
	address_t* tmp_addresses = probe->addresses;
	xmlChar* name_prop = xmlGetProp(element, BAD_CAST "name");

	if (name_prop==NULL) 
	{
		/* only if the name was not already saved by probe_save_config(): */
		xmlNewProp(element, BAD_CAST "name", BAD_CAST probe->name);
	}
	xmlFree(name_prop);
	ether_ntoa_r(&probe->ethernet_address, ether_addr_str);
	xmlNewProp(element, BAD_CAST "mac", BAD_CAST ether_addr_str);

	/* save addresses: */
	while (tmp_addresses!=NULL) 
	{
		char in6_addr_str[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &tmp_addresses->address, in6_addr_str, INET6_ADDRSTRLEN);
		xmlNewChild(element, NULL, BAD_CAST "address", BAD_CAST in6_addr_str);
		tmp_addresses = tmp_addresses->next;
	}

	/* save neighbors: */
	if (neighbor_list_save(element, probe->neighbors)==-1) 
	{
		return -1;
	}
	return 0;
}

int probe_set_addresses(struct probe* probe)
{
	struct ifaddrs* if_addresses;
	time_t current = time(NULL);

	if (probe->type==PROBE_TYPE_REMOTE) 
	{
		/* nothing to do: */
		return 0;
	}

	if (getifaddrs(&if_addresses)!=0) 
	{
		fprintf(stderr, "[probes] ERROR: setting interface addresses.\n");
		return -1;
	}

	while (if_addresses!=NULL) 
	{
		if (strcmp(if_addresses->ifa_name, probe->name)==0) 
		{
			/* found an address entry for the current interface: */
			if (if_addresses->ifa_addr->sa_family==AF_INET6) 
			{
				struct sockaddr_in6* inet6 = (struct sockaddr_in6*) if_addresses->ifa_addr;
				addresses_add(&probe->addresses,
						&inet6->sin6_addr ,
						current, current);
			} 
			else if (if_addresses->ifa_addr->sa_family==AF_PACKET) 
			{
				struct sockaddr_ll* linklayer = (struct sockaddr_ll*) if_addresses->ifa_addr;
				memcpy(&probe->ethernet_address, linklayer->sll_addr, sizeof(struct ether_addr));
			}

		}
		if_addresses = if_addresses->ifa_next;
	}
	freeifaddrs(if_addresses);
	return 0;
}

void probe_unlock(const char* probe_name)
{
	struct probe_list* tmp_probes;

	pthread_mutex_lock(&probes_lock);
	tmp_probes = probes;
	while (tmp_probes!=NULL) 
	{
		if (strncmp(probe_name, tmp_probes->entry.name, PROBE_NAME_SIZE)==0) 
		{
			break;
		}
		tmp_probes = tmp_probes->next;
	}
	if (tmp_probes!=NULL) 
	{
		pthread_mutex_unlock(&tmp_probes->lock);
	}
	pthread_mutex_unlock(&probes_lock);
}

void probe_updown(enum probe_updown_state state, struct probe* probe)
{
	union event_data* event = event_data_create();
	struct probe* probe_cp=&event->probe_updown.probe;

	if (state==PROBE_UPDOWN_STATE_UP) 
	{
		probe_copy(probe_cp, probe);
	} 
	else 
	{
		/* on probe down only the name is copied,
		 * all other fields were set to 0 by event_data_create().
		 */
		strlcpy(event->probe_updown.probe.name, probe->name, PROBE_NAME_SIZE);
	}

	/* decide which address will be used as a key for updates: */
	event->probe_updown.state = state;
	event_queue(EVENT_TYPE_PROBE_UPDOWN, event);
}

void probe_updown_free(union event_data** probe_updown)
{
	/* There are pointers to the:
	 *     - ethernet address list (old_macs)
	 *     - IPv6 address list (addresses)
	 * Those nested lists must be released.
	 */
	addresses_free(&(*probe_updown)->probe_updown.probe.addresses);
	extinfo_list_free(&(*probe_updown)->probe_updown.probe.extinfo);
	neighbors_free(&(*probe_updown)->probe_updown.probe.neighbors);
	clean_routers(&(*probe_updown)->probe_updown.probe.routers);
	free(*probe_updown);
	*probe_updown = NULL;
}

int probe_updown_save(xmlNodePtr element,
        const struct probe_updown_info* probe_updown)
{
	xmlNodePtr probe_element;

	probe_element = xmlNewChild(element, NULL, BAD_CAST "probe", NULL);
	/* save probe state: */
	if (probe_updown->state==PROBE_UPDOWN_STATE_UP) 
	{
		xmlNewChild(element, NULL, BAD_CAST "state", BAD_CAST "up");
		/* if UP: save probe state information: */
		probe_save_config(probe_element, &probe_updown->probe);
		probe_save_neighbors(probe_element, &probe_updown->probe);

	} 
	else 
	{
		xmlNewChild(element, NULL, BAD_CAST "state", BAD_CAST "down");
		xmlNewProp(probe_element, BAD_CAST "name", BAD_CAST probe_updown->probe.name);
	}

	return 0;
}
