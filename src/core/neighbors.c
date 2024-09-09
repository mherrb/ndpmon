
#include "neighbors.h"


/*********************************
IPv6 Addresses Handling
**********************************/

int addresses_add(address_t** addresses, const struct in6_addr* inet6_address,
        time_t firstseen, time_t lastseen)
{
    address_t* atmp=*addresses;
    address_t* new;

    if (IN6_IS_ADDR_MULTICAST(inet6_address)) {
         return -1;
     }
     if ((new = (address_t *) malloc(sizeof(struct address))) == NULL) {
         perror("malloc");
         return -1;
     }
     memcpy(&new->address, inet6_address, sizeof(struct in6_addr));
     new->firstseen = firstseen;
     new->lastseen = lastseen;
     /* keep list terminated: */
     new->next = NULL;
     /* append to the list: */
     if (atmp == NULL) {
         /* if the list is empty, the new address will be the new list: */
         *addresses = new;
     } else {
         /* walk to the end and append new address: */
         while (atmp->next != NULL)
             atmp = atmp->next;
         atmp->next = new;
     }
     return 0;
}

void addresses_free(address_t** addresses)
{

    while (*addresses!=NULL) {
        address_t* current=*addresses;
        *addresses = (*addresses)->next;
        free(current);

    }
}

int addresses_remove(address_t **addresses, const struct in6_addr* const addr)
{
    /* initialize two pointers to the address list: */
    address_t *atmp = *addresses; /* will be the current element */
    address_t *atmp2 = *addresses; /* will be the element before the current */

    /* search address: */
    while (atmp != NULL) {
        if (IN6_ARE_ADDR_EQUAL(addr,&(atmp->address))) {
            if (atmp == *addresses) {
                /* if this is the first element in the list: */
                *addresses = atmp->next;
                free(atmp);
                return 1;
            }
            /* somewhere else in the list: */
            atmp2->next = atmp->next;
            free(atmp);
            return 1;
        }
        if (atmp != *addresses) {
            /* only iterate atmp2 if we are not at the first element: */
            atmp2 = atmp2->next;
        }
        atmp = atmp->next;
    }
    return 0;
}

int neighbor_has_lla(const neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* lla)
{
    const neighbor_list_t *tmp = get_neighbor_by_mac(list, eth);

    if (tmp==NULL) {
        /* no such neighbor found: */
        return 0;
    }
    /* neighbor found, check for lla: */
    if (IN6_ARE_ADDR_EQUAL(lla,&(tmp->lla))) {
        return 1;
    }
    return 0;
}

int neighbor_has_ip(const neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* addr)
{
    const neighbor_list_t *tmp = get_neighbor_by_mac(list, eth);
    address_t *atmp;

    if (tmp == NULL) {
        /* no such neighbor found */
        return 0;
    }
    /* neighbor found, check for ipv6 global address: */
    atmp = tmp->addresses;
    while (atmp != NULL) {
        if (IN6_ARE_ADDR_EQUAL(addr,&(atmp->address))) {
            return 1;
        }
        atmp = atmp->next;
    }

    return 0;
}

int neighbor_ip_add(neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* addr)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);
    time_t current = time(NULL);
    int result;

    if (tmp == NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }
    if (IN6_IS_ADDR_MULTICAST(&addr)) {
        return 0;
    }
    result = addresses_add(&tmp->addresses, addr, current, current);
    return result;
}

int neighbor_ip_remove(neighbor_list_t *list, const struct ether_addr* eth,
        const struct in6_addr* addr)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);
    int result;

    if (tmp == NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }
    if (IN6_IS_ADDR_MULTICAST(&addr)) {
        return 0;
    }
    result = addresses_remove(&tmp->addresses, addr);
    return result;
}



int set_neighbor_lla(neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* lla)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);

    if (tmp == NULL) {
        /* no such neighbor found: */
        return 0;
    }
    /* the given neighbor was found, set lla: */
    memcpy(&tmp->lla, lla, sizeof(struct in6_addr));
    return 1;
}




/*********************************
Ethernet Addresses Handling
**********************************/

int ethernets_add(ethernet_t** ethernets, const struct ether_addr* address)
{
    ethernet_t* etmp=*ethernets;
    ethernet_t* new;

    if ((new = (ethernet_t *) malloc(sizeof(ethernet_t))) == NULL) {
         perror("malloc");
         return 0;
     }
     memcpy(&(new->mac), address, sizeof(struct ether_addr));
     /* keep the list terminated: */
     new->next = NULL;
     /* append new ethernet address to the list: */
     if (etmp == NULL) {
         *ethernets = new;
     } else {
         /* walk to the end of the list to keep ordering: */
         while (etmp->next != NULL)
             etmp = etmp->next;
         etmp->next = new;
     }
     return 0;
}

void ethernets_free(ethernet_t** ethernets)
{

    while (*ethernets!=NULL) {
        ethernet_t* current=*ethernets;
        *ethernets = (*ethernets)->next;
        free(current);

    }
}

int ethernets_remove(ethernet_t **ethernets, const struct ether_addr* eth)
{
    /* initialize two pointers to the old mac list: */
    ethernet_t* etmp  = *ethernets; /* will be current element*/
    ethernet_t* etmp2 = *ethernets; /* will be element before the current element */

    /* neighbor found, remove ethernet address: */
    while (etmp != NULL) {
        if (!MEMCMP(eth,&(etmp->mac), sizeof(struct ether_addr))) {
            if (etmp == *ethernets) {
                /* if this is the first ethernet address in the list:
                 * second element will be the new list, free first entry.
                 */
                *ethernets = etmp->next;
                free(etmp);
                return 1;
            }
            /* if this is not the first ethernet address in the list:
             * the current element is unlinked from the list and freed.
             */
            etmp2->next = etmp->next;
            free(etmp);
            return 1;
        }
        if (etmp != *ethernets) {
            /* if this is not the first iteration: */
            etmp2 = etmp2->next;
        }
        etmp = etmp->next;
    }
    return 0;
}

int neighbor_set_last_mac(neighbor_list_t *list, const struct in6_addr* const lla, const struct ether_addr* const eth)
{
	while(list != NULL)
	{
		if(IN6_ARE_ADDR_EQUAL(lla,&(list->lla)))
		{
			memcpy(&list->previous_mac, eth, sizeof(struct ether_addr));
			return 1;
		}
		list = list->next;
	}

	return 0;
}

struct ether_addr neighbor_get_last_mac(neighbor_list_t *list, struct in6_addr lla)
{
	neighbor_list_t *tmp = list;
	struct ether_addr ret;

	while(tmp != NULL)
	{
		if(IN6_ARE_ADDR_EQUAL(&lla,&(tmp->lla)))
		{
			return tmp->previous_mac;
		}
		tmp = tmp->next;
	}

	memcpy(&ret, ether_aton("11:11:11:11:11:11"), sizeof(struct ether_addr));

	return ret;
}

int neighbor_has_old_mac(const neighbor_list_t *list,
        const struct in6_addr* lla, const struct ether_addr* old_mac)
{
	const neighbor_list_t *tmp = get_neighbor_by_lla(list, lla);
	ethernet_t *etmp;

	if (tmp == NULL) 
	{
		/* neighbor with the given LLA not found: */
		return 0;
	}

	/* neighbor found, check for ethernet address: */
	etmp = tmp->old_mac;
	while (etmp != NULL) 
	{
#if 0
		/* another complex and not good looking way to do the checks */
		char ether_test[ETH_ADDRSTRLEN+1];
		char ether_test2[ETH_ADDRSTRLEN+1];
		const struct ether_addr * e = &(etmp->mac);
		sprintf(ether_test, "%02x:%02x:%02x:%02x:%02x:%02x", 
				(unsigned int)e->ether_addr_octet[0],
				(unsigned int)e->ether_addr_octet[1],
				(unsigned int)e->ether_addr_octet[2],
				(unsigned int)e->ether_addr_octet[3],
				(unsigned int)e->ether_addr_octet[4],
				(unsigned int)e->ether_addr_octet[5] );
		e = old_mac;
		sprintf(ether_test2, "%02x:%02x:%02x:%02x:%02x:%02x", 
				(unsigned int)e->ether_addr_octet[0],
				(unsigned int)e->ether_addr_octet[1],
				(unsigned int)e->ether_addr_octet[2],
				(unsigned int)e->ether_addr_octet[3],
				(unsigned int)e->ether_addr_octet[4],
				(unsigned int)e->ether_addr_octet[5] );
		fprintf(stderr, "Compare with %s %s !\n", ether_test, ether_test2 );
		if( !strncmp( ether_test, ether_test2, ETH_ADDRSTRLEN) )
			fprintf(stderr, "Woohoo they match !\n");
#endif
		if (!MEMCMP(old_mac,&(etmp->mac), sizeof(struct ether_addr))) 
		{
			return 1;
		}

		etmp = etmp->next;
	}

	return 0;
}

int neighbor_update_mac(neighbor_list_t *list, const struct in6_addr* lla,
        const struct ether_addr* new_mac)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_lla(list, lla);

    if (tmp == NULL) {
        /* neighbor with the given LLA not found: */
        return 0;
    }
    /* neighbor found, update MAC: */
    ethernets_add(&tmp->old_mac, &tmp->mac);
    ethernets_remove(&tmp->old_mac, new_mac);
    tmp->previous_mac = tmp->mac;
    memcpy(&tmp->mac, new_mac, sizeof(struct ether_addr));
#ifdef _MACRESOLUTION_
    strlcpy(tmp->vendor, get_manufacturer(manuf, new_mac), MANUFACTURER_NAME_SIZE);
#endif
    return 1;
}

#ifdef _MACRESOLUTION_
int set_neighbor_vendor(neighbor_list_t *list, const struct ether_addr* eth,
        const char * vendor)
{
	neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);

	if (tmp == NULL)
	{
		/* no such neighbor found: */
		return 0;
	}

	/* the given neighbor was found, set vendor: */
	memcpy(&tmp->vendor, vendor, MANUFACTURER_NAME_SIZE);
	return 1;

}
#endif



/*********************************
Timers
**********************************/

int reset_neighbor_address_timer(neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* addr)
{
    time_t current= time(NULL);

    return set_neighbor_address_timer(list, eth, addr, current);
}

int set_neighbor_address_timer(neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* addr, time_t value)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);
    address_t *atmp;

    if (tmp == NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }
    /* given neighbor found, search address: */
    atmp = tmp->addresses;
    while (atmp != NULL) {
        if (IN6_ARE_ADDR_EQUAL(addr,&(atmp->address))) {
            /* set the timer to the given value: */
            atmp->lastseen = value;
            return 1;
        }
        atmp = atmp->next;
    }
    /* the given ipv6 address was not found: */
    return 0;
}

int set_neighbor_first_address_timer(neighbor_list_t *list, const struct ether_addr* eth, const struct in6_addr* addr, time_t value)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);
    address_t *atmp;

    if (tmp == NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }
    atmp = tmp->addresses;
    while (atmp != NULL) {
        if (IN6_ARE_ADDR_EQUAL(addr,&(atmp->address))) {
            /* set the timer to the given value: */
            atmp->lastseen = value;
            return 1;
        }
        atmp = atmp->next;
    }
    /* the given ipv6 address was not found: */
    return 0;
}

int reset_neighbor_timer(neighbor_list_t *list, const struct ether_addr* eth, const struct probe* probe)
{
    char buffer[NOTIFY_BUFFER_SIZE];
    char str_ip[IP6_STR_SIZE];
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);
    time_t current = time(NULL);

    if (tmp==NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }

    /* neighbor with the given ethernet address found, reset timer: */
    if(difftime(current, tmp->timer) > 6*30*DAY_TIME) {
        /* if the station has been inactive for a long time (6 months): */
        inet_ntop(AF_INET6, &tmp->lla, str_ip, INET6_ADDRSTRLEN);
        snprintf (buffer, NOTIFY_BUFFER_SIZE, "new activity from: %s %s", ether_ntoa((struct ether_addr*)(&(tmp->mac))),str_ip);
        alert_raise(1, probe, "new activity", buffer, eth, NULL, &tmp->lla,NULL);
    }
    tmp->timer = current;
    return 1;
}

int set_neighbor_timer(neighbor_list_t *list, const struct ether_addr* eth, time_t value)
{
    neighbor_list_t *tmp = (neighbor_list_t*) get_neighbor_by_mac(list, eth);

    if (tmp==NULL) {
        /* no neighbor with the given ethernet address found: */
        return 0;
    }
    /* neighbor with the given ethernet address found, set timer: */
    tmp->timer = value;
	return 1;
}





/*********************************
List Handling
**********************************/

#if 0
unused
int del_neighbor(neighbor_list_t **list, const struct ether_addr* eth)
{
	neighbor_list_t *tmp = *list, *tmp2 = *list;

	if(!is_neighbor_by_mac(*list,eth))
	{
		fprintf(stderr,"neighbor not in list\n");
		return 0;
	}

	while(tmp != NULL)
	{
		if(!memcmp(&eth,&(tmp->mac), sizeof(struct ether_addr)))
		{
			if(tmp == *list)
			{
				/* if it is the first item in the list */
				*list = tmp->next;
				free(tmp);
				return 1;
			}
			/* else the previous item point to the following one */
			tmp2->next = tmp->next;
			free(tmp);
			return 1;
		}
		/* if it is not the first item, go to the next one */
		if(!(tmp==*list))
			tmp2=tmp2->next;

		tmp = tmp->next;
	}
	/* should never happen */
	return 0;
}
#endif

int add_neighbor(neighbor_list_t **list, const struct ether_addr* eth)
{
	neighbor_list_t *tmp = *list;
	neighbor_list_t *new = NULL;

	if(is_neighbor_by_mac(*list,eth))
	{
		fprintf(stderr,"Neighbor already in list %s\n", ether_ntoa(eth));
		return 0;
	}

	new=(neighbor_list_t *)malloc(sizeof(neighbor_list_t));
	/*if( (new=(neighbor_list_t *)malloc(sizeof(neighbor_list_t))) == NULL)*/
	if( new == NULL)
	{
		perror("malloc");
		return 0;
	}

	memcpy(&new->mac, eth, sizeof(struct ether_addr));
/* ADDED */
	memcpy(&new->first_mac_seen, eth, sizeof(struct ether_addr));
        new->trouble = 0;
/* END ADDED */
#ifdef _MACRESOLUTION_
	strlcpy(new->vendor, get_manufacturer(manuf, eth), MANUFACTURER_NAME_SIZE);
#endif
	new->old_mac = NULL;
	new->lla  = in6addr_any;
	new->addresses = NULL;
	new->timer = time(NULL);
	new->next = NULL;
	new->extinfo = NULL;

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


int is_neighbor_by_mac(const neighbor_list_t* list, const struct ether_addr* eth)
{
    if (get_neighbor_by_mac(list, eth)!=NULL) {
        return 1;
    }
    return 0;
}

int is_neighbor_by_lla(const neighbor_list_t* list, const struct in6_addr* lla)
{
    if (get_neighbor_by_lla(list, lla)!=NULL) {
        return 1;
    }
    return 0;
}

int is_neighbor_by_ip(const neighbor_list_t *list, const struct in6_addr* addr)
{
    if (get_neighbor_by_ip(list, addr)!=NULL) {
        return 1;
    }
    return 0;
}

const neighbor_list_t * get_neighbor_by_mac(const neighbor_list_t *list, const struct ether_addr* eth)
{

    while(list != NULL) {
        if(!MEMCMP(eth,&(list->mac), sizeof(struct ether_addr))) {
            return list;
        }
        list = list->next;
    }
    return NULL;
}

const neighbor_list_t * get_neighbor_by_lla(const neighbor_list_t *list, const struct in6_addr* lla)
{

    while(list != NULL) {
        if(IN6_ARE_ADDR_EQUAL(lla,&(list->lla))) {
            return list;
        }
        list = list->next;
    }
    return NULL;
}

const neighbor_list_t * get_neighbor_by_ip(const neighbor_list_t *list, const struct in6_addr* addr)
{

    while (list != NULL) {
        address_t *atmp = list->addresses;
        while (atmp != NULL) {
            if (IN6_ARE_ADDR_EQUAL(addr,&(atmp->address)))
                return list;

            atmp = atmp->next;
        }
        list = list->next;
    }
    return NULL;
}

int nb_neighbor(neighbor_list_t *neighbors)
{
	int n = 0;
	neighbor_list_t *tmp = neighbors;

	while(tmp != NULL)
	{
		n++;
		tmp=tmp->next;
	}

	return n;
}

int neighbors_free(neighbor_list_t **list)
{
	neighbor_list_t *tmp = *list, *ntodel = NULL;

	while(tmp != NULL)
	{
		ntodel = tmp;
		addresses_free(&tmp->addresses);
		ethernets_free(&tmp->old_mac);
		extinfo_list_free(&tmp->extinfo);
		tmp = tmp->next;
		free(ntodel);
	}

	return 1;
}




/*********************************
Serialization
**********************************/

void print_neighbors(neighbor_list_t *list)
{
	neighbor_list_t *tmp = list;
	while(tmp != NULL)
	{
		char eth[ETH_ADDRSTRLEN], first_eth[ETH_ADDRSTRLEN], lla[INET6_ADDRSTRLEN];
		address_t *atmp = tmp->addresses;
		ethernet_t *etmp = tmp->old_mac;

		inet_ntop(AF_INET6, &tmp->lla, lla, INET6_ADDRSTRLEN);
		strlcpy(eth,ether_ntoa(&(tmp->mac)), ETH_ADDRSTRLEN);
		strlcpy(first_eth,ether_ntoa(&(tmp->first_mac_seen)), ETH_ADDRSTRLEN);
		fprintf(stderr,"    Neighbor (%s,%s,%s,%ld):\n", eth, first_eth, lla, tmp->timer);
		if(atmp != NULL)
		{
			fprintf(stderr,"        IPv6 Global Addresses:\n");
			while(atmp != NULL)
			{
				char addr[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &atmp->address, addr, INET6_ADDRSTRLEN);
				fprintf(stderr,"            %s\n", addr);
				atmp=atmp->next;
			}
		}
		if(etmp != NULL)
		{
			fprintf(stderr,"    Old MAC Addresses:\n");
			while(etmp != NULL)
			{
				char addr[ETH_ADDRSTRLEN+1];
				strlcpy(addr,ether_ntoa(&(etmp->mac)), ETH_ADDRSTRLEN);
				fprintf(stderr,"    %s\n", addr);
				etmp=etmp->next;
			}
		}
		fprintf(stderr,"\n");
		tmp=tmp->next;
	}
}

int neighbor_load(xmlNodePtr element, neighbor_list_t* new_neighbor)
{
	xmlNodePtr neighbor_child = element->children;
	struct in6_addr lla;
	struct ether_addr* temp = NULL;
#ifdef _MACRESOLUTION_
	xmlChar* mac_vendor;
#endif

	memset(new_neighbor, 0, sizeof(neighbor_list_t));
	memset(&lla, 0, sizeof(struct in6_addr));

	while (neighbor_child != NULL)
	{

		if (neighbor_child->type != XML_ELEMENT_NODE)
		{
			neighbor_child = neighbor_child->next;
			continue;
		}

		if (STRCMP(neighbor_child->name, "mac")==0)
		{
			temp = ether_aton((char*) neighbor_child->children->content);
			if (temp == NULL)
			{
				fprintf( stderr, "[neighbors] ERROR: Invalid mac %s parsing neighbor cache.\n",	(char*) neighbor_child->children->content);
				return -1;
			}

			memcpy(&new_neighbor->mac, temp, sizeof(struct ether_addr));

#ifdef _MACRESOLUTION_
			/* MAC RESOLUTION: Parse the vendor */
			mac_vendor = xmlGetProp(neighbor_child, BAD_CAST "vendor");
			memcpy(&new_neighbor->vendor, mac_vendor, MANUFACTURER_NAME_SIZE);
#endif
		} 
		else if (STRCMP(neighbor_child->name, "first_mac_seen")==0)
		{
			temp = ether_aton((char*) neighbor_child->children->content);
			if (temp == NULL)
			{
				fprintf( stderr, "[neighbors] ERROR: Invalid mac %s parsing neighbor cache.\n",	(char*) neighbor_child->children->content);
				return -1;
			}

			memcpy(&(new_neighbor->first_mac_seen), temp, sizeof(struct ether_addr));
		} 
		else if (STRCMP(neighbor_child->name, "lla") == 0)
		{
			inet_pton(AF_INET6, (char*) neighbor_child->children->content, &new_neighbor->lla);
		}
		else if (STRCMP(neighbor_child->name, "lastseen") == 0)
		{
			new_neighbor->timer = atoi((char*) neighbor_child->children->content);
		}
		else if (STRCMP(neighbor_child->name, "addresses") == 0)
		{
			xmlNodePtr address = neighbor_child->children;

			while (address != NULL)
			{
				xmlChar* firstseen = NULL;
				xmlChar* lastseen = NULL;
				struct in6_addr ipv6_address;

				if (address->type != XML_ELEMENT_NODE
						|| STRCMP(address->name, "address") != 0)
				{
					/* skip other DOM content: */
					address = address->next;
					continue;
				}
				/* we have an address XML element: */
				inet_pton(AF_INET6, (char*) address->children->content, &ipv6_address);
				firstseen = xmlGetProp(address, BAD_CAST"firstseen");
				lastseen = xmlGetProp(address, BAD_CAST "lastseen");
				/* load values in neighbor cache: */
				addresses_add(&new_neighbor->addresses, &ipv6_address, atoi((char*)firstseen), atoi((char*)lastseen));
				xmlFree(firstseen);
				xmlFree(lastseen);
				address = address->next;
			}
		} 
		else if (STRCMP(neighbor_child->name, "old_macs")==0)
		{
			xmlNodePtr old_mac = neighbor_child->children;

			while (old_mac!=NULL)
			{
				xmlChar* temp_last_mac=NULL;
				struct ether_addr* temp=NULL;

				if (old_mac->type != XML_ELEMENT_NODE || STRCMP(old_mac->name, "mac") != 0)
				{
					/* skip other DOM content: */
					old_mac = old_mac->next;
					continue;
				}

				/* we have a mac element: */
				temp = ether_aton((char*)old_mac->children->content);
				if (temp==NULL)
				{
					fprintf(stderr, "[neighbors] Invalid mac %s parsing neighbor cache.\n", (char*)old_mac->children->content);
				}
				ethernets_add(&(new_neighbor->old_mac), temp);

				/* Was it the alst mac used ? */
				if ((temp_last_mac = xmlGetProp(old_mac, BAD_CAST "last"))!=NULL)
				{
					memcpy(&new_neighbor->previous_mac, temp, sizeof(struct ether_addr));
				}
				old_mac = old_mac->next;
			}
		}
		neighbor_child = neighbor_child->next;
	}

	extinfo_list_load(element, &new_neighbor->extinfo);

	return 0;
}

int neighbor_list_load(xmlNodePtr element, neighbor_list_t **list)
{
	xmlNodePtr neighbor=element->children;

	while (neighbor!=NULL) 
	{
		if (neighbor->type!=XML_ELEMENT_NODE) 
		{
			neighbor = neighbor->next;
			continue;
		}

		/* found XML element, check for "neighbor": */
		if (STRCMP(neighbor->name, "neighbor")==0) 
		{
			neighbor_list_t new_neighbor;
			neighbor_list_t* new_neighbor_entry;
#if 0
			ethernet_t * old_macs;
#endif
			if (neighbor_load(neighbor, &new_neighbor)==-1) 
			{
				return -1;
			}
			add_neighbor(list, &new_neighbor.mac);
			new_neighbor_entry = (neighbor_list_t*) get_neighbor_by_mac(*list,&new_neighbor.mac);
			/* copy first mac seen otherwise it takes the current one */
    			memcpy(&(new_neighbor_entry->first_mac_seen), &(new_neighbor.first_mac_seen), sizeof(struct ether_addr));
#ifdef _MACRESOLUTION_
			set_neighbor_vendor(*list, &new_neighbor.mac, (const char*)&new_neighbor.vendor);
#endif
			set_neighbor_lla(*list, &new_neighbor.mac, &new_neighbor.lla);
			set_neighbor_timer(*list, &new_neighbor.mac, new_neighbor.timer);
			neighbor_set_last_mac(*list, &new_neighbor.lla, &new_neighbor.previous_mac);
			if (new_neighbor_entry==NULL) 
			{
				/* should never happen: */
				return -1;
			}

			new_neighbor_entry->addresses = new_neighbor.addresses;
			new_neighbor_entry->old_mac   = new_neighbor.old_mac;
#if 0
/* wotks as well but more complex */
old_macs = new_neighbor.old_mac;
while(old_macs != NULL)
{
	ethernets_add(&(new_neighbor_entry->old_mac), &(old_macs->mac) );
	old_macs = old_macs->next;
}
#endif
		}
		neighbor = neighbor->next;
	}
	return 0;
}

int neighbor_save(xmlNodePtr neighbor_element, const neighbor_list_t* list)
{
	char lla_str[INET6_ADDRSTRLEN];
	char timer_str[TIME_STR_SIZE];
	xmlNodePtr addresses_element;
	xmlNodePtr old_macs_element;
	xmlNodePtr lastseen_element;
	address_t* addresses = list->addresses;
	ethernet_t* old_macs = list->old_mac;
	struct extinfo_list* extinfo = list->extinfo;

#ifdef _MACRESOLUTION_
	xmlNodePtr mac_element;

	mac_element = xmlNewChild(neighbor_element, NULL, BAD_CAST "mac", BAD_CAST ether_ntoa(&list->mac));
	/* Add the mac vendor element */
	xmlNewProp(mac_element, BAD_CAST "vendor", BAD_CAST list->vendor);
#endif

	xmlNewChild(neighbor_element, NULL, BAD_CAST "first_mac_seen", BAD_CAST ether_ntoa(&(list->first_mac_seen)));
	inet_ntop(AF_INET6, &list->lla, lla_str, INET6_ADDRSTRLEN);
	xmlNewChild(neighbor_element, NULL, BAD_CAST "lla", BAD_CAST lla_str);

	/* When was it seen last */
	snprintf(timer_str, TIME_STR_SIZE, "%i", (int) list->timer);
	lastseen_element = xmlNewChild(neighbor_element, NULL, BAD_CAST "lastseen", BAD_CAST timer_str);
	/* Text version for WEB interface */
	snprintf(timer_str, TIME_STR_SIZE, "%s", ctime(&(list->timer)));
	xmlNewProp(lastseen_element, BAD_CAST "lastseenstr", BAD_CAST timer_str);

	addresses_element = xmlNewChild(neighbor_element, NULL, BAD_CAST "addresses", NULL);
	while (addresses!=NULL) 
	{
		char ipv6_str[INET6_ADDRSTRLEN];
		char firstseen_str[TIME_STR_SIZE];
		char lastseen_str[TIME_STR_SIZE];
		xmlNodePtr address_element;

		inet_ntop(AF_INET6, &addresses->address, ipv6_str, INET6_ADDRSTRLEN);
		address_element = xmlNewChild(addresses_element, NULL, BAD_CAST "address", BAD_CAST ipv6_str);

		/* when was it seen first ? */
		snprintf(firstseen_str, TIME_STR_SIZE, "%i", (int) addresses->firstseen);
		xmlNewProp(address_element, BAD_CAST "firstseen", BAD_CAST firstseen_str);
		/* Text version for WEB interface */
		snprintf(firstseen_str, TIME_STR_SIZE, "%s", ctime(&(addresses->firstseen)));
		xmlNewProp(address_element, BAD_CAST "firstseenstr", BAD_CAST firstseen_str);


		/* when was it seen last ? */
		snprintf(lastseen_str, TIME_STR_SIZE, "%i", (int) addresses->lastseen);
		xmlNewProp(address_element, BAD_CAST "lastseen", BAD_CAST lastseen_str);
		/* Text version for WEB interface */
		snprintf(lastseen_str, TIME_STR_SIZE, "%s", ctime(&(addresses->lastseen)));
		xmlNewProp(address_element, BAD_CAST "lastseenstr", BAD_CAST lastseen_str);

		addresses = addresses->next;
	}

	/* Need to check here
	 * expected to add mac_element in loop in old_macs_element and not neighbor elemen
	 */
	old_macs_element = xmlNewChild(neighbor_element, NULL, BAD_CAST "old_macs", NULL);
	while (old_macs!=NULL) 
	{
		xmlNodePtr mac_element;
		mac_element = xmlNewChild(old_macs_element, NULL, BAD_CAST "mac", BAD_CAST ether_ntoa(&old_macs->mac));
		/* was it the alst used mac address ? */
		if (!MEMCMP(&(old_macs->mac),&(list->previous_mac), sizeof(struct ether_addr)))
		{
			/* Add the attribute */
			xmlNewProp(mac_element, BAD_CAST "last", BAD_CAST "true");
		}
		old_macs = old_macs->next;
	}
	while (extinfo!=NULL) {
		const struct extinfo_type* const extinfo_type = extinfo->type;
		xmlNodePtr extinfo_element = xmlNewChild(neighbor_element, NULL, BAD_CAST extinfo_type->name, NULL);

		if ((extinfo_type->handler_xml_save)(extinfo_element, extinfo->data)==-1) {
			fprintf(stderr,
					"[neighbors] ERROR: Could not save extinfo information %s for neighbor %s.\n",
					extinfo_type->name, ether_ntoa(&list->mac));
			return -1;
		}
		extinfo = extinfo->next;
	}
	return 0;
}

int neighbor_list_save(xmlNodePtr element, const neighbor_list_t *list)
{

    while (list!=NULL) {
        xmlNodePtr neighbor_element = xmlNewChild(element, NULL, BAD_CAST "neighbor", NULL);
        if (neighbor_save(neighbor_element, list)==-1) {
            return -1;
        }
        list = list->next;
    }
    return 0;
}

void neighbor_copy(neighbor_list_t* destination, const neighbor_list_t* source)
{
    ethernet_t* ethernet_copy = NULL;
    ethernet_t* ethernet_tmp = source->old_mac;
    address_t* addresses_copy = NULL;
    address_t* addresses_tmp = source->addresses;

    memset(destination, 0, sizeof(neighbor_list_t));
    destination->timer = source->timer;
    destination->extinfo = NULL; /* TODO copy extinfo? */
    /* copy shallow values: */
    memcpy(&destination->mac, &source->mac, sizeof(struct ether_addr));
    memcpy(&destination->first_mac_seen, &source->first_mac_seen,
            sizeof(struct ether_addr));
    memcpy(&destination->previous_mac, &source->previous_mac,
            sizeof(struct ether_addr));
    memcpy(&destination->lla, &source->lla, sizeof(struct in6_addr));
    /* copy ethernet address list: */
    while (ethernet_tmp != NULL) {
        ethernets_add(&ethernet_copy, &ethernet_tmp->mac);
        ethernet_tmp = ethernet_tmp->next;
    }
    destination->old_mac = ethernet_copy;
    /* copy ip6 address list: */
    while (addresses_tmp != NULL) {
        addresses_add(&addresses_copy, &addresses_tmp->address,
                addresses_tmp->firstseen, addresses_tmp->lastseen);
        addresses_tmp = addresses_tmp->next;
    }
    destination->addresses = addresses_copy;
    destination->next = NULL;
}

void neighbor_update(char* probe_name,
        const struct ether_addr* const key_mac,
        const struct in6_addr* const key_lla, const neighbor_list_t* neighbor)
{
    /* the neighbors data must be copied for thread safety: */
    union event_data* event = event_data_create();
    neighbor_list_t* neighbor_cp=&event->neighbor_update.neighbor;

    neighbor_copy(neighbor_cp, neighbor);
    /* retrieve the probes name: */
    strlcpy(event->neighbor_update.probe_name, probe_name, PROBE_NAME_SIZE);

    /* decide which address will be used as a key for updates: */
    if (key_lla!=NULL) {
        event->neighbor_update.key_type = NEIGHBOR_UPDATE_KEY_TYPE_LLA;
    } else if (key_mac!=NULL) {
        event->neighbor_update.key_type = NEIGHBOR_UPDATE_KEY_TYPE_ETHERNET;
    } else {
        event->neighbor_update.key_type = NEIGHBOR_UPDATE_KEY_TYPE_NONE;
    }
    event_queue(EVENT_TYPE_NEIGHBOR_UPDATE, event);

}

void neighbor_update_free(union event_data** neighbor_update)
{
    /* There are pointers to the:
     *     - ethernet address list (old_macs)
     *     - IPv6 address list (addresses)
     * Those nested lists must be released.
     */
    ethernets_free(&(*neighbor_update)->neighbor_update.neighbor.old_mac);
    addresses_free(&(*neighbor_update)->neighbor_update.neighbor.addresses);
    free(*neighbor_update);
    *neighbor_update = NULL;
}

int neighbor_update_save(xmlNodePtr element, const struct neighbor_update_info* neighbor_update)
{
     xmlNodePtr neighbor_element;
     xmlNodePtr key_element;

     xmlNewChild(element, NULL, BAD_CAST "probe", BAD_CAST neighbor_update->probe_name);
     /* save key for update actions: */
     if (neighbor_update->key_type==NEIGHBOR_UPDATE_KEY_TYPE_LLA) {
         key_element = xmlNewChild(element, NULL, BAD_CAST "key", NULL);
         xmlNewProp(key_element, BAD_CAST "type", BAD_CAST "lla");
     } else if (neighbor_update->key_type==NEIGHBOR_UPDATE_KEY_TYPE_ETHERNET) {
         key_element = xmlNewChild(element, NULL, BAD_CAST "key", NULL);
         xmlNewProp(key_element, BAD_CAST "type", BAD_CAST "ethernet");
     } else {
         key_element = xmlNewChild(element, NULL, BAD_CAST "key", NULL);
         xmlNewProp(key_element, BAD_CAST "type", BAD_CAST "none");
     }

     /* save neighbor data: */
     neighbor_element = xmlNewChild(element, NULL, BAD_CAST "neighbor", NULL);
     neighbor_save(neighbor_element, &neighbor_update->neighbor);
     return 0;
}

