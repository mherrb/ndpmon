#include "watchers.h"

struct watcher_list* watchers=NULL;

extern int DEBUG;

int watchers_add(char* name, watcher_type watcher, uint8_t icmp6_type_match, uint16_t watch_flags_match) 
{
    struct watcher_list* new_watcher;
    struct watcher_list* tmp_watcher;
    
    if ((new_watcher=malloc(sizeof(struct watcher_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    if ((new_watcher->name=malloc(WATCHER_NAME_SIZE))==NULL) {
        perror("malloc");
        return -1;
    }
    memset(new_watcher->name, 0, WATCHER_NAME_SIZE);
    strncpy(new_watcher->name, name, WATCHER_NAME_SIZE-1);
    new_watcher->watcher = watcher;
    new_watcher->icmp6_type_match = icmp6_type_match;
    new_watcher->watch_flags_match = watch_flags_match;
    new_watcher->next = NULL; /* terminate list*/
    /* this must be inserted in a weird way to have a FIFO list: */
    /* if the list is empty: */
    if (watchers==NULL) {
        watchers = new_watcher;
        return 0;
    }
    /* else we have to walk to the last entry... */
    tmp_watcher = watchers;
    while (tmp_watcher->next != NULL) {
        tmp_watcher = tmp_watcher->next;
    }
    /* ...and append the new entry to the list: */
    tmp_watcher->next = new_watcher;
    return 0;
}

int watchers_call(struct capture_info* const capture_info) 
{
    struct watcher_list* tmp_watcher=watchers;
    int packet_result = 0;
    int watchers_result = 0;

    capture_info->watch_flags = WATCH_FLAG_CONTINUE_CHECKING|WATCH_FLAG_STOP_ON_ERROR;
    while (tmp_watcher!=NULL) 
    {
        /* if there is an icmp type given and it does not match that of the packet, skip this watcher: */
        if (tmp_watcher->icmp6_type_match!=0 && tmp_watcher->icmp6_type_match != capture_info->icmp6_type) 
	{
            tmp_watcher = tmp_watcher->next;
            continue;
        }

        /* if there are any watch flags given and they are not set for the packet, skip this watcher: */
        if (tmp_watcher->watch_flags_match!=0 && !(watchers_flags_isset(capture_info->watch_flags, tmp_watcher->watch_flags_match))) 
	{
            tmp_watcher = tmp_watcher->next;
            continue;
        }

        if (DEBUG) 
	{
            fprintf(stderr, "[watchers] calling watcher \"%s\".\n", tmp_watcher->name);
        }

        watchers_result = tmp_watcher->watcher(capture_info);
        if (watchers_result > packet_result) 
	{
            /* only worse news cause update: */
            packet_result = watchers_result;
        }

	/* Stop if the watcher returned an error and WATCH_FLAG_STOP_ON_ERROR is set
	 */
	if( (watchers_result == 2) && watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_STOP_ON_ERROR) )
	{
		break;
	}

        tmp_watcher = tmp_watcher->next;
    }

    return packet_result;
}

int  watchers_flags_isset(const uint16_t flags, const uint16_t flags_to_check) 
{
    
    return ((flags&flags_to_check)==flags_to_check);
}

void watchers_flags_set(uint16_t *flags, const uint16_t flags_to_set) 
{
    
    (*flags) = (*flags)|flags_to_set;
}

void watchers_flags_unset(uint16_t *flags, const uint16_t flags_to_unset) 
{
    
    watchers_flags_set(flags, flags_to_unset);
    (*flags) = (*flags)^flags_to_unset;
}

void watchers_free() 
{
    struct watcher_list* tmp_watcher;
    
    while (watchers!=NULL) {
        tmp_watcher = watchers;
        watchers = watchers->next;
        free(tmp_watcher->name);
        free(tmp_watcher);
    }
}

char* watchers_icmp6_type_to_string(uint8_t icmp6_type) 
{
    switch (icmp6_type)
	{
		case ND_ROUTER_SOLICIT:
			return "ND_ROUTER_SOLICIT";
		case ND_ROUTER_ADVERT:
			return "ND_ROUTER_ADVERT";
		case ND_NEIGHBOR_SOLICIT:
			return "ND_NEIGHBOR_SOLICIT";
		case ND_NEIGHBOR_ADVERT:
			return "ND_NEIGHBOR_ADVERT";
		case ND_REDIRECT:
			return "ND_REDIRECT";
		default:
			return NULL;
	}
}

void watchers_print() 
{
    struct watcher_list* tmp_watcher=watchers;
    
    fprintf(stderr, "[watchers] all registered watchers: {\n");
    while (tmp_watcher!=NULL) {
        fprintf(stderr, "    %s:\n", tmp_watcher->name);
        if (tmp_watcher->icmp6_type_match!=0) {
            char* text = watchers_icmp6_type_to_string(tmp_watcher->icmp6_type_match);
            if (text==NULL) {
                fprintf(stderr, "        called only for ICMPv6 type: %u\n", tmp_watcher->icmp6_type_match);
            } else {
                fprintf(stderr, "        called only for ICMPv6 type: %s\n", text);
            }
        } else {
            fprintf(stderr, "        no ICMPv6 type specified.\n");
        }
        fprintf(stderr, "        called only if isset: [");
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_CONTINUE_CHECKING)) {
            fprintf(stderr, "CONTINUE_CHECKING ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_IS_IP6)) {
            fprintf(stderr, "IS_IP6 ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_IS_ICMP6)) {
            fprintf(stderr, "IS_ICMP6 ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_IS_NDP)) {
            fprintf(stderr, "IS_NDP ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_IP6_SRC_SPECIFIED)) {
            fprintf(stderr, "IP6_SRC_SPECIFIED ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_NEW_ETHERNET_ADDRESS)) {
            fprintf(stderr, "NEW_ETHERNET_ADDRESS ");
        }
        if (watchers_flags_isset(tmp_watcher->watch_flags_match, WATCH_FLAG_IS_LEGITIMATE_ROUTER)) {
            fprintf(stderr, "IS_LEGITIMATE_ROUTER ");
        }
        fprintf(stderr, "]\n");
        tmp_watcher = tmp_watcher->next;
    }
    fprintf(stderr, "}\n");
}

