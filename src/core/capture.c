#include "capture.h"

/* WARNING
 * Need to treat differently option headers with fixed and dynamic lenght
 * For dynamic ones, do a malloc based on the lenght field in the option header
 * For fixed, sizeof(struct nd_option_list) is fine
 * WARNING */
int capture_nd_option_list_add(struct nd_option_list** option_list, const struct nd_opt_hdr* const opt) 
{
	struct nd_option_list* tmp_list;
	struct nd_option_list* new;

	/* RDNSS and DNSSL option header size varies
	 * malloc and memset to 0 based on header length by adding size of the NS or domain length
	 **/
	if( (opt->nd_opt_type == ND_OPT_RDNSS) || (opt->nd_opt_type == ND_OPT_DNSSL) ) 
	{
		if ( (new = malloc(sizeof(struct nd_option_list) + ((opt->nd_opt_len-1) * 8) ) ) == NULL)
		{
			perror("malloc");
			return -1;
		}
		memset(new, 0, sizeof(struct nd_option_list)+ ((opt->nd_opt_len-1) * 8) );
	}
	else
	{
		if ((new = malloc(sizeof(struct nd_option_list))) == NULL) 
		{
			perror("malloc");
			return -1;
		}
		memset(new, 0, sizeof(struct nd_option_list));
	}

	new->next = NULL;
	switch (opt->nd_opt_type) 
	{
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
			memcpy(&new->option_data, opt, sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr));
			break;

		case ND_OPT_PREFIX_INFORMATION:
			memcpy(&new->option_data, opt, sizeof(struct nd_opt_prefix_info));
			break;

		case ND_OPT_MTU:
			memcpy(&new->option_data, opt, sizeof(struct nd_opt_mtu));
			break;

		case ND_OPT_RDNSS:
			memcpy(&new->option_data, opt, opt->nd_opt_len * 8);
			break;

		case ND_OPT_DNSSL:
			memcpy(&new->option_data, opt, opt->nd_opt_len * 8);
			break;

		case ND_OPT_ROUTE_INFORMATION:
			memcpy(&new->option_data, opt, sizeof(struct nd_opt_route_info));
			break;


		default:
			if (DEBUG) 
			{
				fprintf(stderr, "[capture] unknown option type %u, ignoring option.\n",	opt->nd_opt_type);
			}
	}

	if (*option_list == NULL) 
	{
		*option_list = new;
	} 
	else 
	{
		/* if the list is not empty walk to the end to keep ordering: */
		tmp_list = *option_list;
		while (tmp_list->next != NULL) 
		{
			tmp_list = tmp_list->next;
		}

		tmp_list->next = new;
	}

	return 0;
}

void capture_nd_option_list_free(struct nd_option_list** option_list) 
{
	while (*option_list!=NULL) 
	{
		struct nd_option_list* current=*option_list;
		*option_list = (*option_list)->next;
		free(current);
	}
}


/** Processes a captured packet and calls the watch functions if the captured packet is an ICMPv6 packet.
    @param interface     The interface the packet was captured on.
    @param packet_data   Pointer to the content of the packet.
    @param packet_length Length of the packet content.
    @return              The return value of watchers_call() (0 if OK, 1 if
                         low and 2 if high priority alert).
*/
int capture_process_packet(struct probe* probe, const struct timeval* timestamp, uint8_t* packet_data, int packet_length) 
{
	/* stores the result of the watcher calls: */
	int packet_result;
	/* to make accessing ip6 information easier: */
	struct capture_info  capture_info;
	/* pre-initialize a buffer for storing alerts: */
	char message[NOTIFY_BUFFER_SIZE];

	memset(&capture_info, 0, sizeof(struct capture_info));
	memset(&message, 0, NOTIFY_BUFFER_SIZE);
	capture_info.probe = probe;
	capture_info.message = message;
	capture_info.packet_data = packet_data;
	capture_info.packet_length = packet_length;

#ifdef _COUNTERMEASURES_
	/* if (cm_on_link_remove(packet, hdr->len)!=0) { */
	if (cm_on_link_remove(capture_info.packet_data, capture_info.packet_length)!=0) 
	{
		fprintf(stderr,"---- ICMP packet ----\n");
		fprintf(stderr, "[countermeasures]: Packet dropped as it is a NDPMon counter measure.\n");
		fprintf(stderr,"------------------\n\n");
		return 0;
	}
#endif
	/* Call watch functions: */
	packet_result = watchers_call(&capture_info);
	/* Free neighbor discovery option list: */
	capture_nd_option_list_free((struct nd_option_list**)&capture_info.option_list);

	fprintf(stderr,"------------------\n\n");

	sched_yield();
	return packet_result;
}
