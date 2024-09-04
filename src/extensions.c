#include "extensions.h"

int extensions_register_handlers() 
{
	/* The alert handlers are called in the same order as you add them here.
	 * So the order in which the actions are taken may be tuned here.
	 * Core handlers:
	 */
	event_handler_add("std_pipe_program", alert_handler_std_pipe_program);
	event_handler_add("std_sendmail",     alert_handler_std_sendmail);
	event_handler_add("std_syslog",       alert_handler_std_syslog);
	event_handler_add("std_xml_append",   alert_handler_std_xml_append);
	event_handler_add("std_save_cache",   parser_handler_std_save_cache);

#ifdef _SOAP_
	/* Soap handlers: */
	event_handler_add("soap",             soap_event_handler);
#endif

#ifdef _WEBINTERFACE_
	event_handler_add("webinterface",     wi_export_handler);
#endif
	return 0;
}

int extensions_register_types() 
{
	if (extinfo_type_list_add("last_dad_address", last_dad_address_free, NULL, NULL, NULL)!=0) return -1;
#ifdef _RULES_
	if (extinfo_type_list_add("rules", rule_list_free, rule_list_print, rule_list_load, rule_list_save)!=0) return -1;
#endif
#ifdef _SOAP_
	if (extinfo_type_list_add("soap", soap_settings_free, soap_settings_print, soap_settings_load, soap_settings_save)!=0) return -1;
#endif
	return 0;
}

int extensions_register_watchers() 
{
	/* Here all watch functions are registered. Their ordering is important! The first watch function registered will be the
	   the first to be called for a captured packet.
	   */
	/* Prepare information for the packet: */
	if (watchers_add("watch_prepare_ethernet", &watch_prepare_ethernet, 0, WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;
	if (watchers_add("watch_prepare_inet6",    &watch_prepare_inet6,    0, WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_IP6)!=0) return -1;
	if (watchers_add("watch_prepare_icmp6",    &watch_prepare_icmp6,    0, WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_ICMP6)!=0) return -1;
	if (watchers_add("watch_prepare_nd",       &watch_prepare_nd,       0, WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;

	/* General checks, only for ND packets: */
	if (watchers_add("watch_eth_mismatch",  &watch_eth_mismatch,  0,      WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;
	if (watchers_add("watch_eth_broadcast", &watch_eth_broadcast, 0,      WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;
	if (watchers_add("watch_ip_broadcast", &watch_ip_broadcast,   0,      WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;
	if (watchers_add("watch_bogon", &watch_bogon,                 0,      WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;
	if (watchers_add("watch_hop_limit", &watch_hop_limit,         0,      WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IS_NDP)!=0) return -1;

	/* Router Solicitation checks: */
	if (watchers_add("new_station", &new_station,   ND_ROUTER_SOLICIT,    WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IP6_SRC_SPECIFIED)!=0) return -1;

	/* Router Advertisement checks: */
	/* 
	 * Do not update ethernet and ip6 addresses in neighbors if something was wrong with the RA
	 * as it may be forged
	*/
	if (watchers_add("watch_ra", &watch_ra,         ND_ROUTER_ADVERT,     WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_STOP_ON_ERROR)!=0) return -1;
	if (watchers_add("new_station", &new_station,   ND_ROUTER_ADVERT,     WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;

	/* Neighbor Solicitation checks: */
	if (watchers_add("new_station", &new_station,   ND_NEIGHBOR_SOLICIT,  WATCH_FLAG_CONTINUE_CHECKING | WATCH_FLAG_IP6_SRC_SPECIFIED)!=0) return -1;
	if (watchers_add("watch_dad", &watch_dad,       ND_NEIGHBOR_SOLICIT,  WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;

	/* Neighbor Advertisement checks: */
	if (watchers_add("watch_dad_dos", &watch_dad_dos, ND_NEIGHBOR_ADVERT, WATCH_FLAG_STOP_ON_ERROR | WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;
	if (watchers_add("watch_na_target", &watch_na_target, ND_NEIGHBOR_ADVERT, WATCH_FLAG_STOP_ON_ERROR | WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;
	if (watchers_add("new_station", &new_station,     ND_NEIGHBOR_ADVERT, WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;
	if (watchers_add("watch_R_flag", &watch_R_flag,   ND_NEIGHBOR_ADVERT, WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;

	/* Redirect checks: */
	if (watchers_add("watch_rd_src", &watch_rd_src, ND_REDIRECT, WATCH_FLAG_CONTINUE_CHECKING)!=0) return -1;

#ifdef _COUNTERMEASURES_
	/* if (watchers_add("watch_ndpmon_present", &watch_ndpmon_present, ND_NDPMON_PRESENT, WATCH_FLAG_CONTINUE_CHECKING |  WATCH_FLAG_IS_NDP_MESSAGE)!=0) return -1; */
	if (watchers_add("watch_ndpmon_present", &watch_ndpmon_present, ND_NDPMON_PRESENT, WATCH_FLAG_CONTINUE_CHECKING |  WATCH_FLAG_IS_NDP)!=0) return -1;
#endif
#ifdef _RULES_
	if (watchers_add("rule_match_all",       &rule_match_all, 0,          WATCH_FLAG_IS_NDP)!=0) return -1;
#endif

	/* Print list:*/
	if (DEBUG) {
		watchers_print();
	}
	return 0;
}

void extensions_setup(char * interface) 
{
	/* Plugin initialization */
#ifdef _COUNTERMEASURES_
	/* Will init before parsing
	 * cm_init(); 
	 */
#endif

#ifdef _MACRESOLUTION_
	read_manuf_file(_MANUF_PATH_,&manuf);
#endif

#ifdef _SOAP_
	soap_up();
#endif
}

void extensions_teardown() 
{
#ifdef _MACRESOLUTION_
	clean_manufacturer(&manuf);
#endif

#ifdef _SOAP_
	soap_down();
#endif
}
