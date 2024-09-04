#ifndef _PARSERS_
#define _PARSERS_ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>


#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include <libxml/xpath.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>

#include "../membounds.h"
#include "../ndpmon_defs.h"

#include "neighbors.h"
#include "probes.h"
#include "routers.h"
#include "settings.h"

#ifdef _COUNTERMEASURES_
#include "../plugins/countermeasures/countermeasures.h"
#endif
#ifdef _RULES_
#include "../plugins/rules/rules.h"
#endif
#ifdef _WEBINTERFACE_
#include "../plugins/webinterface/webinterface.h"
#endif

/** @file
 *  Access to the configuration and neighbor cache XML files (only used by the core).
 */

#define NB_CACHE_SIZE 255
#define MY_ENCODING "ISO-8859-1"

/** Appends an alert to the XML alerts file.
 *  @param alert The alert to be appended.
 *  @return      0 on success, -1 otherwise.
 */
int paser_alerts_append(const struct alert_info* const alert);

/** Stores the running NDPMon configuration to the XML configuration file.
    Recursively calls the store procedures of other modules to build the
    XML file's DOM.
    @return 0 on success, -1 otherwise.
*/
int parser_config_store();

/** Parses the startup XML configuration of NDPMon from a xml file.
    Recursively calls the parse procedures of other modules to parse
    the XML file's DOM.
    @return 0 on success, -1 otherwise.
*/
int parser_config_parse();

/** Parses the neighbor cache and loads its content to the different
 *  neighbor cache lists of the different probes.
 *  Recursively calls the load procedures of other modules to parse
 *  the XML file's DOM.
 *  @return 0 on success, -1 otherwise.
 */
int parser_neighbors_parse();

/** Stores the neighbor lists of all probes to the NDPMon neighbors XML file.
 *  @return 0 on success, -1 otherwise.
 */
int parser_neighbors_store();

/** This handler periodically saves the neighbor cache if it encounters
 *  an EVENT_TYPE_NEIGHBOUR_UPDATE event.
 *  @param event Is used to check if the current event is a neighbor update.
 */
void parser_handler_std_save_cache(const struct event_info* event);

#if 0
void parse_config();
void write_config();
void parse_cache();
void write_cache();
#endif

#endif
