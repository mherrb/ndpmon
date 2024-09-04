#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_

#include "./watchers/monitoring.h"
#include "./watchers/monitoring_ra.h"
#include "./watchers/monitoring_na.h"
#include "./watchers/monitoring_ns.h"
#include "./watchers/monitoring_rd.h"

#ifdef _MACRESOLUTION_
#include "./plugins/mac_resolv/mac_resolv.h"
#endif

#ifdef _COUNTERMEASURES_
#include "./plugins/countermeasures/countermeasures.h"
#endif

#ifdef _WEBINTERFACE_
#include "./plugins/webinterface/webinterface.h"
#endif

#ifdef _RULES_
#include "./plugins/rules/rules.h"
#endif

#ifdef _SOAP_
#include "./plugins/soap/soap.h"
#endif

/** @file
 *  Provides extension points needed to integrate custom watch functions
 *  or plugins. These well defined points should be used to register extension
 *  functionality.
 */



/** Used to register event handlers. Event handlers react to events raised
 *  by watch functions (@ref events.h). Called during NDPMon startup.
 *
 *  @return 0 on success, -1 otherwise.
 */
int extensions_register_handlers();

/** Used to register extension information (extinfo) types. Extinfo types are
 *  used by plugins to store custom information to core data structures
 *  (@ref extinfo.h). Called during NDPMon startup.
 *
 *  @return 0 on success, -1 otherwise.
 */
int extensions_register_types();

/** All watch functions called for captured packets are registered in this
 *  function. Called during NDPMon startup.
 *
 *  @return 0 on success, -1 otherwise.
 */
int extensions_register_watchers();

/** This function should be used to initialize plugins. It is called during
 *  NDPMon startup.
 */
void extensions_setup();

/** This function should be used to release resources used by plugins or watch
 *  functions. It is called if NDPMon is terminated, for example by a SIGINT
 *  signal.
 */
void extensions_teardown();

#endif
