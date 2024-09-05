#ifndef _WEBINTERFACE_H_
#define _WEBINTERFACE_H_

#if 0
#include <libxml/xmlmemory.h>
#include <libxml/debugXML.h>
#include <libxml/HTMLtree.h>
#include <libxml/xmlIO.h>


#include <libxml/xinclude.h>
#include <libxml/catalog.h>




#endif

#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h> /*xsltStylesheetPtr */
#include <libxslt/transform.h> /* xsltApplyStylesheet() */
#include <libxslt/xsltutils.h> /* xsltSaveResultToFilename */

#include "ndpmon_defs.h"
#include "../../core/events.h"

/** Exports the alerts XML file to WEBDIR as HTML, using XSLT.
 *  @return Always 0.
 */
int wi_export_alerts();

/** Exports the XML neighbor cache as HTML to the WEBDIR path.
 *  @return Always 0.
 */
int wi_export_neighbor_cache();

/** Periodically triggers the webinterface export.
 *  @param event The event, is check to be EVENT_TYPE_NEIGHBOR_UPDATE or
 *               EVENT_TYPE_ALERT.
 */
void wi_export_handler(const struct event_info* event);

#endif
