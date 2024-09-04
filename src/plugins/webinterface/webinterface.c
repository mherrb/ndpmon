
#include "webinterface.h"

int wi_export_alerts() 
{
	xsltStylesheetPtr stylesheet = NULL;
	xmlDocPtr doc, res;

	xmlSubstituteEntitiesDefault(1);
	xmlLoadExtDtdDefaultValue = 1;
	stylesheet = xsltParseStylesheetFile((unsigned char*)_WEBINTERFACE_PATH_"/alerts.xsl");
	doc = xmlParseFile(alerts_path);
	res = xsltApplyStylesheet(stylesheet, doc, 0);
	fprintf(stderr, "[webinterface]: Exporting alerts to \""_WEBINTERFACE_PATH_"/alerts.html\".\n");
	xsltSaveResultToFilename(_WEBINTERFACE_PATH_"/alerts.html", res, stylesheet, 0);

	xsltFreeStylesheet(stylesheet);
	xmlFreeDoc(res);
	xmlFreeDoc(doc);
	xsltCleanupGlobals();
	xmlCleanupParser();
	return 0;
}

int wi_export_neighbor_cache() 
{
	xsltStylesheetPtr stylesheet = NULL;
	xmlDocPtr doc, res;

	xmlSubstituteEntitiesDefault(1);
	xmlLoadExtDtdDefaultValue = 1;
	stylesheet = xsltParseStylesheetFile((unsigned char*)_WEBINTERFACE_PATH_"/neighbor.xsl");
	doc = xmlParseFile(cache_path);
	res = xsltApplyStylesheet(stylesheet, doc, 0);
	fprintf(stderr, "[webinterface]: Exporting neighbor cache to \""_WEBINTERFACE_PATH_"/neighbors.html\".\n");
	xsltSaveResultToFilename(_WEBINTERFACE_PATH_"/neighbors.html", res, stylesheet, 0);

	xsltFreeStylesheet(stylesheet);
	xmlFreeDoc(res);
	xmlFreeDoc(doc);
	xsltCleanupGlobals();
	xmlCleanupParser();
	return 0;
}

void wi_export_handler(const struct event_info* event) 
{
	/* to periodicaly export program information: */
	static time_t last_save_time = 0;
	time_t current = time(NULL);

	/* Always export alerts right away */
	if(event->type == EVENT_TYPE_ALERT)
	{
		wi_export_alerts();
	}

	/* every minute export the neighbor list
	 * may it be a EVENT_TYPE_NEIGHBOR_UPDATE or EVENT_TYPE_ALERT event
	 */
	if (event->type == EVENT_TYPE_NEIGHBOR_UPDATE || event->type == EVENT_TYPE_ALERT) 
	{
		if (difftime(current, last_save_time) > 60) 
		{
			wi_export_alerts();
			wi_export_neighbor_cache();
			last_save_time = current;
		}
	}
}
