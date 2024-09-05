#include "parser.h"

int paser_alerts_append(const struct alert_info* const alert)
{
	xmlDoc *doc = NULL;
	xmlNodePtr root_element = NULL;
	xmlNodePtr new_alert = NULL;

	/*parse the file and get the DOM */
	doc = xmlReadFile(alerts_path, NULL, XML_PARSE_NOBLANKS);
	/*Get the root element node */
	root_element = xmlDocGetRootElement(doc);

	/*append the new alert to the DOM*/
	new_alert = xmlNewChild(root_element, NULL, BAD_CAST "alert", NULL);
	if (alert_save(new_alert, alert)==-1) 
	{
		fprintf(stderr, "ERROR: appending alert to XML file.\n");
		return -1;
	}

	if (xmlSaveFormatFile(alerts_path, doc, 1)==-1) 
	{
		fprintf(stderr, "[parser] ERROR: Could not write to alerts file. Alert not appended.\n");
		return -1;
	}

	xmlFreeDoc(doc);
	return 0;
}

int parser_config_parse()
{
	xmlDocPtr doc;
	xmlNodePtr root_element, element;

	fprintf(stderr,"Reading configuration file: \"%s\" ...\n",config_path);

	/* read the XML DOM validating the DTD: */
	doc = xmlReadFile(config_path, NULL, XML_PARSE_NOBLANKS | XML_PARSE_DTDVALID);
	/* get the root element and delegate its children to the handlers: */
	root_element = xmlDocGetRootElement(doc);
	element = root_element->children;
	while (element!=NULL) {
		if (element->type!=XML_ELEMENT_NODE) 
		{
			element = element->next;
			continue;
		}

		if (STRCMP(element->name, "probes")==0) 
		{
			if (probe_list_load_config(element)==-1) 
			{
				return -1;
			}
		} 
		else if (STRCMP(element->name, "settings")==0) 
		{
			if (settings_parse(element)==-1) 
			{
				return -1;
			}
		}
#ifdef _COUNTERMEASURES_
		else if (STRCMP(element->name, "countermeasures")==0) 
		{
			cm_config_parse(element);
		}
#endif

		/* fetch next element: */
		element = element->next;
	}
	/* frees the XML document AND the assigned tree: */
	xmlFreeDoc(doc);
	fprintf(stderr,"[parser] Finished reading the configuration.\n");
	return 0;
}

int parser_config_store()
{
	xmlDoc *doc;
	xmlNodePtr root_element;
	xmlNodePtr probes_element;
	xmlNodePtr settings_element;
	xmlNodePtr xslt_element;
#ifdef _COUNTERMEASURES_
	xmlNodePtr countermeasures_element;
#endif

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc==NULL) 
	{
		fprintf(stderr, "[parser] ERROR: creating XML document");
		return -1;
	}

	/* Give the stylesheet for display in the web interface */
	xslt_element = xmlNewPI( xmlCharStrdup("xml-stylesheet"), xmlCharStrdup("type=\"text/xsl\" href=\"config.xsl\""));
	xmlAddChild( (xmlNodePtr)doc, xslt_element); 

	root_element = xmlNewNode(NULL, BAD_CAST "config_ndpmon");
	xmlDocSetRootElement(doc, root_element);
	xmlCreateIntSubset(doc, BAD_CAST "config_ndpmon", NULL, BAD_CAST "config_ndpmon.dtd");

	settings_element = xmlNewChild(root_element, NULL, BAD_CAST "settings", NULL);
	if (settings_store(settings_element)==-1) 
	{
		return -1;
	}

	probes_element = xmlNewChild(root_element, NULL, BAD_CAST "probes", NULL);
	if (probe_list_save_config(probes_element)==-1) 
	{
		return -1;
	}

#ifdef _COUNTERMEASURES_
	countermeasures_element = xmlNewChild(root_element, NULL, BAD_CAST "countermeasures", NULL);
	if( cm_config_store(countermeasures_element) == -1 )
	{
		return -1;
	}
#endif

	if (xmlSaveFormatFileEnc(config_path, doc, "ISO-8859-1", 1)==-1) 
	{
		fprintf(stderr, "[parser] ERROR: Could not write to config file.\n");
		return -1;
	}
	xmlFreeDoc(doc);
	return 0;
}

int parser_neighbors_parse()
{
	xmlDocPtr doc;
	xmlNodePtr root_element;

	fprintf(stderr,"Reading neighbors file: \"%s\" ...\n",cache_path);

	/* read the XML DOM validating the DTD: */
	doc = xmlReadFile(cache_path, NULL, XML_PARSE_NOBLANKS | XML_PARSE_DTDVALID);
	/* get the root element and delegate its children to the handlers: */
	root_element = xmlDocGetRootElement(doc);

	if (probe_list_load_neighbors(root_element)==-1) 
	{
		xmlFreeDoc(doc);
		return -1;
	}

	xmlFreeDoc(doc);
	fprintf(stderr,"[parser] Finished reading the neighbor cache.\n");
	return 0;
}

int parser_neighbors_store()
{
	xmlDoc *doc;
	xmlNodePtr root_element;
	xmlNodePtr xslt_element;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc==NULL) 
	{
		fprintf(stderr, "[parser] ERROR: creating XML document");
		return -1;
	}

	/* Give the stylesheet for display in the web interface */
	xslt_element = xmlNewPI( xmlCharStrdup("xml-stylesheet"), xmlCharStrdup("type=\"text/xsl\" href=\"neighbor.xsl\""));
	xmlAddChild( (xmlNodePtr)doc, xslt_element); 

	root_element = xmlNewNode(NULL, BAD_CAST "neighbors");
	xmlDocSetRootElement(doc, root_element);

	xmlCreateIntSubset(doc, BAD_CAST "neighbors", NULL, BAD_CAST "neighbor_list.dtd");

	fprintf(stderr, "[parser] Writing cache...\n");

	if (probe_list_save_neighbors(root_element)==-1) 
	{
		return -1;
	}

	if (xmlSaveFormatFileEnc(cache_path, doc, "ISO-8859-1", 1)==-1) 
	{
		fprintf(stderr, "[parser] ERROR: Could not write to neighbor cache.\n");
		return -1;
	}
	xmlFreeDoc(doc);
	return 0;
}

void parser_handler_std_save_cache(const struct event_info* event)
{
	/* to periodicaly save the neighbor cache: */
	static time_t last_save_time = 0;
	time_t current = time(NULL);

	if (event->type == EVENT_TYPE_NEIGHBOR_UPDATE) 
	{
		if (difftime(current, last_save_time) > 60) 
		{
			parser_neighbors_store();
			last_save_time = current; /* extension point */
#ifdef _COUNTERMEASURES_
			cm_indicate_ndpmon_presence(data->probe_name);
#endif
		}
	}
}
