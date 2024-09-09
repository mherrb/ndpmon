/********************************************************************************
NDPMon - Neighbor Discovery Protocol Monitor
Copyright (C) 2006 MADYNES Project, LORIA - INRIA Lorraine (France)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Author Info:
  Name: Thibault Cholez
  Mail: thibault.cholez@esial.uhp-nancy.fr

Maintainer:
  Name: Frederic Beck
  Mail: frederic.beck@loria.fr

MADYNES Project, LORIA-INRIA Lorraine, hereby disclaims all copyright interest in
the tool 'NDPMon' (Neighbor Discovery Protocol Monitor) written by Thibault Cholez.

Olivier Festor, Scientific Leader of the MADYNEs Project, 20 August 2006
***********************************************************************************/


#include "alerts.h"

static int watch;

int alert_already_sent(const char* const message)
{
	static char old_messages[HISTORY_LENGTH][NOTIFY_BUFFER_SIZE];
	static int index=0;
	int i;

	for (i=0; i<HISTORY_LENGTH; i++)
	{
		if (!strcmp(message, old_messages[i]))
			/* the message has been found: */
			return 1;
	}

	/* message was not found, add it to the history.*/
	strlcpy(old_messages[index], message, NOTIFY_BUFFER_SIZE);

	/* history is a cyclic buffer, if the end is reached go back to the
	 * start: */
	if(index==HISTORY_LENGTH-1)
		index=0;
	else
		index++;

	return 0;
}


char* alert_create_mailmessage(const struct alert_info* const alert_info) 
{
	char *mail;
	char ethernet_address1_str[ETH_ADDRSTRLEN];
	char ethernet_address2_str[ETH_ADDRSTRLEN];
	char ipv6_address_str[INET6_ADDRSTRLEN];
	char hostname[HOST_NAME_SIZE];
	uint8_t mac_unspecified[sizeof(struct ether_addr)];
	uint8_t ipv6_unspecified[sizeof(struct in6_addr)];
#ifdef _MACRESOLUTION_
	const char *ethernet_vendor = "n/a";
	const char *ethernet_vendor2 = "n/a";
#endif

	/* allocate buffer: */
	if ((mail=malloc(ALERT_MAIL_SIZE))==NULL) {
		perror("malloc");
		return NULL;
	}
	memset(mail, 0, ALERT_MAIL_SIZE);
	memset(mac_unspecified, 0, sizeof(struct ether_addr));
	memset(ipv6_unspecified, 0, sizeof(struct in6_addr));

	/* convert numeric values: */
	ether_ntoa_r(&alert_info->ethernet_address1, ethernet_address1_str);
#ifdef _MACRESOLUTION_
	ethernet_vendor = get_manufacturer(manuf, &alert_info->ethernet_address1);
#endif

	if (memcmp(&alert_info->ethernet_address2, mac_unspecified, sizeof(struct ether_addr))==0) 
	{
		strlcpy(ethernet_address2_str, "n/a", ETH_ADDRSTRLEN);
	} else 
	{
		ether_ntoa_r(&alert_info->ethernet_address2, ethernet_address2_str);
#ifdef _MACRESOLUTION_
		ethernet_vendor2 = get_manufacturer(manuf, &alert_info->ethernet_address2);
#endif
	}

	if (memcmp(&alert_info->ipv6_address, ipv6_unspecified, sizeof(struct in6_addr))==0) 
	{
		strlcpy(ipv6_address_str, "n/a", ETH_ADDRSTRLEN);
	} else 
	{
		inet_ntop(AF_INET6, &alert_info->ipv6_address, ipv6_address_str, INET6_ADDRSTRLEN);
	}

	if (use_reverse_hostlookups==1) 
	{
		alert_gethostfromipv6(&alert_info->ipv6_address,hostname);
	} else 
	{
		strlcpy(hostname, "n/a", HOST_NAME_SIZE);
	}

	/* write content: */
#ifdef _MACRESOLUTION_
	snprintf(mail, ALERT_MAIL_SIZE-1,
		 "%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n",
		 "Reason:", alert_info->reason,
		 "MAC:",  ethernet_address1_str,
		 "Vendor:", ethernet_vendor,
		 "MAC2:", ethernet_address2_str,
		 "Vendor2:", ethernet_vendor2,
		 "IPv6:", ipv6_address_str,
		 "DNS:", hostname
		);
#else
	snprintf(mail, ALERT_MAIL_SIZE-1,
			"%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n%-9s%s\n",
			"Reason:", alert_info->reason,
			"MAC:",  ethernet_address1_str,
			"MAC2:", ethernet_address2_str,
			"IPv6:", ipv6_address_str,
			"DNS:", hostname
		);
#endif

	return mail;
}


void alert_free(union event_data** alert) 
{
	/* There are no pointers to other structures in an alert,
	 * so there is nothing to do except freeing it.
	 */
	free(*alert);
	*alert = NULL;
}


int alert_gethostfromipv6(const struct in6_addr* const ipv6_address, char* hostname) 
{
	/*struct in6_addr addrbuf;*/
	struct hostent *h;

	/*if (0 == inet_pton(AF_INET6, ipv6adr, &addrbuf)) {
	  snprintf(hostname, HOST_NAME_SIZE, "<%s>",hstrerror(h_errno));
	  if (DEBUG) fprintf(stderr,"Problem (inet_pton) looking up \"%." HOST_NAME_LEN_FSTR "s\": %." HOST_NAME_LEN_FSTR "s\n", ipv6adr, hstrerror(h_errno));
	  return;
	  }*/
	h = gethostbyaddr(ipv6_address, sizeof(struct in6_addr), AF_INET6);
	if (h) 
	{
		snprintf(hostname, HOST_NAME_SIZE, "%s", h->h_name);
		return 0;
	} else 
	{
		char ipv6_address_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ipv6_address, ipv6_address_str, INET6_ADDRSTRLEN);
		snprintf(hostname, HOST_NAME_SIZE, "<%s>", hstrerror(h_errno));
		if (DEBUG) 
		{
			fprintf(
					stderr,
					"Problem (gethostbyaddr) looking up \"%." HOST_NAME_LEN_FSTR "s\": %." HOST_NAME_LEN_FSTR "s\n",
					ipv6_address_str, hstrerror(h_errno));
		}
		return -1;
	}
	return 0;
}


void alert_handler_std_pipe_program(const struct event_info* event) 
{
	char *mailmessage;
	const struct alert_info* alert;

	if (event->type!=EVENT_TYPE_ALERT) 
	{
		return;
	}
	alert = &event->data->alert;

	switch (alert->priority) 
	{
		case 2:
			if (action_high_pri.exec_pipe_program == NULL) 
			{
				return;
			}
			break;
		case 1:
			if (action_low_pri.exec_pipe_program == NULL) 
			{
				return;
			}
			break;
		default:
			break;
	}
	mailmessage = alert_create_mailmessage(alert);
	if (alert->priority == 2)
	    do_exec_pipe_program(action_high_pri.exec_pipe_program, mailmessage);
	else
	    do_exec_pipe_program(action_low_pri.exec_pipe_program, mailmessage);
	free(mailmessage);
}


void alert_handler_std_syslog(const struct event_info* event) 
{
	const struct alert_info* alert;

	if (event->type != EVENT_TYPE_ALERT) 
	{
		return;
	}
	alert = &event->data->alert;

	switch (alert->priority) 
	{
		case 2:
			if (action_high_pri.syslog != 1) 
			{
				return;
			}
			break;
		case 1:
			if (action_low_pri.syslog != 1)
			{
				return;
			}
			break;
		default:
			break;
	}
	syslog(LOG_INFO, " %s ", alert->message);
}


void alert_handler_std_sendmail(const struct event_info* event) 
{
	char *mailmessage;
	const struct alert_info* alert;

	if (event->type != EVENT_TYPE_ALERT) 
	{
		return;
	}
	alert = &event->data->alert;

	switch (alert->priority) 
	{
		case 2:
			if (action_high_pri.sendmail != 1) 
			{
				return;
			}
		case 1:
			if (action_low_pri.sendmail != 1)
			{
				return;
			}
			break;
		default:
			break;
	}
	/* create mailmessage: */
	mailmessage = alert_create_mailmessage(alert);
	alert_sendmail(mailmessage, alert->message);
	free(mailmessage);
}


void alert_handler_std_xml_append(const struct event_info* event) 
{
	const struct alert_info* alert;

	if (event->type != EVENT_TYPE_ALERT) 
	{
		return;
	}
	alert = &event->data->alert;
	parser_alerts_append(alert);
}

void alert_raise(int priority, const struct probe* probe, char* reason,
        char* message, const struct ether_addr* const ethernet_address1,
        const struct ether_addr* ethernet_address2,
        const struct in6_addr* const ipv6_address, struct extinfo_list* extinfo)
{
	union event_data* new = event_data_create();
	time_t current = time(NULL);

	if (!watch)
	{
		if (DEBUG)
		{
			fprintf(stderr, "[alerts] learning mode, alert \"%s\" on probe \"%s\" ignored.\n", reason, probe->name);
		}

		return;
	}

	/* Print information: */
	fprintf(stderr, "[alerts] Alert \"%s\" raised on probe \"%s\".\n", reason, probe->name);

	/* fill event_data structure: */
	new->alert.priority = priority;
	new->alert.time     = current;
	strlcpy(new->alert.probe_name, probe->name, PROBE_NAME_SIZE);
	strlcpy(new->alert.reason, reason, ALERT_REASON_SIZE);
	strlcpy(new->alert.message, message, ALERT_MESSAGE_SIZE);
	memcpy(&new->alert.ethernet_address1, ethernet_address1, sizeof(struct ether_addr));

	if (ethernet_address2!=NULL)
	{
		memcpy(&new->alert.ethernet_address2, ethernet_address2, sizeof(struct ether_addr));
	}

	if (ipv6_address!=NULL)
	{
		memcpy(&new->alert.ipv6_address, ipv6_address, sizeof(struct in6_addr));
	}

	new->alert.extinfo = extinfo;

	event_queue(EVENT_TYPE_ALERT, new);
}


int alert_save(xmlNodePtr element, const struct alert_info* const alert) 
{
	char priority_str[2];
	char mac1_str[ETH_ADDRSTRLEN];
	char mac2_str[ETH_ADDRSTRLEN];
	char ip_str[INET6_ADDRSTRLEN];
	time_t rawtime;
	struct tm * timeinfo;
	char time_humanread_str[80];
	char time_str[20];

	/* convert numerical values: */
	ether_ntoa_r(&alert->ethernet_address1, mac1_str);
	ether_ntoa_r(&alert->ethernet_address2, mac2_str);
	inet_ntop(AF_INET6, &alert->ipv6_address, ip_str, INET6_ADDRSTRLEN);
	snprintf(priority_str, 2, "%i", alert->priority);
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	snprintf(time_str, 20, "%i", (int)alert->time);
	strftime (time_humanread_str,80,"%c",timeinfo);

	/* add the information in alphabetical order to the element: */
	xmlNewChild(element, NULL, BAD_CAST "ethernet_address1", BAD_CAST mac1_str);
	xmlNewChild(element, NULL, BAD_CAST "ethernet_address2", BAD_CAST mac2_str);
	xmlNewChild(element, NULL, BAD_CAST "ipv6_address", BAD_CAST ip_str);
	xmlNewChild(element, NULL, BAD_CAST "message", BAD_CAST alert->message);
	xmlNewChild(element, NULL, BAD_CAST "priority", BAD_CAST priority_str);
	xmlNewChild(element, NULL, BAD_CAST "probe", BAD_CAST alert->probe_name);
	xmlNewChild(element, NULL, BAD_CAST "reason", BAD_CAST alert->reason);
	xmlNewChild(element, NULL, BAD_CAST "time", BAD_CAST time_str);
	xmlNewChild(element, NULL, BAD_CAST "time_str", BAD_CAST time_humanread_str);

	if (extinfo_list_save(element, alert->extinfo)==-1) 
	{
		return -1;
	}
	return 0;
}


void alert_sendmail(const char* message, const char* subjectappend) 
{
	FILE *pp;
	static char args[MAIL_ARGS_SIZE];/*shoule be sufficient*/

	snprintf(args, MAIL_ARGS_SIZE, "mail -s \"NDPMon_Security_Alert: %s\" %s", subjectappend, admin_mail);


	printf("[alerts] Sending mail alert ...\n");
	pp = popen(args, "w");
	if (pp == NULL)
	{
		perror("popen error: unable to send mail");
		return;
	}


	fprintf(pp,"%s",message);
#ifdef _LINUX_
	/* For the Cc: */
	fprintf(pp,"\n");
#endif

	fflush(pp);

	pclose(pp);
}


void alert_set_active(int b)
{
	watch = b;
}


void do_exec_pipe_program(char* program, char* pipedata) 
{
	FILE *pipeprocess;

	pipeprocess = popen(program, "w");
	fprintf(pipeprocess, "%s\n", pipedata);
	fflush(pipeprocess);
	pclose(pipeprocess);
}

