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

#ifndef _ALERTS_H_
#define _ALERTS_H_ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>

#include <libxml/tree.h>

#include "../membounds.h"
#include "ndpmon_defs.h"
#include "../ndpmon_netheaders.h"

#include "events.h"
#include "extinfo.h"
#include "probes.h"

/** @file
 *  Raises alerts and provides functions to post alerts to the syslog, mail or XML.
 */

/** The length of the list of mail alerts send (to prevent sending multiple mail alerts for the same problem). */
#define HISTORY_LENGTH 20
/** The size of a mail notification text. */
#define ALERT_MAIL_SIZE     2048
/** Integer defining a low priority alert (1). */
#define ALERT_PRIORITY_LOW  1
/** Integer representing a high priority alert (2). */
#define ALERT_PRIORITY_HIGH 2

extern int parser_alerts_append(const struct alert_info* const alert);

/** Test if the message has been recently sent to avoid
 *  multiple warnings for the same problem.
 *  @param message The message to check for.
 */
int alert_already_sent(const char* const message);

/** Allocates buffer for a mail message and writes its content
 *  according to the given alert_info.
 *  @param alert_info The alert info.
 */
char* alert_create_mailmessage(const struct alert_info* const alert_info);

/** Frees the data of an alert event.
 *  @param alert The alert to be freed.
 */
void alert_free(union event_data** alert);

/** Resolves an IPv6 address to a hostname to have additional information
 *  for the alert message.
 *  @param ipv6_address The address to be resolved.
 *  @param hostname     Buffer to hold the hostname, must be of
 *                      HOST_NAME_SIZE.
 *  @return             0 on success, -1 otherwise.
 */
int alert_gethostfromipv6(const struct in6_addr* const ipv6_address,
        char* hostname);

/** Standard alert handler: Calls a pipe program (if one given in the config).
 * @param alert The alert information.
 */
void alert_handler_std_pipe_program(const struct event_info* event);

/** Standard alert handler: Adds a syslog entry (if enable in the config).
 * @param alert The alert information.
 */
void alert_handler_std_syslog(const struct event_info* event);

/** Standard alert handler: Sends a mail alert. (if enable in the config).
 * @param alert The alert information.
 */
void alert_handler_std_sendmail(const struct event_info* event);

/** Standard alert handler: Appends alert to XML alerts file.
 * @param alert The alert information.
 */
void alert_handler_std_xml_append(const struct event_info* event);

/** Raises an alert , which means adding the alert
 *  to the global alert list and calling all alert handlers.
 *  @param priority          ALERT_PRIORITY_LOW or ALERT_PRIORITY_HIGH
 *  @param reason            The short reason for this alert.
 *  @param message           The brief description of what happened.
 *  @param ethernet_address1 The ethernet address involved.
 *  @param ethernet_address2 The second ethernet address involved, if one.
 *  @param ipv6_address      The IPv6 address involved.
 *  @return                  0 on success, -1 otherwise.
 */
void alert_raise(int priority, const struct probe* probe, char* reason, char* message, const struct ether_addr* const ethernet_address1, const struct ether_addr* ethernet_address2, const struct in6_addr* const ipv6_address, struct extinfo_list* extinfo);

/** Saves an alert to a given XML element.
 *  @param element The element to add the information to.
 *  @param alert   The alert information.
 *  @return        0 on success, -1 otherwise.
 */
int alert_save(xmlNodePtr element, const struct alert_info* const alert);

/** Sends a mail notification about the given alert.
 *  @param message       The mail message as created by alert_create_mailmessage().
 *  @param subjectappend The reason for this alert.
 */
void alert_sendmail(const char* message, const char* subjectappend);

/** Define if warnings must be reported.
 *  @param a Active (1) or disabled (0).
 */
void alert_set_active(int a);

/* Execute external program and send data to its stdin */
void do_exec_pipe_program(char* program, char* pipedata);




#endif
