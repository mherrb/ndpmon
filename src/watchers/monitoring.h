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


#ifndef _MONITORING_
#define _MONITORING_ 1


/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#endif

#ifdef _OPENBSD_
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

#ifdef _LINUX_
#include <netinet/ether.h>
#endif

#include <time.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <string.h>
#include <stdlib.h>

#include "../membounds.h"
#include "ndpmon_defs.h"

#include "../core/alerts.h"
#include "../core/capture.h"
#include "../core/print_packet_info.h"
#include "../core/watchers.h"

#ifdef _COUNTERMEASURES_
#include "../plugins/countermeasures/countermeasures.h"
#endif

#define MEMCMP(a, b, n) memcmp((char *)a, (char *)b, n)

int watch_prepare_ethernet(struct capture_info* const capture_info);

int watch_prepare_inet6(struct capture_info* const capture_info);

int watch_prepare_icmp6(struct capture_info* const capture_info);

/*  Checks whether this message is a ND message and activates further and NDP specific
    checks accordingly.
*/
int watch_prepare_nd(struct capture_info* const capture_info);

/*Look for mismatch between the source link layer addr and the one anounced
 *in the icmp option*/
int watch_eth_mismatch(struct capture_info* const capture_info);

/*Look if the source mac address is a broadcast addr or is all zeros*/
int watch_eth_broadcast(struct capture_info* const capture_info);


/*Look if the source ip address is a broadcast addr*/
int watch_ip_broadcast(struct capture_info* const capture_info);


/*Look if the source ip address is local to the subnet*/
int watch_bogon(struct capture_info* const capture_info);

/* Look if the hop limit is set to 255 */
int watch_hop_limit(struct capture_info* const capture_info);

/* New Station ? */
int new_station(struct capture_info* const capture_info);

#endif
