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

#ifndef _MONITORING_RA_
#define _MONITORING_RA_ 1

/* Setting headers according to OSTYPE */
#ifdef _FREEBSD_
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
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

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "../membounds.h"
#include "ndpmon_defs.h"

#include "../core/alerts.h"
#include "../core/watchers.h"
#include "../core/routers.h"

#ifdef _COUNTERMEASURES_
#include "../plugins/countermeasures/countermeasures.h"
#endif

#if 0
/* 
 * RFC6106 - RDNSS and DNSSL
 * Belongs in <netinet/icmp6.h> 
 **/

/* Recursive DNS Server */
#define ND_OPT_RDNSS 25
struct nd_opt_rdnss
{
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved;
	uint32_t nd_opt_rdnss_lifetime;
	/* followed by one or more (should not be more than MAXNS) IPv6 addresses */
	/* struct in6_addr *nd_opt_rdnss_addr; */
};

/* DNS Search List */
#define ND_OPT_DNSSL 31
struct nd_opt_dnssl
{
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved;
	uint32_t nd_opt_dnssl_lifetime;
	/* followed by one or more domain names */
};

/* RFC6106 - END */
#endif

int watch_ra(struct capture_info* const capture_info);

#endif
