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

#include "monitoring_rd.h"


/*Test if the RD buffer comes from a router with IP6 and MAC address
 *specified in the configuration file
 */
int watch_rd_src(struct capture_info* const capture_info)
{
	const struct ether_header* ethernet_header = capture_info->ethernet_header;
	const struct ip6_hdr* ip6_header           = capture_info->ip6_header;
	char* buffer                               = capture_info->message;
	char ip_address[INET6_ADDRSTRLEN], ether_address[ETH_ADDRSTRLEN];
	struct ether_addr *src_eth = (struct ether_addr *) ethernet_header->ether_shost;
	int ret = 0;
	struct probe* locked_probe;
	int found_router = 12345;

	/* addresses to string */
	ipv6_ntoa(ip_address, ip6_header->ip6_src);
	strlcpy( ether_address, ether_ntoa(src_eth), ETH_ADDRSTRLEN);

	/* begin critical section: */
	locked_probe = probe_lock(capture_info->probe->name);
	found_router = router_has_router(locked_probe->routers, ip6_header->ip6_src, *src_eth);
	locked_probe = NULL;
	probe_unlock(capture_info->probe->name);
	/* end critical section. */

	if(!found_router)
	{
		int found_mac;
		int found_lla;

		/* begin critical section: */
		locked_probe = probe_lock(capture_info->probe->name);
		found_mac = is_router_mac_in(locked_probe->routers, *src_eth);
		found_lla = is_router_lla_in(locked_probe->routers, ip6_header->ip6_src);
		locked_probe = NULL;
		probe_unlock(capture_info->probe->name);
		/* end critical section. */

		if( found_mac && found_lla)
		{
			/* valid MAC and IP, but not together */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong couple IP/MAC %s %s in RD", ether_address, ip_address);
			alert_raise(2, capture_info->probe, "wrong couple IP/MAC in RD", buffer, src_eth, NULL, &ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else if( found_mac && !found_lla)
		{
			/* wrong IP */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong router redirect ip %s %s", ether_address, ip_address);
			alert_raise(2, capture_info->probe, "wrong router redirect ip", buffer, src_eth, NULL, &ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else if( !found_mac && found_lla)
		{
			/* wrong MAC */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong router redirect mac %s %s", ether_address, ip_address);
			alert_raise(2, capture_info->probe, "wrong router redirect mac", buffer, src_eth, NULL, &ip6_header->ip6_src, NULL);
			ret = 2;
		}
		else
		{
			/* wrong MAC AND wrong IP */
			snprintf (buffer, NOTIFY_BUFFER_SIZE, "wrong router redirect %s %s", ether_address, ip_address);
			alert_raise(2, capture_info->probe, "wrong router redirect", buffer, src_eth, NULL, &ip6_header->ip6_src, NULL);
			ret = 2;
		}
	}

	/* Legitimate Routers can redirect */
	return ret;

#if 0
	char* mac_address = NULL;
	int mac_ok = 0, ip_ok = 0;

	if(routers != NULL)
	{
		mac_address= (char*)ether_ntoa((struct ether_addr*) (ethernet_header->ether_shost));
		mac_ok = is_router_mac_in(routers, *src_eth);
	}
	else
		mac_ok=1;

	if(routers != NULL)
	{
		ipv6_ntoa(ip_address, ip6_header->ip6_src);
		ip_ok = is_router_lla_in(routers, ip6_header->ip6_src);
	}
	else
		ip_ok=1;

	if(!ip_ok || !mac_ok)
	{
		snprintf (buffer, NOTIFY_BUFFER_SIZE-1, "wrong router redirect %s %s", mac_address, ip_address);
		notify(2, buffer, "wrong router redirect", (struct ether_addr*) (ethernet_header->ether_shost), ip_address, NULL);
		return 2;
	}
	else
		return 0; /*Official routers can redirect*/
#endif
}
