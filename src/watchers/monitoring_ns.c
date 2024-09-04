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


#include "monitoring_ns.h"

void last_dad_address_free(void** data) {
    free(*data);
    *data = NULL;
}

/*Note which addr is wanted by a dad message
*/
int watch_dad(struct capture_info* const capture_info) {
    struct nd_neighbor_solicit* neighbor_solicit =
            (struct nd_neighbor_solicit*) capture_info->icmp6_header;
    struct in6_addr* last_dad_addr;
    struct probe* probe_locked;

    if (IN6_IS_ADDR_UNSPECIFIED(&(capture_info->ip6_header->ip6_src))) {
        /*This is a DAD NS message*/
        fprintf(stderr, "Setting LAST DAD ADDR\n");
        last_dad_addr = malloc(sizeof(struct in6_addr));
        if (last_dad_addr==NULL) {
            perror("malloc");
            return -1;
        }
        memcpy(last_dad_addr, &neighbor_solicit->nd_ns_target, sizeof(struct in6_addr));
        /* critical section: */
        probe_locked = probe_lock(capture_info->probe->name);
        extinfo_list_set(&probe_locked->extinfo, "last_dad_address", last_dad_addr);
        probe_unlock(capture_info->probe->name);
        /* end of critical section. */
    }
    return 0;
}

#if 0
struct in6_addr* get_last_dad_addr(const struct probe* const probe) {
    struct in6_addr* last_dad_addr = extinfo_list_get_data(probe->extinfo, "last_dad_address");
    return &last_dad_addr;
}
#endif
