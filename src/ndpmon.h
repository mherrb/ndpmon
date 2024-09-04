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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <signal.h>

#include <unistd.h>            /*To read options from the command line*/

#include "ndpmon_defs.h"
#include "ndpmon_netheaders.h"
#include "membounds.h"

#include "extensions.h"

#include "./core/alerts.h"
#include "./core/capture.h"
#include "./core/events.h"
#include "./core/neighbors.h"
#include "./core/parser.h"
#include "./core/print_packet_info.h"
#include "./core/routers.h"
#include "./core/settings.h"
#include "./core/watchers.h"

#if defined (_CAPTURE_USE_PCAP_) || defined (_CAPTURE_USE_LNFQ_)
#include "./capture/capture_pcap.h"
#include "./capture/capture_lnfq.h"
#else
#error "Define either _CAPTURE_USE_PCAP_ or _CAPTURE_USE_LNFQ_ to build NDPMon."
#endif


/** @file
 *  NDPMon compilation starting point.
 */

/** This functions performs initialization tasks like loading configuration
 *  or neighbor cache.
 */
void setup();

/** This function stops packet capturing, cancels the event queue thread and
 *  releases resources used by the program. It is called by the signal handler handler().
 */
void teardown();

/** NDPMon signal handler to terminate the daemon.
 *  @param n Signal number.
 */
void handler(int n);

/** Displays a help message and exits.*/
void usage();

/** Main function of the daemon. This function parses command line arguments
 *  and calls setup() to start monitoring.
 */
int main(int argc,char **argv);
