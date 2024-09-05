#ifndef _CAPTURE_H_
#define _CAPTURE_H_

#include <sched.h>

#include "ndpmon_defs.h"
#include "../ndpmon_netheaders.h"
#include "parser.h"
#include "probes.h"
#include "watchers.h"

#include "print_packet_info.h"

/* Forward declaration of library specific structure.*/
struct capture_descriptor;

/* Forward declaration of probe type: */
struct probe;


void capture_nd_option_list_free(struct nd_option_list** option_list);

int capture_nd_option_list_add(struct nd_option_list** option_list,
        const struct nd_opt_hdr* const opt);

int capture_is_icmp6_packet(const uint8_t* packet, int packet_length, struct icmp6_hdr** icmpptr);

int capture_nd_option_list_add(struct nd_option_list** option_list,
        const struct nd_opt_hdr* const opt);

int capture_process_packet(struct probe* probe, const struct timeval* timestamp, uint8_t* packet_data, int packet_length);

/* Interface to library specific funtions. */

/** Stops packet capturing on all interfaces of PROBE_TYPE_INTERFACE.
 *
 */
extern void capture_down_all();

/** Initializes packet capturing on all interfaces of PROBE_TYPE_INTERFACE
 *
 */
extern void capture_up_all();

#endif
