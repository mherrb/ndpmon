#ifndef _WATCHERS_H
#define _WATCHERS_H

/** @file
    Manages the different watch functions.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "../ndpmon_netheaders.h"

/** Size of the human readable name of a watch function (may be equivalent to the C source code name). */
#define WATCHER_NAME_SIZE  25

/** Watch flag: Call further watch functions for the current packet. */
#define WATCH_FLAG_CONTINUE_CHECKING      0x8000
/** Watch flag: The current packet is an IPv6 packet. */
#define WATCH_FLAG_IS_IP6                 0x4000
/** Watch flag: The current packet is an ICMPv6 packet. */
#define WATCH_FLAG_IS_ICMP6               0x2000
/** Watch flag: The current packet is a Neighbor Discovery message. */
#define WATCH_FLAG_IS_NDP                 0x1000
/** The IPv6 source of the current NDP message is specified. */
#define WATCH_FLAG_IP6_SRC_SPECIFIED      0x0800
/** The ethernet address found in the current NDP message was not found in the cache (it is new). */
#define WATCH_FLAG_NEW_ETHERNET_ADDRESS   0x0400
/** The ethernet address found in the current NDP message belongs to a router in the router list. */
#define WATCH_FLAG_IS_LEGITIMATE_ROUTER   0x0200
/** Watch flag: Stop all watch function calls if the previous returned 2 i.e. something wrong has been detected e.g. dad dos */
#define WATCH_FLAG_STOP_ON_ERROR          0x0100

struct probe;

/** Information for the current packet captured. */
struct capture_info {
    /** Probe on which this packet has been captured. The probe should
        be locked if its data structures are accessed, only the <B>name</B>
        field can be accessed savely because it does never change after
        startup.
     */
    struct probe* probe;
    /** Pre-allocated buffer for building an alert message. */
    char* message;
    /** Ethernet header of the packet. */
    const struct ether_header* ethernet_header;
    /** IPv6 header of the packet, if any. */
    const struct ip6_hdr* ip6_header;
    /** ICMPv6 header of the packet, if the packet is an ICMPv6 message (else NULL). */
    const struct icmp6_hdr* icmp6_header;
    /** ICMPv6 type of the current message, if it is an ICMPv6 message (else 0). */
    uint8_t icmp6_type;
    /** Neighbor Discovery options, if the packet is a NDP message and options are present. */
    const struct nd_option_list* option_list;
    /** Pointer to the raw data of the packet. */
    const uint8_t* packet_data;
    /** Length of the packet. */
    int packet_length;
    /** Watch flags for the current packet that define its protocol type and further information. */
    uint16_t watch_flags;
};



/** A type definition for a common interface to watch functions (watchers).*/
typedef int (*watcher_type) (struct capture_info* const capture_information);

/** Linked list type for the list of watch functions (watchers).*/
struct watcher_list {
    /** Name of the watch function, e.g. watch_ra. */
    char* name;
    /** Pointer to the watch function, which must be of watcher_type.*/
    watcher_type watcher;
    /** Indicates for which ICMPv6 packets this watcher is called.
        A value of zero (0) means that it is called for all ICMPv6 packets.
        A non-zero value indicates that this watcher is only called for the specified ICMPv6 type.
        Use multiple watcher_list entries to register a watch function for multiple ICMPv6 types.
    */
    uint8_t      icmp6_type_match;
    /** Indicates additional criteria for this watcher to be called.
        The watcher is only called if all specified flags are set for the packet.
    */
    uint16_t     watch_flags_match;
    /** Pointer to the next watcher_list entry.*/
    struct watcher_list* next;
};

/** Adds a new watcher to the list of watch functions.
    @param name             Name of the watch function, e.g. watch_ra.
    @param watcher          Pointer to the watch function, which must be of watcher_type.
    @param icmp6_type_match Indicates for which ICMPv6 packets this watcher is called.
        A value of zero (0) means that it is called for all ICMPv6 packets.
        A non-zero value indicates that this watcher is only called for the specified ICMPv6 type.
        Use multiple watcher_list entries to register a watch function for multiple ICMPv6 types.
    @param watch_flags_match Indicates additional criteria for this watcher to be called.
        The watcher is only called if all specified flags are set for the packet.
    @return 0 on success, -1 otherwise.
*/
int  watchers_add(char* name, watcher_type watcher, uint8_t icmp6_type_match, uint16_t watch_flags_match);

/** Calls all registered watch functions for this packet according to match criteria.
    Match criteria are the ICMPv6 type of the packet and the flags which some watch functions may set.
    @return 0 on success, -1 otherwise
*/
int watchers_call(struct capture_info* const capture_info);

int  watchers_flags_isset(const uint16_t flags, const uint16_t flags_to_check);

void watchers_flags_set(uint16_t *flags, const uint16_t flags_to_set);

void watchers_flags_unset(uint16_t *flags, const uint16_t flags_to_unset);

/** Frees all entries of the watcher_list.
*/
void watchers_free();

/** Prints all entries of the watcher_list.
*/
void watchers_print();

#endif
