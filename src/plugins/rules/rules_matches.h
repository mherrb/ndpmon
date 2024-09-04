#ifndef _RULES_MATCHES_H_
#define _RULES_MATCHES_H_

/** @file
 *  Functions that are used to check if rules match a given packet.
 */

#include <stdio.h>

#include "../../core/extinfo.h"
#include "../../core/probes.h"
#include "../../core/watchers.h"
#include "rules_types.h"

extern struct rule_list* rules;

extern int DEBUG;

/** Matches a given value against a specific flag using bitwise AND with respect
 *  to the match kind (match or no_match).
 *  @param match The match used to determine the match kind.
 *  @param value The packet value to be checked.
 *  @param flag  The flag to be checked.
 */
int rule_match_and(const struct rule_match_list* const match,
        const unsigned int value, const unsigned int flag);

/** Checks all rules if they match a given packet.
 *  @param capture_info    The capture_info structure containing all
 *                         information on the captured packet.
 *  @return                0 on success (which does not mean that a
 *                         rule matched).
 */
int rule_match_all(struct capture_info* const capture_info);

/** Checks if the given ethernet address matches that of the match.
 *  @param match            The match holding the match kind and the value of
 *                          this match to check against.
 *  @param ethernet_address The ethernet address of the packet.
 *  @return                 1 if the packet matches, 0 otherwise.
 */
int rule_match_ether_addr(const struct rule_match_list* const match, const struct ether_addr* const ethernet_address);

/** Checks a given match against an ethernet header.
 *  @param match           The match.
 *  @param ethernet_header The ethernet header of the packet.
 *  @return                1 if the packet matches, 0 otherwise.
 */
int rule_match_ethernet(const struct rule_match_list* const match, const struct ether_header* const ethernet_header);

/** Checks a given match against an ICMPv6 header.
 *  @param match         The match.
 *  @param icmp6_header  The ICMPv6 header of the packet.
 *  @param packet_length The total length of the packet.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_icmp6(const struct rule_match_list* const match,
        const struct icmp6_hdr* const icmp6_header, const struct nd_option_list* option_list);

/** Checks a given IPv6 address against that of the match.
 *  @param match         The match.
 *  @param inet6_address The IPv6 address of the packet.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_in6_addr(const struct rule_match_list* const match, const struct in6_addr* const inet6_address);

/** Checks a given match against an IPv6 header.
 *  @param match      The match.
 *  @param ip6_header The IPv6 header of the packet.
 *  @return           1 if the packet matches, 0 otherwise.
 */
int rule_match_inet6(const struct rule_match_list* const match, const struct ip6_hdr* const ip6_header);

/** Checks a given match against a ND neighbor advertisement.
 *  @param match         The match.
 *  @param router_advert The neighbor advertisement.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_neighbor_advert(const struct rule_match_list* const match,
        const struct nd_neighbor_advert* const neighbor_advert);

/** Checks a given match against an option list.
 *  @param match         The match.
 *  @param option_list   The option list.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_opt(const struct rule_match_list* const match,
        const struct nd_option_list* option_list);

/** Checks a given match against an option list that may contain a
 *  prefix information option.
 *  @param match         The match.
 *  @param option_list   The option list.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_opt_prefix(const struct rule_match_list* const match,
        const struct nd_option_list* option_list);

/** Checks for a given match and a ND option type if the option is contained
 *  in the list of options of the current captured packet.
 *  @param match         The match.
 *  @param option_list   Option list.
 *  @param opt_type      Option type to check for.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_opt_type(const struct rule_match_list* const match,
        const struct nd_option_list* option_list, uint8_t opt_type);

/** Checks a given match against a ND redirect message.
 *  @param match         The match.
 *  @param redirect      The redirect message.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_redirect(const struct rule_match_list* const match,
        const struct nd_redirect* const redirect);

/** Checks a given match against a ND router advertisement.
 *  @param match         The match.
 *  @param router_advert The router advertisement.
 *  @return              1 if the packet matches, 0 otherwise.
 */
int rule_match_nd_router_advert(const struct rule_match_list* const match,
        const struct nd_router_advert* const router_advert);

/** Checks a given match against an 8bit unsigned integer with respect to
 *  the match kind (match or no_match).
 *  @param match The match.
 *  @param uint8 The number.
 *  @return      1 if the packet matches, 0 otherwise.
 */
int rule_match_uint8(const struct rule_match_list* const match, const uint8_t uint8);

/** Checks a given match against an 16bit unsigned integer with respect to
 *  the match kind (match or no_match) taking care of network byte order.
 *  @param match  The match.
 *  @param uint16 The number.
 *  @return       1 if the packet matches, 0 otherwise.
 */
int rule_match_uint16(const struct rule_match_list* const match, const uint16_t uint16);

/** Checks a given match against an 32bit unsigned integer with respect to
 *  the match kind (match or no_match) taking care of network byte order.
 *  @param match  The match.
 *  @param uint32 The number.
 *  @return       1 if the packet matches, 0 otherwise.
 */
int rule_match_uint32(const struct rule_match_list* const match, const uint32_t uint32);

#endif
