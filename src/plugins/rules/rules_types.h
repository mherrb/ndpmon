#ifndef _RULES_TYPES_H_
#define _RULES_TYPES_H_

/** @file
 *  Common definitions and type declarations for the rules plugin.
 */

#include <stdint.h>

#include "../../ndpmon_netheaders.h"

#define RULE_DESCRIPTION_SIZE 120
#define RULE_MATCH_VALUE_SIZE 120
#define RULE_FIELD_SIZE       60
#define RULE_MATCH_KIND_SIZE  120
#define RULE_FIELDS_COUNT     40
/* ethernet fields: */
#define RULE_FIELD_ETHERNET_SOURCE                    0 /* : eth */
#define RULE_FIELD_ETHERNET_DESTINATION               1 /* : eth */
/* ipv6 fields: */
#define RULE_FIELD_INET6_SOURCE                       2 /* : ip */
#define RULE_FIELD_INET6_DESTINATION                  3 /* : ip */
#define RULE_FIELD_INET6_PAYLOAD                      4 /* : uint16 */
#define RULE_FIELD_INET6_NEXTHEADER                   5 /* : uint8 */
#define RULE_FIELD_INET6_HOPLIMIT                     6 /* : uint8 */
/* general icmpv6 fields: */
#define RULE_FIELD_ICMP6_TYPE                         7 /* : uint8 */
#define RULE_FIELD_ICMP6_CODE                         8 /* : uint8 */
/* neighbor discovery specific: */
#define RULE_FIELD_ND_RS                              9 /* : void */
#define RULE_FIELD_ND_RA                              10 /* : void */
#define RULE_FIELD_ND_NS                              11 /* : void */
#define RULE_FIELD_ND_NA                              12 /* : void */
#define RULE_FIELD_ND_RD                              13 /* : void */
/* router advertisements: */
#define RULE_FIELD_ND_RA_CURHOPLIMIT                  14 /* : uint8 */
#define RULE_FIELD_ND_RA_FLAG_MANAGED                 15 /* : void */
#define RULE_FIELD_ND_RA_FLAG_OTHER                   16 /* : void */
#define RULE_FIELD_ND_RA_FLAG_HOMEAGENT               17 /* : void */
#define RULE_FIELD_ND_RA_LIFETIME                     18 /* : uint16 */
#define RULE_FIELD_ND_RA_REACHABLETIMER               19 /* : uint32 */
#define RULE_FIELD_ND_RA_RETRANSTIMER                 20 /* : uint32 */
/* neighbor solicitation: */
#define RULE_FIELD_ND_NS_TARGETADDRESS                21 /* : ip */
/* neighbor advertisement: */
#define RULE_FIELD_ND_NA_FLAG_ROUTER                  22 /* : void */
#define RULE_FIELD_ND_NA_FLAG_SOLICITED               23 /* : void */
#define RULE_FIELD_ND_NA_FLAG_OVERRIDE                24 /* : void */
#define RULE_FIELD_ND_NA_TARGETADDRESS                25 /* : ip */
/* redirect message: */
#define RULE_FIELD_ND_RD_TARGETADDRESS                26 /* : ip */
#define RULE_FIELD_ND_RD_DESTINATIONADDRESS           27 /* : ip */
/* options: */
#define RULE_FIELD_ND_OPT_SOURCELINKLAYER             28 /* : void */
#define RULE_FIELD_ND_OPT_TARGETLINKLAYER             29 /* : void */
#define RULE_FIELD_ND_OPT_PREFIXINFO                  30 /* : void */
#define RULE_FIELD_ND_OPT_MTU                         31 /* : void */
/* option source linklayer: */
#define RULE_FIELD_ND_OPT_SOURCELINKLAYER_ADDRESS    32 /* : eth */
/* option target linklayer: */
#define RULE_FIELD_ND_OPT_TARGETLINKLAYER_ADDRESS    33 /* : eth */
/* option prefix information: */
#define RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_ONLINK      34 /* : void */
#define RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_AUTOCONF    35 /* : void */
#define RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME    36 /* : uint32 */
#define RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME 37 /* : uint32 */
#define RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX           38 /* : ip */
/* option mtu: */
#define RULE_FIELD_ND_OPT_MTU_MTU                     39 /* uint32 */


#define RULE_MATCH         200
#define RULE_NO_MATCH      201

/** Holds a list of rules.
*/
struct rule_list {
    /** Description of the rule, will be displayed in any alert triggered by this rule.
    */
    char description[RULE_DESCRIPTION_SIZE];
    /** Pointer to the first criteria that must match for this rule to be applied.
    */
    struct rule_match_list* matches;
    /** Pointer to the first export of this rule. An export defines what fields will
        be included in an alert triggered by this rule.
    */
    struct rule_export_list* exports;
    /** Pointer to the next rule list entry.
    */
    struct rule_list* next;
};

/** A type for the NDP packet fields that can be queried in a match.
*/
typedef uint8_t rule_field_t;

/** A type for the different kinds of matches.
*/
typedef uint8_t rule_match_kind_t;

/** Union to hold the different types of value for the different fields of
 *  packets.
 */
union rule_match_value {
    /** Value access for unsigned 8 bit integers. */
    uint8_t uint8;
    /** Value access for unsigned 16 bit integers. Value is assumed to be
     * in host byte order.
     */
    uint16_t uint16;
    /** Value access for unsigned 32 bit integers. Value is assumed to be in
     *  host byte order.
     */
    uint32_t uint32;
    /** Value access for ethernet addresses. */
    struct ether_addr ethernet_address;
    /** Nested structure to provide access to an IPv6 address and a prefix mask.
     */
    struct {
        /**The IPv6 address.*/
        struct in6_addr address;
        /** Number of valid bits in the address.*/
        uint8_t         prefix;
    } inet6;
};

/** Holds a list of matches.
*/
struct rule_match_list {
    /** The field of the NDP packet against which this rule is matched.
    */
    rule_field_t field;
    /** Describes whether the match is an exclusion criteria (no-match).
    */
    rule_match_kind_t kind;
    /** The value or value alias of this match.
    */
    union rule_match_value value;
    /** Pointer to the next match list entry.
    */
    struct rule_match_list* next;
};

#endif
