#include "rules_matches.h"

int rule_match_and(const struct rule_match_list* const match,
        const unsigned int value, const unsigned int flag) {

    if (match->kind == RULE_MATCH) {
        return (value & flag)==flag;
    }
    return !((value & flag)==flag);
}

int rule_match_all(struct capture_info* const capture_info) {
    const struct ether_header* ethernet_header = capture_info->ethernet_header;
    const struct ip6_hdr* ip6_header           = capture_info->ip6_header;
    const struct icmp6_hdr* icmp6_header       = capture_info->icmp6_header;
    const struct nd_option_list* option_list   = capture_info->option_list;
    struct rule_list* tmp_rule = NULL;
    struct probe* probe_locked;

    /* critical section: */
    probe_locked = probe_lock(capture_info->probe->name);
    tmp_rule = extinfo_list_get_data(probe_locked->extinfo, "rules");
    probe_unlock(capture_info->probe->name);
    /* end of critical section. */

    while (tmp_rule != NULL) {
        struct rule_match_list* match = tmp_rule->matches;
        int matches_all = 1;
        while (match != NULL && matches_all == 1) {
            switch (match->field) {
                case RULE_FIELD_ETHERNET_SOURCE:
                case RULE_FIELD_ETHERNET_DESTINATION:
                    matches_all = rule_match_ethernet(match, ethernet_header);
                    break;
                case RULE_FIELD_INET6_SOURCE:
                case RULE_FIELD_INET6_DESTINATION:
                case RULE_FIELD_INET6_PAYLOAD:
                case RULE_FIELD_INET6_NEXTHEADER:
                case RULE_FIELD_INET6_HOPLIMIT:
                    matches_all = rule_match_inet6(match, ip6_header);
                    break;
                default:
                    if (match->field < RULE_FIELDS_COUNT) {
                        matches_all = rule_match_icmp6(match, icmp6_header,
                                option_list);
                    } else {
                        fprintf(
                                stderr,
                                "[rules] ERROR: Unknown field type \"%u\" for matching rule \"%s\".\n",
                                match->field, tmp_rule->description);
                    }
            }
            match = match->next;
        }
        if (matches_all == 1) {
            if (DEBUG) {
                fprintf(stderr, "[rules] Matched rule %s\n",
                        tmp_rule->description);
            }
            alert_raise(1, capture_info->probe, "user defined rule matched", tmp_rule->description, (struct ether_addr*) capture_info->ethernet_header->ether_shost, NULL, &capture_info->ip6_header->ip6_src, NULL);
        }
        tmp_rule = tmp_rule->next;
    }
    return 0;
}

int rule_match_ether_addr(const struct rule_match_list* const match,
        const struct ether_addr* const ethernet_source) {

    if (match->kind == RULE_MATCH) {
        return (memcmp(&(match->value.ethernet_address), ethernet_source,
                sizeof(struct ether_addr)) == 0);
    }
    return (memcmp(&(match->value.ethernet_address), ethernet_source,
            sizeof(struct ether_addr)) != 0);
}

int rule_match_ethernet(const struct rule_match_list* const match,
        const struct ether_header* const ethernet_header) {

    switch (match->field) {
        case RULE_FIELD_ETHERNET_SOURCE:
            return rule_match_ether_addr(match,
                    (struct ether_addr*) ethernet_header->ether_shost);
        case RULE_FIELD_ETHERNET_DESTINATION:
            return rule_match_ether_addr(match,
                    (struct ether_addr*) ethernet_header->ether_dhost);
    }
    return 0;
}

int rule_match_icmp6(const struct rule_match_list* const match,
        const struct icmp6_hdr* const icmp6_header, const struct nd_option_list* option_list) {

    switch (match->field) {
        case RULE_FIELD_ICMP6_TYPE:
            return rule_match_uint8(match, icmp6_header->icmp6_type);
        case RULE_FIELD_ICMP6_CODE:
            return rule_match_uint8(match, icmp6_header->icmp6_code);
        case RULE_FIELD_ND_RS:
            if (match->kind == RULE_MATCH) {
                return (icmp6_header->icmp6_type == ND_ROUTER_SOLICIT);
            }
            return (icmp6_header->icmp6_type == ND_ROUTER_SOLICIT);
        case RULE_FIELD_ND_RA:
            if (match->kind == RULE_MATCH) {
                return (icmp6_header->icmp6_type == ND_ROUTER_ADVERT);
            }
            return (icmp6_header->icmp6_type == ND_ROUTER_ADVERT);
        case RULE_FIELD_ND_NS:
            if (match->kind == RULE_MATCH) {
                return (icmp6_header->icmp6_type == ND_NEIGHBOR_SOLICIT);
            }
            return (icmp6_header->icmp6_type == ND_NEIGHBOR_SOLICIT);
        case RULE_FIELD_ND_NA:
            if (match->kind == RULE_MATCH) {
                return (icmp6_header->icmp6_type == ND_NEIGHBOR_ADVERT);
            }
            return (icmp6_header->icmp6_type == ND_NEIGHBOR_ADVERT);
        case RULE_FIELD_ND_RD:
            if (match->kind == RULE_MATCH) {
                            return (icmp6_header->icmp6_type == ND_REDIRECT);
                        }
                        return (icmp6_header->icmp6_type == ND_REDIRECT);
        case RULE_FIELD_ND_RA_CURHOPLIMIT:
        case RULE_FIELD_ND_RA_FLAG_MANAGED:
        case RULE_FIELD_ND_RA_FLAG_OTHER:
        case RULE_FIELD_ND_RA_FLAG_HOMEAGENT:
        case RULE_FIELD_ND_RA_LIFETIME:
        case RULE_FIELD_ND_RA_REACHABLETIMER:
        case RULE_FIELD_ND_RA_RETRANSTIMER:
            if (icmp6_header->icmp6_type==ND_ROUTER_ADVERT) {
                return rule_match_nd_router_advert(match, (struct nd_router_advert*)icmp6_header);
            }
            fprintf(stderr, "[rules] WARNING: Tried to match a router advertisement "
                    "field on a packet that is no router advertisement.\n");
            return 0;
        case RULE_FIELD_ND_NS_TARGETADDRESS:
            if (icmp6_header->icmp6_type==ND_NEIGHBOR_SOLICIT) {
                            return rule_match_in6_addr(
                        match,
                        &((struct nd_neighbor_solicit*) icmp6_header)->nd_ns_target);
            }
            fprintf(stderr, "[rules] WARNING: Tried to match a neighbor advertisement "
                "field on a packet that is no neighbor advertisement.\n");
            return 0;
        case RULE_FIELD_ND_NA_FLAG_ROUTER:
        case RULE_FIELD_ND_NA_FLAG_SOLICITED:
        case RULE_FIELD_ND_NA_FLAG_OVERRIDE:
        case RULE_FIELD_ND_NA_TARGETADDRESS:
            if (icmp6_header->icmp6_type==ND_NEIGHBOR_ADVERT) {
                return rule_match_nd_neighbor_advert(match, (struct nd_neighbor_advert*)icmp6_header);
            }
            fprintf(stderr, "[rules] WARNING: Tried to match a neighbor advertisement "
                    "field on a packet that is no neighbor advertisement.\n");
            return 0;
        case RULE_FIELD_ND_RD_TARGETADDRESS:
        case RULE_FIELD_ND_RD_DESTINATIONADDRESS:
            if (icmp6_header->icmp6_type==ND_REDIRECT) {
                return rule_match_nd_redirect(match, (struct nd_redirect*)icmp6_header);
            }
            fprintf(stderr, "[rules] WARNING: Tried to match a redirect "
                    "field on a packet that is no redirect message.\n");
            return 0;
        default:
            return rule_match_nd_opt(match, option_list);
    }
    return 0;
}

int rule_match_in6_addr(const struct rule_match_list* const match,
        const struct in6_addr* const inet6_address) {
    uint8_t address1_prefixed[sizeof(struct in6_addr)];
    uint8_t address2_prefixed[sizeof(struct in6_addr)];
    uint8_t prefix_mask[sizeof(struct in6_addr)];
    uint8_t address_index;
    /* preparation for the prefix initialization */
    uint8_t bits_to_zero = 128 - match->value.inet6.prefix;
    uint8_t bytes_to_zero = bits_to_zero / 8;
    uint8_t remaining_bits = bits_to_zero % 8;
    uint8_t* prefix_mask_ptr = (uint8_t*) &prefix_mask;

    /* setting prefix mask to all 1: */
    memset(prefix_mask_ptr, UINT8_MAX, sizeof(struct in6_addr));

    /* setting unused bits of prefix mask to zero */
    memset(prefix_mask_ptr + 16 - bytes_to_zero, 0, bytes_to_zero);
    if (remaining_bits > 0) {
        prefix_mask_ptr[15 - bytes_to_zero] = (prefix_mask_ptr[15
                - bytes_to_zero] >> (remaining_bits)) << (remaining_bits);
    }
    /* for each byte do a bitwise and of prefix mask with the rule's addr:*/
    for (address_index = 0; address_index < sizeof(struct in6_addr); address_index++) {
        address1_prefixed[address_index]
                = (((uint8_t*) &(match->value.inet6.address))[address_index])
                        & prefix_mask[address_index];
        address2_prefixed[address_index]
                = (((uint8_t*) inet6_address)[address_index])
                        & prefix_mask[address_index];
    }
    /* switch according to match type: */
    if (match->kind == RULE_MATCH) {
        return (memcmp(address1_prefixed, address2_prefixed,
                sizeof(struct in6_addr)) == 0);
    }
    return (memcmp(address1_prefixed, address2_prefixed,
            sizeof(struct in6_addr)) != 0);
}

int rule_match_inet6(const struct rule_match_list* const match,
        const struct ip6_hdr* const inet6_header) {
    switch (match->field) {
        case RULE_FIELD_INET6_SOURCE:
            return rule_match_in6_addr(match, &inet6_header->ip6_src);
        case RULE_FIELD_INET6_DESTINATION:
            return rule_match_in6_addr(match, &inet6_header->ip6_dst);
        case RULE_FIELD_INET6_PAYLOAD:
            return rule_match_uint16(match, inet6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
        case RULE_FIELD_INET6_NEXTHEADER:
            return rule_match_uint8(match, inet6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        case RULE_FIELD_INET6_HOPLIMIT:
            return rule_match_uint8(match, inet6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    }
    fprintf(stderr, "[rules] ERROR: Unknown field %i in match_inet6.\n", match->field);
    return 0;
}

int rule_match_nd_neighbor_advert(const struct rule_match_list* const match,
        const struct nd_neighbor_advert* const neighbor_advert) {

    switch (match->field) {
        case RULE_FIELD_ND_NA_FLAG_ROUTER:
            return rule_match_and(match, neighbor_advert->nd_na_flags_reserved, ND_NA_FLAG_ROUTER);
        case RULE_FIELD_ND_NA_FLAG_SOLICITED:
            return rule_match_and(match, neighbor_advert->nd_na_flags_reserved, ND_NA_FLAG_SOLICITED);
        case RULE_FIELD_ND_NA_FLAG_OVERRIDE:
            return rule_match_and(match, neighbor_advert->nd_na_flags_reserved, ND_NA_FLAG_OVERRIDE);
        case RULE_FIELD_ND_NA_TARGETADDRESS:
            return rule_match_in6_addr(match, &neighbor_advert->nd_na_target);
    }
    fprintf(stderr, "[rules] ERROR: Unknown field %i in match_nd_neighbor_advert.\n", match->field);
    return 0;
}

int rule_match_nd_opt(const struct rule_match_list* const match,
        const struct nd_option_list* option_list) {
    switch (match->field) {
        case RULE_FIELD_ND_OPT_SOURCELINKLAYER:
            return rule_match_nd_opt_type(match, option_list, ND_OPT_SOURCE_LINKADDR);
        case RULE_FIELD_ND_OPT_TARGETLINKLAYER:
            return rule_match_nd_opt_type(match, option_list, ND_OPT_TARGET_LINKADDR);
        case RULE_FIELD_ND_OPT_PREFIXINFO:
            return rule_match_nd_opt_type(match, option_list, ND_OPT_PREFIX_INFORMATION);
        case RULE_FIELD_ND_OPT_MTU:
            return rule_match_nd_opt_type(match, option_list, ND_OPT_MTU);
        case RULE_FIELD_ND_OPT_SOURCELINKLAYER_ADDRESS:
            while (option_list!=NULL) {
                    if (option_list->option_data.option_header.nd_opt_type==ND_OPT_SOURCE_LINKADDR) {
                        return rule_match_ether_addr(match, &option_list->option_data.linklayer.ethernet_address);
                    }
                    option_list = option_list->next;
                }
            /* option not found: */
            if (match->kind==RULE_MATCH) {
                return 0;
            }
            return 1;
        case RULE_FIELD_ND_OPT_TARGETLINKLAYER_ADDRESS:
            while (option_list!=NULL) {
                    if (option_list->option_data.option_header.nd_opt_type==ND_OPT_TARGET_LINKADDR) {
                        return rule_match_ether_addr(match, &option_list->option_data.linklayer.ethernet_address);
                    }
                    option_list = option_list->next;
                }
            /* option not found: */
            if (match->kind==RULE_MATCH) {
                return 0;
            }
            return 1;
        case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_ONLINK:
        case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_AUTOCONF:
        case RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX:
            return rule_match_nd_opt_prefix(match, option_list);
        case RULE_FIELD_ND_OPT_MTU_MTU:
            while (option_list!=NULL) {
                    if (option_list->option_data.option_header.nd_opt_type==ND_OPT_TARGET_LINKADDR) {
                        return rule_match_uint32(match, option_list->option_data.mtu.nd_opt_mtu_mtu);
                    }
                    option_list = option_list->next;
                }
            /* option not found: */
            if (match->kind==RULE_MATCH) {
                return 0;
            }
            return 1;

    }
    fprintf(stderr, "[rules] ERROR: Unknown field %i in match_nd_opt.\n", match->field);
    return 0;

}

int rule_match_nd_opt_prefix(const struct rule_match_list* const match,
        const struct nd_option_list* option_list) {
    while (option_list!=NULL) {
        if (option_list->option_data.option_header.nd_opt_type==ND_OPT_PREFIX_INFORMATION) {
            const struct nd_opt_prefix_info* prefix_info=&option_list->option_data.prefix_info;
            switch (match->field) {
                case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_ONLINK:
                                    return rule_match_and(match, prefix_info->nd_opt_pi_flags_reserved, ND_OPT_PI_FLAG_ONLINK);
                case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_AUTOCONF:
                    return rule_match_and(match, prefix_info->nd_opt_pi_flags_reserved, ND_OPT_PI_FLAG_AUTO);
                case RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME:
                    return rule_match_uint32(match, prefix_info->nd_opt_pi_valid_time);
                case RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME:
                    return rule_match_uint32(match, prefix_info->nd_opt_pi_preferred_time);
                case RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX:
                    return rule_match_in6_addr(match, &prefix_info->nd_opt_pi_prefix);
            }
            fprintf(stderr, "[rules] ERROR: Unknown field %i in match_nd_opt_prefix.\n", match->field);
            return 0;
        }
        option_list = option_list->next;
    }
    /* option not found: */
    if (match->kind==RULE_MATCH) {
        return 0;
    }
    return 1;
}

int rule_match_nd_opt_type(const struct rule_match_list* const match,
        const struct nd_option_list* option_list, uint8_t opt_type) {
    while (option_list!=NULL) {
        if (option_list->option_data.option_header.nd_opt_type==opt_type) {
            /* given option found: */
            if (match->kind==RULE_MATCH) {
                return 1;
            }
            return 0;
        }
        option_list = option_list->next;
    }
    /* given option was not found: */
    if (match->kind == RULE_MATCH) {
        return 0;
    }
    return 1;
}

int rule_match_nd_redirect(const struct rule_match_list* const match,
        const struct nd_redirect* const redirect) {
    switch (match->field) {
        case RULE_FIELD_ND_RD_TARGETADDRESS:
            return rule_match_in6_addr(match, &redirect->nd_rd_target);
        case RULE_FIELD_ND_RD_DESTINATIONADDRESS:
            return rule_match_in6_addr(match, &redirect->nd_rd_dst);
    }
    fprintf(stderr, "[rules] ERROR: Unknown field %i in match_nd_redirect.\n", match->field);
    return 0;
}

int rule_match_nd_router_advert(const struct rule_match_list* const match,
        const struct nd_router_advert* const router_advert) {

    switch (match->field) {
        case RULE_FIELD_ND_RA_CURHOPLIMIT:
            return rule_match_uint8(match, router_advert->nd_ra_curhoplimit);
        case RULE_FIELD_ND_RA_FLAG_MANAGED:
            return rule_match_and(match, router_advert->nd_ra_flags_reserved, ND_RA_FLAG_MANAGED);
        case RULE_FIELD_ND_RA_FLAG_OTHER:
            return rule_match_and(match, router_advert->nd_ra_flags_reserved, ND_RA_FLAG_OTHER);
        case RULE_FIELD_ND_RA_FLAG_HOMEAGENT:
            return rule_match_and(match, router_advert->nd_ra_flags_reserved, ND_RA_FLAG_HOME_AGENT);
        case RULE_FIELD_ND_RA_LIFETIME:
            return rule_match_uint16(match, router_advert->nd_ra_router_lifetime);
        case RULE_FIELD_ND_RA_REACHABLETIMER:
            return rule_match_uint32(match, router_advert->nd_ra_reachable);
        case RULE_FIELD_ND_RA_RETRANSTIMER:
            return rule_match_uint32(match, router_advert->nd_ra_retransmit);
    }
    fprintf(stderr, "[rules] ERROR: Unknown field %i in match_nd_router_advert.\n", match->field);
    return 0;
}

int rule_match_uint8(const struct rule_match_list* const match, const uint8_t uint8) {
    if (match->kind == RULE_MATCH) {
        return match->value.uint8 == uint8;
    }
    return match->value.uint8 != uint8;
}

int rule_match_uint16(const struct rule_match_list* const match, const uint16_t uint16) {
    /* beaware of network byte order: */
    if (match->kind == RULE_MATCH) {
        return match->value.uint16 == ntohs(uint16);
    }
    return match->value.uint16 != ntohs(uint16);
}

int rule_match_uint32(const struct rule_match_list* const match, const uint32_t uint32) {
    /* beaware of network byte order: */
        if (match->kind == RULE_MATCH) {
            return match->value.uint32 == ntohl(uint32);
        }
        return match->value.uint32 != ntohl(uint32);
}
