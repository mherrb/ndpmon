#include "rules.h"

static char rule_field_translations[RULE_FIELDS_COUNT][RULE_FIELD_SIZE];
static int  rule_field_translations_initialized = 0;

void rule_field_to_str(const rule_field_t field, char* const res) {

    memset(res, 0, RULE_FIELD_SIZE );
    if (field > (RULE_FIELDS_COUNT-1)) {
        strlcpy(res, "UNKNOWN", RULE_FIELD_SIZE);
        return;
    }
    strlcpy(res, rule_field_translations[field], RULE_FIELD_SIZE);
}

void rule_field_translations_init() {
    if (rule_field_translations_initialized!=0) {
        return;
    }
    strlcpy(rule_field_translations[RULE_FIELD_ETHERNET_SOURCE]
                            , "ethernet.source", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ETHERNET_DESTINATION]
                            , "ethernet.destination", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_INET6_SOURCE]
                            , "inet6.source", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_INET6_DESTINATION]
                            , "inet6.destination", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_INET6_PAYLOAD]
                            , "inet6.payload", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_INET6_NEXTHEADER]
                            , "inet6.nextheader", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_INET6_HOPLIMIT]
                            , "inet6.hoplimit", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ICMP6_TYPE]
                            , "icmp6.type", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ICMP6_CODE]
                            , "icmp6.code", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RS]
                            , "nd.rs", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA]
                            , "nd.ra", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NS]
                            , "nd.ns", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NA]
                            , "nd.na", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RD]
                                , "nd.rd", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_CURHOPLIMIT]
                            , "nd.ra.curhoplimit", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_FLAG_MANAGED]
                            , "nd.ra.flag.managed", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_FLAG_OTHER]
                            , "nd.ra.flag.other", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_FLAG_HOMEAGENT]
                            , "nd.ra.flag.homeagent", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_LIFETIME]
                            , "nd.ra.lifetime", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_REACHABLETIMER ]
                            , "nd.ra.reachabletimer", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RA_RETRANSTIMER]
                            , "nd.ra.retranstimer", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NS_TARGETADDRESS]
                            , "nd.ns.targetaddress", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NA_FLAG_ROUTER]
                            , "nd.na.flag.router", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NA_FLAG_SOLICITED]
                            , "nd.na.flag.solicited", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NA_FLAG_OVERRIDE]
                            , "nd.na.flag.override", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_NA_TARGETADDRESS]
                            , "nd.na.targetaddress", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RD_TARGETADDRESS]
                            , "nd.rd.targetaddress", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_RD_DESTINATIONADDRESS]
                            , "nd.rd.destinationaddress", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_SOURCELINKLAYER]
                            , "nd.opt.sourcelinklayer", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_TARGETLINKLAYER]
                            , "nd.opt.targetlinklayer", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO]
                            , "nd.opt.prefixinfo", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_MTU]
                            , "nd.opt.mtu", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_SOURCELINKLAYER_ADDRESS]
                            , "nd.opt.sourcelinklayer.address", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_TARGETLINKLAYER_ADDRESS]
                            , "nd.opt.targetlinklayer.address", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_ONLINK]
                            , "nd.opt.prefixinfo.flag.onlink", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_AUTOCONF]
                            , "nd.opt.prefixinfo.flag.autoconf", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME]
                            , "nd.opt.prefixinfo.validlifetime", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME]
                            , "nd.opt.prefixinfo.preferredlifetime", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX]
                            , "nd.opt.prefixinfo.prefix", RULE_FIELD_SIZE);
    strlcpy(rule_field_translations[RULE_FIELD_ND_OPT_MTU_MTU]
                            , "nd.opt.mtu.mtu", RULE_FIELD_SIZE);
    if (DEBUG) {
        int x;
        for (x=0; x< RULE_FIELDS_COUNT; x++) {
            fprintf(stderr, "%s\n", rule_field_translations[x]);
        }
    }
    rule_field_translations_initialized = 1;
}

int rule_list_add(struct rule_list** rules, char* description, struct rule_match_list* matches,
        struct rule_export_list* exports) {
    struct rule_list* tmp_rules=*rules;
    struct rule_list* new_rule=NULL;
    
    /* initialize fields: */
    if ((new_rule=malloc(sizeof(struct rule_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    if (description==NULL || matches==NULL) {
        fprintf(stderr, "[rules] ERROR: unitialized rule information.");
        return -1;
    }
    memset(new_rule->description, 0, RULE_DESCRIPTION_SIZE);
    strlcpy(new_rule->description, description, RULE_DESCRIPTION_SIZE);
    new_rule->matches = matches;
    new_rule->exports = exports;
    new_rule->next = NULL; /* keep the list terminated */
    
    if (*rules==NULL) {
        /* if the rules list is empty the new rule becomes the global list: */
        *rules = new_rule;
    } else {
        /* else we have to walk through the list and append the new rule to the end: */
        while (tmp_rules->next!=NULL) {
            tmp_rules = tmp_rules->next;
        }
        tmp_rules->next = new_rule;
    }
    return 0;
}

void rule_list_free(void** data) {
    struct rule_list* rules = *data;
    while (rules!=NULL) {
        struct rule_list* current=rules;
        rules=(rules)->next;
        rule_match_list_free(&current->matches);
        free(current);
    }
}

int rule_list_load (xmlNodePtr element, void** data) {
    struct rule_list* rules=NULL;
    xmlNodePtr rule = element->children;

    rule_field_translations_init();
    while(rule!=NULL) {
        if (rule->type == XML_ELEMENT_NODE && STRCMP(rule->name,"rule")==0) {
            char* description=NULL;
            struct rule_match_list* matches=NULL;
            xmlAttrPtr rule_attr  = rule->properties;
            xmlNodePtr rule_child = rule->children;

            while (rule_attr!=NULL) {
                if (rule_attr->type!=XML_ATTRIBUTE_NODE) {
                    rule_attr = rule_attr->next;
                    continue;
                }
                if (STRCMP(rule_attr->name,"description")==0) {
                    description = (char*)XML_GET_CONTENT(rule_attr->children);
                rule_attr = rule_attr->next;
                }
            }
            while (rule_child!=NULL) {
                if (rule_child->type == XML_ELEMENT_NODE
                        && (STRCMP(rule_child->name,"match")==0
                        || STRCMP(rule_child->name, "no_match")==0)) {
                    rule_field_t match_field=0;
                    rule_match_kind_t match_kind=0;
                    union rule_match_value match_value;
                    char* match_value_str=NULL;
                    xmlAttrPtr match_child = rule_child->properties;

                    while (match_child!=NULL) {
                        if (match_child->type != XML_ATTRIBUTE_NODE) {
                            match_child = match_child->next;
                            continue;
                        }
                        /* we have a param: */
                        if (STRCMP(match_child->name, "field")==0) {
                            if (rule_str_to_field((char*)match_child->children->content, &match_field)!=0) {
                                fprintf(stderr, "[rules] parsing XML rules: WARNING: invalid match field %s\n", (char*)XML_GET_CONTENT(match_child->children));
                            }
                        } else if (STRCMP(match_child->name, "value")==0) {
                            match_value_str = (char*)XML_GET_CONTENT(match_child->children);
                        }
                        match_child = match_child->next;
                    }
                    if (rule_str_to_value(match_value_str, match_field, &match_value)!=0) {
                        fprintf(stderr, "[rules] parsing XML rules: WARNING: invalid match value %s\n", match_value_str);
                    }
                    if (STRCMP(rule_child->name,"match")==0) {
                        match_kind = RULE_MATCH;
                    } else {
                        match_kind = RULE_NO_MATCH;
                    }
                    rule_match_list_add(&matches, match_field, match_kind, &match_value);
                }
                rule_child = rule_child->next;
            }      
            rule_list_add(&rules, description, matches, NULL);
        }
        rule = rule->next;
    }
    *data = rules;
    return 0;
}

void rule_list_print(void* data) {
    const struct rule_list* tmp_rules=data;

    fprintf(stderr, "[rules] all rules: {\n");
    while (tmp_rules!=NULL) {
        fprintf(stderr, "    %s: {\n", tmp_rules->description);
        rule_match_list_print(tmp_rules->matches);
        fprintf(stderr, "    }\n");
        tmp_rules = tmp_rules->next;
    }
    fprintf(stderr, "}\n");
}

int rule_list_save(xmlNodePtr rules_element, void* data) {
    struct rule_list* tmp_rules=(struct rule_list*) data;

    /* store all rules: */
    while (tmp_rules!=NULL) {
        xmlNodePtr rule_element;
        struct rule_match_list* rule_matches = tmp_rules->matches;

        /* create a new element for this rule and add description: */
        rule_element = xmlNewChild(rules_element, NULL, BAD_CAST "rule", NULL);
        xmlNewProp(rule_element, BAD_CAST "description", BAD_CAST &tmp_rules->description);
        /* store all rule matches:*/
        while (rule_matches!=NULL) {
            xmlNodePtr match_element;
            char field_str[RULE_FIELD_SIZE];
            char value_str[RULE_MATCH_VALUE_SIZE];

            /* convert match field and value to string: */
            rule_field_to_str(rule_matches->field, field_str);
            rule_match_value_to_str(&rule_matches->value, rule_matches->field, value_str);
            /* add the information to the XML DOM: */
            match_element = xmlNewChild(rule_element, NULL, BAD_CAST "match", NULL);
            xmlNewProp(match_element, BAD_CAST "field", BAD_CAST field_str);
            xmlNewProp(match_element, BAD_CAST "value", BAD_CAST value_str);
            /* fetch next rule match: */
            rule_matches = rule_matches->next;
        }
        /* fetch next rule: */
        tmp_rules = tmp_rules->next;
    }
    return 0;
}

int rule_match_list_add(struct rule_match_list** matches, rule_field_t field, rule_match_kind_t match_kind, union rule_match_value* match_value) {
    struct rule_match_list* tmp_matches=*matches;
    struct rule_match_list* new_match;
    
    /* initialize fields: */
    if ((new_match=malloc(sizeof(struct rule_match_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    memcpy(&new_match->value, match_value, sizeof(union rule_match_value));
    new_match->field = field;
    new_match->kind = match_kind;
    new_match->next = NULL; /* keep the list terminated */

    if (*matches==NULL) {
        /* if the given list is empty the new match will be the new list: */
        *matches=new_match;
    } else {
        while (tmp_matches->next!=NULL) {
            tmp_matches = tmp_matches->next;
        }
        tmp_matches->next = new_match;
    }
    return 0;
}

void rule_match_list_free(struct rule_match_list** matches) {

    while (*matches!=NULL) {
        struct rule_match_list* current=*matches;
        *matches = (*matches)->next;
        free(current);
    }
}

void rule_match_list_print(struct rule_match_list* matches) {
    char field_str[RULE_FIELD_SIZE];
    char value_str[RULE_MATCH_VALUE_SIZE];

    while (matches!=NULL) {
        rule_field_to_str(matches->field, field_str);
        rule_match_value_to_str(&matches->value, matches->field, value_str);
        fprintf(
            stderr, "        %s %s %s\n",
            (matches->kind==RULE_MATCH ? "match" : "no match"),
            field_str,
            value_str
        );
        matches = matches->next;
    }
}

void rule_match_value_to_str(const union rule_match_value* const value,
        const rule_field_t field, char* res) {
    char temp[RULE_MATCH_VALUE_SIZE];

    memset(res, 0, RULE_MATCH_VALUE_SIZE);
    memset(temp, 0, RULE_MATCH_VALUE_SIZE);
    switch (field) {
        /* integer fields: */
        /* fields of type uint8: */
        case RULE_FIELD_INET6_NEXTHEADER:
        case RULE_FIELD_INET6_HOPLIMIT:
        case RULE_FIELD_ICMP6_TYPE:
        case RULE_FIELD_ICMP6_CODE:
        case RULE_FIELD_ND_RA_CURHOPLIMIT:
            sprintf(res, "%u", value->uint8);
            break;
            /* fields of type uint16: */
        case RULE_FIELD_INET6_PAYLOAD:
        case RULE_FIELD_ND_RA_LIFETIME:
            sprintf(res, "%u", value->uint16);
            break;
            /* fields of type uint32: */
        case RULE_FIELD_ND_RA_REACHABLETIMER:
        case RULE_FIELD_ND_RA_RETRANSTIMER:
        case RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME:
        case RULE_FIELD_ND_OPT_MTU_MTU:
            sprintf(res, "%u", value->uint32);
            break;
            /* fields of type struct ether_addr: */
        case RULE_FIELD_ETHERNET_SOURCE:
        case RULE_FIELD_ETHERNET_DESTINATION:
        case RULE_FIELD_ND_OPT_SOURCELINKLAYER_ADDRESS:
        case RULE_FIELD_ND_OPT_TARGETLINKLAYER_ADDRESS:
            strlcpy(res, ether_ntoa(&value->ethernet_address),
                    RULE_MATCH_VALUE_SIZE);
            break;
            /* fields of type struct in6_addr: */
        case RULE_FIELD_INET6_SOURCE:
        case RULE_FIELD_INET6_DESTINATION:
        case RULE_FIELD_ND_NS_TARGETADDRESS:
        case RULE_FIELD_ND_NA_TARGETADDRESS:
        case RULE_FIELD_ND_RD_TARGETADDRESS:
        case RULE_FIELD_ND_RD_DESTINATIONADDRESS:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX:
            inet_ntop(AF_INET6, &value->inet6.address, temp,
                    RULE_MATCH_VALUE_SIZE - 1);
            sprintf(res, "%s/%u", temp, value->inet6.prefix);
            break;
        default:
            strlcpy(res, "UNKNOWN", RULE_FIELD_SIZE);
    }
}


int rule_str_to_field(const char* const field, rule_field_t* res) {
    int x;

    for (x=0; x< RULE_FIELDS_COUNT; x++) {
        if (strncmp(field, rule_field_translations[x], RULE_FIELD_SIZE)==0) {
            *res = x;
            return 0;
        }
    }
    /* no such field found: */
    return -1;
}

int rule_str_to_value(const char* const value_str, const rule_field_t field,
        union rule_match_value* const value_union) {
    char temp[RULE_MATCH_VALUE_SIZE];
    char* pos = NULL;
    int temp_value = value_str==NULL? 0 : atoi(value_str);
    char field_str[RULE_FIELD_SIZE];

    memset(value_union, 0, sizeof(union rule_match_value));
    memset(temp, 0, RULE_MATCH_VALUE_SIZE);

    rule_field_to_str(field, field_str);
    switch (field) {
        /* void fields (fields without value: */
        case RULE_FIELD_ND_RS:
        case RULE_FIELD_ND_RA:
        case RULE_FIELD_ND_NS:
        case RULE_FIELD_ND_NA:
        case RULE_FIELD_ND_RD:
        case RULE_FIELD_ND_RA_FLAG_MANAGED:
        case RULE_FIELD_ND_RA_FLAG_OTHER:
        case RULE_FIELD_ND_RA_FLAG_HOMEAGENT:
        case RULE_FIELD_ND_NA_FLAG_ROUTER:
        case RULE_FIELD_ND_NA_FLAG_SOLICITED:
        case RULE_FIELD_ND_NA_FLAG_OVERRIDE:
        case RULE_FIELD_ND_OPT_SOURCELINKLAYER:
        case RULE_FIELD_ND_OPT_TARGETLINKLAYER:
        case RULE_FIELD_ND_OPT_PREFIXINFO:
        case RULE_FIELD_ND_OPT_MTU:
        case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_ONLINK:
        case RULE_FIELD_ND_OPT_PREFIXINFO_FLAG_AUTOCONF:
            return 0;
            /* fields of type uint8: */
        case RULE_FIELD_INET6_NEXTHEADER:
        case RULE_FIELD_INET6_HOPLIMIT:
        case RULE_FIELD_ICMP6_TYPE:
        case RULE_FIELD_ICMP6_CODE:
        case RULE_FIELD_ND_RA_CURHOPLIMIT:
            if ((temp_value) > UINT8_MAX) {
                fprintf(stderr,
                        "[rules] WARNING: value %u of field %s exceeds 8bit unsigned integer range.\n",
                        temp_value, field_str);
            }
            value_union->uint8 = temp_value;
            return 0;
            /* fields of type uint16: */
        case RULE_FIELD_INET6_PAYLOAD:
        case RULE_FIELD_ND_RA_LIFETIME:
            if ((temp_value) > UINT16_MAX) {
                fprintf(stderr,
                        "[rules] WARNING: value %u of field %s exceeds 16bit unsigned integer range.\n",
                        temp_value, field_str);
            }
            value_union->uint16 = temp_value;
            return 0;
            /* fields of type uint32: */
        case RULE_FIELD_ND_RA_REACHABLETIMER:
        case RULE_FIELD_ND_RA_RETRANSTIMER:
        case RULE_FIELD_ND_OPT_PREFIXINFO_VALIDLIFETIME:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFERREDLIFETIME:
        case RULE_FIELD_ND_OPT_MTU_MTU:
            if ((temp_value) > UINT32_MAX) {
                fprintf(stderr,
                        "[rules] WARNING: value %u of field %s exceeds 32bit unsigned integer range.\n",
                        temp_value, field_str);
            }
            value_union->uint32 = temp_value;
            return 0;
            /* fields of type struct ether_addr: */
        case RULE_FIELD_ETHERNET_SOURCE:
        case RULE_FIELD_ETHERNET_DESTINATION:
        case RULE_FIELD_ND_OPT_SOURCELINKLAYER_ADDRESS:
        case RULE_FIELD_ND_OPT_TARGETLINKLAYER_ADDRESS:
            memcpy(&value_union->ethernet_address, ether_aton(value_str),
                    sizeof(struct ether_addr));
            return 0;
            /* fields of type struct in6_addr: */
        case RULE_FIELD_INET6_SOURCE:
        case RULE_FIELD_INET6_DESTINATION:
        case RULE_FIELD_ND_NS_TARGETADDRESS:
        case RULE_FIELD_ND_NA_TARGETADDRESS:
        case RULE_FIELD_ND_RD_TARGETADDRESS:
        case RULE_FIELD_ND_RD_DESTINATIONADDRESS:
        case RULE_FIELD_ND_OPT_PREFIXINFO_PREFIX:
            pos = strstr(value_str, "/");
            if (pos != NULL) {
                strlcpy(temp, value_str, pos - value_str);
                value_union->inet6.prefix = atoi(++pos);
            } else {
                strlcpy(temp, value_str, RULE_MATCH_VALUE_SIZE);
                value_union->inet6.prefix = 128;
            }
            inet_pton(AF_INET6, temp, &value_union->inet6.address);
            return 0;
    }
    return -1;
}

