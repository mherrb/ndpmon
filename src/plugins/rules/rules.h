#ifndef _RULES_H_
#define _RULES_H_

/** @file
 *  Interface of the rules plugin.
 */

#include <stdio.h>

#include <libxml/tree.h>

#include "../../ndpmon_netheaders.h"
#include "ndpmon_defs.h"

#include "rules_types.h"
#include "rules_matches.h"

/** Creates a textual representation of an internal field type like
 *  for instance "ethernet.source" for RULE_FIELD_ETHERNET_SOURCE.
 *  @param field The internal field type.
 *  @param res   A buffer to hold the string representation which is of
 *               size RULE_FIELD_SIZE and is already allocated.
 */
void rule_field_to_str(rule_field_t field, char* res);

/** Initializes the array that is used to translate internal field types to
 *  their human readable counterparts and vice versa.
 */
void rule_field_translations_init();

/** Adds a rule to the list of rules.
    @param description Text to be displayed in an alert if this rule matches.
    @param matches     Pointer to the list of matches that must match to trigger
                       an alert.
    @param export      Pointer to the list of exports (packet fields that are
                       included in an alert if this rule matches).
    @return            0 on success, -1 otherwise.
*/
int rule_list_add(struct rule_list** rules, char* description, struct rule_match_list* matches,
        struct rule_export_list* exports);

/** Frees a rule list.
 *  @param data The rule list to be freed.
*/
void rule_list_free(void** data);

/** Parses the rules from a XML element.
    @param element The XML element to load the configuration from.
    @param args    Additional parameters.
    @return        0 on success.
*/
int rule_list_load (xmlNodePtr element, void** data);

/** Prints the rule list.
 *  @param data The rule list to be printed.
*/
void rule_list_print(void* data);

int rule_list_save(xmlNodePtr rules_element, void* data);

/** Adds a match to a list of matches.
    @param matches The list of matches to which this match will be added.
    @param field   The field to be checked in this match.
    @param kind    Whether this field is a no match (1) or a standard match (0).
    @param value   The value against which the field is checked.
    @return        0 on success, -1 otherwise.
*/
int rule_match_list_add(struct rule_match_list** matches, rule_field_t field,
        uint8_t match_kind, union rule_match_value* match_value);

/** Frees a match list.
    @param matches The list of matches to be released.
*/
void rule_match_list_free(struct rule_match_list** matches);

/** Prints the list of matches of a rule.
 *  @param matches The first match.
 */
void rule_match_list_print(struct rule_match_list* matches);

/** Creates a textual representation of the internal value of a given field.
 *  @param value The (internal) numeric value.
 *  @param field The field that this value belongs to.
 *  @param res   A buffer for the resulting string that is of size
 *               RULE_MATCH_VALUE_SIZE and is already allocated.
 */
void rule_match_value_to_str(const union rule_match_value* const value,
        const rule_field_t field, char* res);

/** Translates the textual representation of a field to rule_field_t.
 *  @param field The string holding the field name representation.
 *  @param res   Pointer to the field type variable to hold the result.
 *  @return      0 on success, -1 if no such field is found.
 */
int rule_str_to_field(const char* const field, rule_field_t* res);

/** Translates the textual representation of a value (ethernet address, IPv6
 *  address, etc.) to an internal numeric value.
 *  @param value_str   The textual representation of the value.
 *  @param field       The field that this value belongs to (determines the
 *                     actual internal data type of the value).
 *  @param value_union Pointer to the variable which will hold the result.
 *  @return            0 on success, -1 if the given field was not found.
 */
int rule_str_to_value(const char* const value_str, const rule_field_t field,
        union rule_match_value* const value_union);

#endif
