#ifndef _EXTINFO_H_
#define _EXTINFO_H_

/** @file
 *  Interface for extension information (extinfo) types and values.
 *  Extension information is used by plugins to store values in the
 *  core data structures (for instance the neighbor list).
 *
 *  Extinfo types are only identified by a string which must match the name
 *  of XML elements in the configuration (or in the neighbor cache) that carry
 *  such information.
 *
 *  Plugins using extinfo values must take care to cast the void* <B>data</B>
 *  pointer value according to the type they deal with.
 */

#include <string.h>
#include <libxml/tree.h>

/** Maximum size for an extension information (extinfo) type name.
 */
#define EXTINFO_NAME_SIZE 100

/** Type for a handler that frees the data of an extinfo value.
 *  <B>data</B> points to the data of the extension
 *  information value and should be set to NULL if the data was freed.
 */
typedef void (*handler_free_t) (void** data);

/** Type for a handler that prints this extinfo information in a
 *  human readable format.
 */
typedef void (*handler_print_t) (void* data);

/** Type for a handler that loads an extension information from a XML element.
 *  The handler must set the pointer <B>data</B> to an allocated buffer that
 *  contains the data read. The handler must return <B>0</B> on success and
 *  <B>-1</B> if an error occurs.
 */
typedef int (*handler_xml_load_t) (xmlNodePtr element, void** data);

/** Type for a handler that saves an extension information from the internal
 *  value to a XML element. <B>data</B> points to the data of the extension
 *  information value. The handler must save the value to the XML element
 *  <B>element</B> and return 0 on success and -1 otherwise.
 */
typedef int (*handler_xml_save_t) (xmlNodePtr element, void* data);

/** Structure to hold a extension information (extinfo) type.
 */
struct extinfo_type {
    /** Name of this extinfo type.*/
    char name[EXTINFO_NAME_SIZE];
    /** See @ref handler_free_t.*/
    handler_free_t handler_free;
    /** See @ref handler_print_t.*/
    handler_print_t handler_print;
    /** See @ref handler_xml_load_t.*/
    handler_xml_load_t handler_xml_load;
    /** See @ref handler_xml_save_t.*/
    handler_xml_save_t handler_xml_save;

};

/** A list holding possible extinfo types.
 *  This list type has a nested entry field only to prevent publishing
 *  the <B>next</B> field to plugins dealing with their extinfo types.
 */
struct extinfo_type_list {
    /** This list entry. */
    struct extinfo_type entry;
    /** Pointer to the next list entry.*/
    struct extinfo_type_list* next;
};

/** A list holding extinfo values.*/
struct extinfo_list {
    /** The type of this extinfo value. */
    const struct extinfo_type* type;
    /** (Pointer to) the data of this extinfo value. */
    void* data;
    /** The next list entry.*/
    struct extinfo_list* next;
};

/** Adds an extinfo type to the list of possible types.
 *  The name must not already exist in the list, else adding the type fails.
 *  @param type The type.
 *  @return     0 on success, -1 otherwise.
 */
int extinfo_type_list_add(const char* const name, handler_free_t handler_free,
        handler_print_t handler_print,
        handler_xml_load_t handler_xml_load,
        handler_xml_save_t handler_xml_save);

/** Frees an extinfo type list, does not free the list entries.*/
void extinfo_type_list_free();

/** Retrieves a extinfo type structure for a given name. Is internally needed
 *  during the XML parsing process and to retrieve extinfo values.
 *  @param name The name of the list entry.
 *  @return     The extinfo_type structure or NULL if not found.
 */
const struct extinfo_type* extinfo_type_list_get(const char* const name);

/** Frees all entries of a given extinfo value list using the free handler
 *  of the entry's extinfo type.
 *  @param list Pointer to the list to be freed (call by reference).
 */
void extinfo_list_free(struct extinfo_list** list);

/** Gets the entry in the given list that is of the specified type.
 *  @param list      The list to be used.
 *  @param type_name The type to be searched.
 *  @return Pointer to the data or NULL if not found.
 */
void* extinfo_list_get_data(const struct extinfo_list* list,
        const char* const type_name);

/** Loads an extinfo value list from a XML element. Ignores children
 *  of <I>element</I> that do not match an extinfo type.
 *  @param element The element containing the extinfo values as children.
 *  @param extinfo The list to be filled.
 *  @return        0 on success, -1 otherwise.
 */
int extinfo_list_load(xmlNodePtr element, struct extinfo_list** extinfo);

/** Prints an extinfo list.
 * @param list The list to be used.
 */
void extinfo_list_print(const struct extinfo_list* list);

/** Sets an entry in an extinfo value list. If an entry of the given type does
 *  not exist it will be created.
 *  @param list Pointer to the list holding this extinfo (call by reference).
 *  @param type The extinfo type, that must already be registered using
 *              extinfo_type_list_add().
 *  @param data The data to be added.
 *  @return     0 on success, -1 otherwise.
 */
int extinfo_list_set(struct extinfo_list** list,
        const char* const type_name, void* data);

/** Saves all entries of the given extinfo value list as children of a XML
 *  element.
 *  @param element The XML element to add the information to.
 *  @param extinfo The list to be saved.
 *  @return        0 on success, -1 otherwise.
 */
int extinfo_list_save(xmlNodePtr element, const struct extinfo_list* extinfo);

#endif
