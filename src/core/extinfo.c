#include "extinfo.h"

static struct extinfo_type_list* extinfo_types=NULL;

int extinfo_type_list_add(const char* const name, handler_free_t handler_free,
        handler_print_t handler_print,
        handler_xml_load_t handler_xml_load,
        handler_xml_save_t handler_xml_save) {
    struct extinfo_type_list* tmp_types=extinfo_types;
    struct extinfo_type_list* new;

    while (tmp_types!=NULL) {
        if (strncmp((tmp_types->entry.name), name, EXTINFO_NAME_SIZE)==0) {
            fprintf(stderr, "[extinfo] ERROR: extinfo type with given name already exists.");
            return -1;
        }
        tmp_types = tmp_types->next;
    }
    if ((new=malloc(sizeof(struct extinfo_type_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    /* set values: */
    new->entry.handler_free = handler_free;
    new->entry.handler_print = handler_print;
    new->entry.handler_xml_load = handler_xml_load;
    new->entry.handler_xml_save = handler_xml_save;
    strncpy(new->entry.name, name, EXTINFO_NAME_SIZE);
    new->next = NULL;
    if (extinfo_types==NULL) {
        /* if the list is empty the new entry is the list: */
        extinfo_types = new;
    } else {
        /* else walk to the end of the list to keep the FIFO ordering: */
        tmp_types = extinfo_types;
        while (tmp_types->next != NULL) {
            tmp_types = tmp_types->next;
        }
        tmp_types->next = new;
    }
    return 0;
}

void extinfo_type_list_free() {
    while (extinfo_types!=NULL) {
        struct extinfo_type_list* current = extinfo_types;
        extinfo_types = extinfo_types->next;
        free(current);
    }
}

const struct extinfo_type* extinfo_type_list_get(const char* const name) {
    struct extinfo_type_list* tmp_types=extinfo_types;

    while (tmp_types!=NULL) {
        if (strncmp(tmp_types->entry.name, name, EXTINFO_NAME_SIZE)==0) {
            return &tmp_types->entry;
        }
        tmp_types = tmp_types->next;
    }
    return NULL;
}

void extinfo_list_free(struct extinfo_list** list) {

    while ((*list)!=NULL) {
        struct extinfo_list* current = *list;
        *list = (*list)->next;
        (current->type->handler_free)(&current->data);
        free(current);
    }
}

void* extinfo_list_get_data(const struct extinfo_list* list, const char* const type_name) {

    while (list!=NULL) {
        if (strncmp(list->type->name, type_name, EXTINFO_NAME_SIZE)==0) {
            return list->data;
        }
        list = list->next;
    }
    return NULL;
}

int extinfo_list_load(xmlNodePtr element, struct extinfo_list** extinfo) {
    xmlNodePtr extinfo_element = element->children;

    while (extinfo_element!=NULL) {
        const struct extinfo_type* extinfo_type;
        void* extinfo_data;

        if (extinfo_element->type != XML_ELEMENT_NODE) {
            extinfo_element = extinfo_element->next;
            continue;
        }
        /* XML element node present, try to load extinfo: */
        extinfo_type = extinfo_type_list_get((char*)extinfo_element->name);
        if (extinfo_type!=NULL && extinfo_type->handler_xml_load!=NULL) {
            /* add extinfo information: */
            if ((extinfo_type->handler_xml_load)(extinfo_element, &extinfo_data)==-1) {
                fprintf(stderr, "[probes] ERROR: While loading extinfo tag %s\n", (char*) extinfo_element->name);
                return -1;
            }
            if (extinfo_list_set(extinfo, (char*) extinfo_element->name, extinfo_data)==-1) {
                fprintf(stderr, "[probes] ERROR: While set extinfo for tag %s\n", (char*) extinfo_element->name);
                return -1;
            }
        }
    extinfo_element = extinfo_element->next;
    }
    return 0;
}

void extinfo_list_print(const struct extinfo_list* list) {

    while (list!=NULL) {
        if (list->type->handler_print!=NULL) {
            (list->type->handler_print)(list->data);
        }
        list = list->next;
    }
}

int extinfo_list_set(struct extinfo_list** list,
        const char* const type_name, void* data) {
    struct extinfo_list* tmp_list = *list;
    struct extinfo_list* new;
    const struct extinfo_type* tmp_type;

    while (tmp_list!=NULL) {
        if (strncmp(tmp_list->type->name, type_name, EXTINFO_NAME_SIZE)==0) {
            tmp_list->data = data;
            return 0;
        }
        tmp_list = tmp_list->next;
    }
    /* entry must be created: */
    tmp_type = extinfo_type_list_get(type_name);
    if (tmp_type==NULL) {
        fprintf(stderr, "[extinfo] ERROR: Tried setting a not registered extinfo type.");
        return -1;
    }
    /* type exists: */
    if ((new=malloc(sizeof(struct extinfo_list)))==NULL) {
        perror("malloc");
        return -1;
    }
    new->data = data;
    new->type = tmp_type;
    new->next = NULL;
    if ((*list)==NULL) {
        /* empty list: entry is the new list: */
        *list = new;
    } else {
        /* else walk to the end of the list and append: */
        tmp_list = *list;
        while (tmp_list->next != NULL) {
            tmp_list = tmp_list->next;
        }
        tmp_list->next = new;
    }
    return 0;
}


int extinfo_list_save(xmlNodePtr element, const struct extinfo_list* extinfo) {

    while (extinfo!=NULL) {
        const struct extinfo_type* const extinfo_type = extinfo->type;
        xmlNodePtr extinfo_element = xmlNewChild(element, NULL, BAD_CAST extinfo_type->name, NULL);

        if (extinfo_type->handler_xml_save!=NULL && ((extinfo_type->handler_xml_save)(extinfo_element, extinfo->data)==-1)) {
            fprintf(stderr,
                    "[probes] ERROR: Could not save extinfo information %s.\n",
                    extinfo_type->name);
            return -1;
        }
        extinfo = extinfo->next;
    }
    return 0;
}
