#ifndef _SETTINGS_H_
#define _SETTINGS_H_


#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>

#include <libxml/tree.h>

#include "../membounds.h"
#include "ndpmon_defs.h"

#include "extinfo.h"



void settings_action_selector_print(struct action_selector* actions);

void settings_print();

int settings_parse(xmlNodePtr element);

int settings_store(xmlNodePtr settings_element);

struct extinfo_list** settings_extinfo_lock();

void settings_extinfo_unlock();

#endif
