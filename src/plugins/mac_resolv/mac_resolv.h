#ifndef _MAC_RESOLV_H_
#define _MAC_RESOLV_H_

#define BUFFER_SIZE 256

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h> 
#include <string.h>

#include "../../membounds.h"
#include "../../ndpmon_netheaders.h"

typedef struct manufacturer{
	char code[MANUFACTURER_CODE_SIZE];
	char name[MANUFACTURER_NAME_SIZE];
	struct manufacturer *next;
}manufacturer_t;

int read_manuf_file(char *filename, manufacturer_t **list);

int is_manufacturer(manufacturer_t *list, char *code, char *name);
int add_manufacturer(manufacturer_t **list, char *code, char *name);
char * get_manufacturer(manufacturer_t *list, const struct ether_addr* const eth);
int clean_manufacturer(manufacturer_t **list);
void print_manufacturer(manufacturer_t *list);

#endif

