#include "settings.h"

static struct extinfo_list* settings_extinfo;
pthread_mutex_t settings_extinfo_mutex=PTHREAD_MUTEX_INITIALIZER;

/* Write value to proc entry
 * Return: 0 is ok
 */
static int write_proc(const char *file, const char *value)
{
	int fd;
	ssize_t ret;

	if (file == NULL || value == NULL) return -1;

	fd = open(file,O_WRONLY);
	if (fd < 0) return -1;

	ret = write(fd,value,strlen(value)); 
	if (ret < 0) {
		char error[100];
		snprintf(error, sizeof(error), "Error while trying to set proc entry %s to %s", file, value);
		perror(error);
		close(fd);
		exit(1);
	}

	close(fd);

	return 0;
}

void str_to_facility(char* value, int* facility) {
    *facility = -1;
    if( !STRCMP(value,"LOG_LOCAL0") )
	{
		*facility = LOG_LOCAL0;
	}
	else if( !STRCMP(value,"LOG_LOCAL0") )
	{
		*facility = LOG_LOCAL0;
	}
	else if( !STRCMP(value,"LOG_LOCAL1") )
	{
		*facility = LOG_LOCAL1;
	}
	else if( !STRCMP(value,"LOG_LOCAL2") )
	{
		*facility = LOG_LOCAL2;
	}
	else if( !STRCMP(value,"LOG_LOCAL3") )
	{
		*facility = LOG_LOCAL3;
	}
	else if( !STRCMP(value,"LOG_LOCAL4") )
	{
		*facility = LOG_LOCAL4;
	}
	else if( !STRCMP(value,"LOG_LOCAL5") )
	{
		*facility = LOG_LOCAL5;
	}
	else if( !STRCMP(value,"LOG_LOCAL6") )
	{
		*facility = LOG_LOCAL6;
	}
	else if( !STRCMP(value,"LOG_LOCAL7") )
	{
		*facility = LOG_LOCAL7;
	}
	else if( !STRCMP(value,"LOG_USER") )
	{
		*facility = LOG_USER;
	}
	else if( !STRCMP(value,"LOG_MAIL") )
	{
		*facility = LOG_MAIL;
	}
	else if( !STRCMP(value,"LOG_DAEMON") )
	{
		*facility = LOG_DAEMON;
	}
	else if( !STRCMP(value,"LOG_AUTH") )
	{
		*facility = LOG_AUTH;
	}
	else if( !STRCMP(value,"LOG_SYSLOG") )
	{
		*facility = LOG_SYSLOG;
	}
	else if( !STRCMP(value,"LOG_LPR") )
	{
		*facility = LOG_LPR;
	}
	else if( !STRCMP(value,"LOG_NEWS") )
	{
		*facility = LOG_NEWS;
	}
	else if( !STRCMP(value,"LOG_UUCP") )
	{
		*facility = LOG_UUCP;
	}
	else if( !STRCMP(value,"LOG_CRON") )
	{
		*facility = LOG_CRON;
	}
	else if( !STRCMP(value,"LOG_AUTHPRIV") )
	{
		*facility = LOG_AUTHPRIV;
	}
	else if( !STRCMP(value,"LOG_FTP") )
	{
		*facility = LOG_FTP;
	}

}

int settings_parse(xmlNodePtr element) {
    xmlNodePtr setting = element->children;
    struct extinfo_list** extinfo;
    
    while (setting!=NULL) {
        if (setting->type!=XML_ELEMENT_NODE) { /*skip everything except xml elements */
            setting = setting->next;
            continue;
        }
        if (STRCMP(setting->name, "actions_high_priority")==0) {
            xmlAttrPtr action = setting->properties;
            
            while (action!=NULL) {
                if (action->type!=XML_ATTRIBUTE_NODE) {
                    action = action->next;
                    continue;
                }
                if (STRCMP(action->name, "sendmail")==0) {
                    if (strcmp("1", (char*)action->children->content)!=0)
                        action_high_pri.sendmail=0;
                    else
                        action_high_pri.sendmail=1; 
                } else if (STRCMP(action->name, "syslog")==0) {
                    if (strcmp("1", (char*)action->children->content)!=0)
                        action_high_pri.syslog=0;
                    else
                        action_high_pri.syslog=1; 
                } else if (STRCMP(action->name, "exec_pipe_program")==0) {
                    action_high_pri.exec_pipe_program = strdup((char*)action->children->content);
                    if (strcmp(action_high_pri.exec_pipe_program, "")==0) {
                        free(action_high_pri.exec_pipe_program);
                        action_high_pri.exec_pipe_program = NULL;
                    }
                }
            action = action->next;
            }

        } else if (STRCMP(setting->name, "actions_low_priority")==0) {
            xmlAttrPtr action = setting->properties;
            
            while (action!=NULL) {
                if (action->type!=XML_ATTRIBUTE_NODE) {
                    action = action->next;
                    continue;
                }
                if (STRCMP(action->name, "sendmail")==0) {
                    if (strcmp("1", (char*)action->children->content)!=0)
                        action_low_pri.sendmail=0;
                    else
                        action_low_pri.sendmail=1; 
                } else if (STRCMP(action->name, "syslog")==0) {
                    if (strcmp("1", (char*)action->children->content)!=0)
                        action_low_pri.syslog=0;
                    else
                        action_low_pri.syslog=1; 
                } else if (STRCMP(action->name, "exec_pipe_program")==0) {
                    action_low_pri.exec_pipe_program = strdup((char*)action->children->content);
                    if (strcmp(action_low_pri.exec_pipe_program, "") == 0) {
                        free(action_low_pri.exec_pipe_program);
                        action_low_pri.exec_pipe_program = NULL;
                    }
                }
            action = action->next;
            }
        } else if (STRCMP(setting->name, "admin_mail")==0) {
            char* value = (char*)XML_GET_CONTENT(setting->children);
            if (value!=NULL) {
                strlcpy(admin_mail,value, ADMIN_MAIL_SIZE);
            }
        } else if (STRCMP(setting->name, "ignor_autoconf")==0) {
	    char* flag = (char *)XML_GET_CONTENT(setting->children);
	    ignor_autoconf = atoi(flag);
            /* Not working for BSD */
/* If the tag ignor_autoconf is set, disables this feature by
 * setting the variables 
 * /proc/sys/net/ipv6/conf/all/autoconf
 * /proc/sys/net/ipv6/conf/all/accept_ra
 * /proc/sys/net/ipv6/conf/all/accept_ra_defrtr
 * /proc/sys/net/ipv6/conf/all/accept_ra_pinfo
 * /proc/sys/net/ipv6/conf/all/accept_redirects
 * to 0 to avoid the monitoring host to be attacked
 */
#ifdef _LINUX_
                /* note: it may be a good option to save values, and restore
                   them when exiting
                */
                write_proc("/proc/sys/net/ipv6/conf/all/autoconf",flag);
                write_proc("/proc/sys/net/ipv6/conf/all/accept_ra",flag);
                write_proc("/proc/sys/net/ipv6/conf/all/accept_ra_defrtr",flag);
                write_proc("/proc/sys/net/ipv6/conf/all/accept_ra_pinfo",flag);
                write_proc("/proc/sys/net/ipv6/conf/all/accept_redirects",flag);
#endif
        } else if (STRCMP(setting->name, "syslog_facility")==0) {
            char* value = (char*)XML_GET_CONTENT(setting->children);
            int facility;
            strlcpy(syslog_facility,value, SYSLOG_FACILITY_SIZE);
            str_to_facility(value, &facility);
            if (facility == -1) {
                fprintf(stderr, "ERROR: unknown syslog facility.");
                return -1;
            }
            openlog ("NDPMon", LOG_NDELAY|LOG_CONS|LOG_PID, facility);
            syslog (LOG_NOTICE, "NDPMon started by user %d", getuid ());
        } else if (STRCMP(setting->name, "use_reverse_hostlookups")==0) {
            char* value = (char*)XML_GET_CONTENT(setting->children);
            if (value==NULL || strcmp("1", value)!=0)
                use_reverse_hostlookups=0;
            else
                use_reverse_hostlookups=1;
        }
        setting = setting->next;
    }

    /* load plugin global configuration: */
    extinfo = settings_extinfo_lock();
    extinfo_list_load(element, extinfo);
    settings_extinfo_unlock();

    settings_print();

    return 0;
}

void settings_action_selector_print(struct action_selector* actions) {
    if (actions->syslog==1)
        fprintf(stderr, "        syslog\n");
    else
        fprintf(stderr, "        no syslog\n");
    if (actions->sendmail==1)
        fprintf(stderr, "        sendmail\n");
    else
        fprintf(stderr, "        no sendmail\n");
    if (actions->exec_pipe_program!=NULL)
        fprintf(stderr, "        pipe program %s\n", actions->exec_pipe_program);
    else
        fprintf(stderr, "        no pipe program\n");
}

void settings_print() {
    fprintf(stderr, "[settings] NDPMon general settings: {\n");
    fprintf(stderr, "    actions high priority {\n");
    settings_action_selector_print(&action_high_pri);
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    actions low priority {\n");
    settings_action_selector_print(&action_low_pri);
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    admin mail %s\n", admin_mail);
    if (ignor_autoconf==1)
        fprintf(stderr, "    ignor autoconf\n");
    else
        fprintf(stderr, "    no ignor autoconf\n");
    fprintf(stderr, "    syslog facility %s\n", syslog_facility);
    if (use_reverse_hostlookups==1)
        fprintf(stderr, "    use reverse hostlookups\n");
    else
        fprintf(stderr, "    no use reverse hostlookups\n");
    fprintf(stderr, "}\n");
    pthread_mutex_lock(&settings_extinfo_mutex);
    extinfo_list_print(settings_extinfo);
    pthread_mutex_unlock(&settings_extinfo_mutex);
}

int settings_store(xmlNodePtr settings_element) {
    xmlNodePtr actions_high_element=NULL;
    xmlNodePtr actions_low_element=NULL;
    struct extinfo_list** extinfo;
    
    /* store actions high priority: */
    actions_high_element = xmlNewChild(settings_element, NULL, BAD_CAST "actions_high_priority",   NULL);
    xmlNewProp(actions_high_element, BAD_CAST "sendmail", (action_high_pri.sendmail==1) ? BAD_CAST "1" : BAD_CAST "0");
    xmlNewProp(actions_high_element, BAD_CAST "syslog", (action_high_pri.syslog==1) ? BAD_CAST "1" : BAD_CAST "0");
    xmlNewProp(actions_high_element, BAD_CAST "exec_pipe_program", BAD_CAST action_high_pri.exec_pipe_program);
    /* store actions low priority: */
    actions_low_element = xmlNewChild(settings_element, NULL, BAD_CAST "actions_low_priority",   NULL);
    xmlNewProp(actions_low_element, BAD_CAST "sendmail", (action_high_pri.sendmail==1) ? BAD_CAST "1" : BAD_CAST "0");
    xmlNewProp(actions_low_element, BAD_CAST "syslog", (action_high_pri.syslog==1) ? BAD_CAST "1" : BAD_CAST "0");
    xmlNewProp(actions_low_element, BAD_CAST "exec_pipe_program", BAD_CAST action_high_pri.exec_pipe_program);
    /* store other settings: */
    xmlNewChild(settings_element, NULL, BAD_CAST "admin_mail",   BAD_CAST admin_mail);
    xmlNewChild(settings_element, NULL, BAD_CAST "ignor_autoconf",  (ignor_autoconf==1) ? BAD_CAST "1" : BAD_CAST "0" );
    xmlNewChild(settings_element, NULL, BAD_CAST "syslog_facility", BAD_CAST syslog_facility);
    xmlNewChild(settings_element, NULL, BAD_CAST "use_reverse_hostlookups", (use_reverse_hostlookups==1) ? BAD_CAST "1" : BAD_CAST "0" );
    /* store plugin global settings: */
    extinfo = settings_extinfo_lock();
    extinfo_list_save(settings_element, *extinfo);
    settings_extinfo_unlock();
    return 0;
}

struct extinfo_list** settings_extinfo_lock() {
    pthread_mutex_lock(&settings_extinfo_mutex);
    return &settings_extinfo;
}

void settings_extinfo_unlock() {
    pthread_mutex_unlock(&settings_extinfo_mutex);
}
