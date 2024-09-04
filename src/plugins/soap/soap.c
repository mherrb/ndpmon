#include "soap.h"

static pthread_t soap_listen_thread;
static pthread_mutex_t soap_settings_lock = PTHREAD_MUTEX_INITIALIZER;
static struct soap_settings* soap_settings = NULL;

void soap_settings_free(void** data) {
    /* no referenced structures, just free it */
    free(*data);
    *data = NULL;
}

int soap_settings_load(xmlNodePtr element, void** data) {
    xmlChar* soap_report_url;
    xmlChar* soap_report_src;
    xmlChar* soap_listen_path;
    xmlChar* soap_listen_port;
    xmlChar* ssl_enabled;
    struct soap_settings* settings;

    if ((settings=malloc(sizeof(struct soap_settings)))==NULL) {
        perror("[soap] malloc failed.\n");
        exit(1);
    }
    memset(settings, 0, sizeof(struct soap_settings));
    soap_report_url = xmlGetProp(element, BAD_CAST "report_url");
    soap_report_src = xmlGetProp(element, BAD_CAST "report_src");
    soap_listen_path = xmlGetProp(element, BAD_CAST "listen_path");
    soap_listen_port = xmlGetProp(element, BAD_CAST "listen_port");
    ssl_enabled      = xmlGetProp(element, BAD_CAST "ssl_enabled");
    if (soap_report_url==NULL) {
        settings->soap_report_enabled = 0;
    } else {
        settings->soap_report_enabled = 1;
        strncpy(settings->soap_report_url, (char*) soap_report_url,SOAP_STR_SIZE);
        if (soap_report_src==NULL) {
            fprintf(stderr, "[soap] ERROR: settings: report source required.\n");
            xmlFree(soap_report_url);
            xmlFree(soap_report_src);
            xmlFree(soap_listen_path);
            xmlFree(soap_listen_port);
            return -1;
        }
        strncpy(settings->soap_report_src, (char*) soap_report_src, SOAP_STR_SIZE);
    }
    if (soap_listen_path==NULL) {
        settings->soap_listen_enabled = 0;
    } else {
        settings->soap_listen_enabled = 1;
        strncpy(settings->soap_listen_path, (char*) soap_listen_path, SOAP_STR_SIZE);
        if (soap_listen_port==NULL) {
            fprintf(stderr, "[soap] ERROR: settings: listen port required.\n");
            xmlFree(soap_report_url);
            xmlFree(soap_report_src);
            xmlFree(soap_listen_path);
            xmlFree(soap_listen_port);
            return -1;
        }
        settings->soap_listen_port = atoi( (char*) soap_listen_port);
    }
    if (ssl_enabled!=NULL) {
        settings->ssl_enabled = atoi((char*)ssl_enabled);
    } else {
        settings->ssl_enabled = 0;

    }
    if (settings->soap_report_enabled==1 || settings->soap_listen_enabled==1) {
        xmlChar* ssl_certfile = xmlGetProp(element, BAD_CAST "ssl_certfile");
        xmlChar* ssl_certpass = xmlGetProp(element, BAD_CAST "ssl_certpass");
        xmlChar* ssl_cafile = xmlGetProp(element, BAD_CAST "ssl_cafile");
        xmlChar* ssl_commonname = xmlGetProp(element, BAD_CAST "ssl_commonname");
        strncpy(settings->ssl_certfile, (char*) ssl_certfile, SOAP_STR_SIZE);
        strncpy(settings->ssl_certpass, (char*) ssl_certpass, SOAP_STR_SIZE);
        strncpy(settings->ssl_cafile, (char*) ssl_cafile, SOAP_STR_SIZE);
        strncpy(settings->ssl_commonname, (char*) ssl_commonname, SOAP_STR_SIZE);
    }
    xmlFree(soap_report_url);
    xmlFree(soap_report_src);
    xmlFree(soap_listen_path);
    xmlFree(soap_listen_port);
    *data = settings;
    pthread_mutex_lock(&soap_settings_lock);
    soap_settings = settings;
    pthread_mutex_unlock(&soap_settings_lock);
    return 0;
}

void soap_settings_print(void* data) {
    struct soap_settings* settings = (struct soap_settings*) data;
    fprintf(stderr, "[soap] plugin configuration {\n");
    if (settings->soap_report_enabled) {
        fprintf(stderr, "    soap report url %s\n", settings->soap_report_url);
        fprintf(stderr, "    soap report source %s\n", settings->soap_report_src);
    } else {
        fprintf(stderr, "no soap report\n");
    }
    if (settings->soap_listen_enabled) {
        char listen_port_str[SOAP_STR_SIZE];

        fprintf(stderr, "    soap listen path %s\n", settings->soap_listen_path);
        snprintf(listen_port_str, SOAP_STR_SIZE, "%u", settings->soap_listen_port);
        fprintf(stderr, "    soap listen port %u\n", settings->soap_listen_port);
    } else {
        fprintf(stderr, "    no soap listen\n");
    }
    if ((settings->soap_report_enabled==1 || settings->soap_listen_enabled==1)) {
        if (settings->ssl_enabled == 1) {
            fprintf(stderr, "    ssl certfile %s\n", settings->ssl_certfile);
            fprintf(stderr, "    ssl certpass %s\n", settings->ssl_certpass);
            fprintf(stderr, "    ssl cafile %s\n", settings->ssl_cafile);
            fprintf(stderr, "    ssl commonname %s\n", settings->ssl_commonname);
        } else {
            fprintf(stderr, "    no ssl\n");
        }
    }
    fprintf(stderr, "}\n");
}

int soap_settings_save(xmlNodePtr element, void* data) {
    struct soap_settings* settings = (struct soap_settings*) data;
    if (settings->soap_report_enabled) {
        xmlNewProp(element, BAD_CAST"report_url", BAD_CAST settings->soap_report_url);
        xmlNewProp(element, BAD_CAST "report_src", BAD_CAST settings->soap_report_src);
    }
    if (settings->soap_listen_enabled) {
        char listen_port_str[SOAP_STR_SIZE];
        xmlNewProp(element, BAD_CAST "listen_path", BAD_CAST settings->soap_listen_path);
        snprintf(listen_port_str, SOAP_STR_SIZE, "%u", settings->soap_listen_port);
        xmlNewProp(element, BAD_CAST "listen_port", BAD_CAST listen_port_str);
    }
    if (settings->soap_report_enabled || settings->soap_listen_enabled) {
        xmlNewProp(element, BAD_CAST "ssl_enabled", (settings->ssl_enabled==1? BAD_CAST "1": BAD_CAST "0"));
        xmlNewProp(element, BAD_CAST "ssl_certfile", BAD_CAST settings->ssl_certfile);
        xmlNewProp(element, BAD_CAST "ssl_certpass", BAD_CAST settings->ssl_certpass);
        xmlNewProp(element, BAD_CAST "ssl_cafile", BAD_CAST settings->ssl_cafile);
        xmlNewProp(element, BAD_CAST "ssl_commonname", BAD_CAST settings->ssl_commonname);
    }
    return 0;
}

void soap_up() {
    int pthread_res;
    herror_t err;

    /* critical section (shared ressource): */
    pthread_mutex_lock(&soap_settings_lock);
    if (soap_settings == NULL ) {
        pthread_mutex_unlock(&soap_settings_lock);
        return;
    }
    if (soap_settings->soap_listen_enabled == 1
            || soap_settings->soap_report_enabled == 1) {
        if (soap_settings->ssl_enabled == 1) {
            if (DEBUG) {
                fprintf(stderr, "[soap] Enabling SSL.\n");
            }
            hssl_enable();
            hssl_set_certificate(soap_settings->ssl_certfile);
            hssl_set_certpass(soap_settings->ssl_certpass);
            hssl_set_ca(soap_settings->ssl_cafile);
            /*   hssl_set_user_verify(soap_ssl_verify);
             *  (currently not working with library)
             */
        } else {
            fprintf(stderr,
                    "[soap] WARNING: SSL disabled. Using unsecured transport.\n");
        }
    }
    if (soap_settings->soap_report_enabled==1) {
        if ((err = soap_client_init_args(0, NULL)) != H_OK) {
            fprintf(stderr, "    %s():%s [%d]\n", herror_func(err), herror_message(
                    err), herror_code(err));
            herror_release(err);
            pthread_mutex_unlock(&soap_settings_lock);
            return;
        }
    }
    if (soap_settings->soap_listen_enabled!=1) {
        if (DEBUG) {
            fprintf(stderr, "[soap] Server not activated.\n");
        }
        pthread_mutex_unlock(&soap_settings_lock);
        return;
    }
    pthread_mutex_unlock(&soap_settings_lock);
    /* end critical section. */

    pthread_res = pthread_create(&soap_listen_thread, NULL, soap_listen, NULL);
    if (DEBUG) {
        if (pthread_res==0)
            fprintf(stderr, "[soap] SOAP listening server started.\n");
        else
            fprintf(stderr, "[soap] SOAP listening server thread create failed.\n");
    }
}

void soap_down() {
    pthread_mutex_lock(&soap_settings_lock);
        if (soap_settings->soap_report_enabled==1) {
            soap_client_destroy();
        }
    pthread_mutex_unlock(&soap_settings_lock);
    raise(SIGUSR1);
    pthread_cancel(soap_listen_thread);
    if (DEBUG) {
        fprintf(stderr, "[soap] Waiting for SOAP server to stop...\n");
    }
    pthread_join(soap_listen_thread, NULL);
}

void* soap_listen(void* args) {
    herror_t err;
    SoapRouter *router;
    char* server_args[6];
    char  server_port[SOAP_STR_SIZE];
    char  server_signal[SOAP_STR_SIZE];

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    pthread_mutex_lock(&soap_settings_lock);
    snprintf(server_port, SOAP_STR_SIZE, "%u", soap_settings->soap_listen_port);
    snprintf(server_signal, SOAP_STR_SIZE, " %i", SIGUSR1);
    server_args[0] = "ndpmon";
    server_args[1] = NHTTPD_ARG_PORT;
    server_args[2] = server_port;
    server_args[3] = NHTTPD_ARG_TERMSIG;
    server_args[4] = server_signal;
    server_args[5] = NULL;
    pthread_mutex_unlock(&soap_settings_lock);
    httpd_set_timeout(2);

     if ((err = soap_server_init_args(5, (char**) &server_args)) != H_OK)
     {
       fprintf(stderr, "    %s(): %s [%d]\n", herror_func(err), herror_message(err), herror_code(err));
       herror_release(err);
       exit(1);
     }

     if (!(router = soap_router_new()))
     {
       fprintf(stderr, "    soap_router_new failed (router == %p)\n", (void*)router);
       herror_release(err);
       exit(1);
     }

     soap_router_register_service(router, soap_listen_alert, "alert", SOAP_URN_STR);
     soap_router_register_service(router, soap_listen_neighbor_update, "neighbor_update", SOAP_URN_STR);
     soap_router_register_service(router, soap_listen_probe_updown, "probe_updown", SOAP_URN_STR);


     pthread_mutex_lock(&soap_settings_lock);
     if (soap_server_register_router(router, soap_settings->soap_listen_path)==0)
     {
       fprintf(stderr, "    error during register router\n");
       herror_release(err);
       exit(1);
     }
     if (DEBUG) {
         fprintf(stderr, "[soap] router (%p) registered for \"%s\"\n", (void*)router, soap_settings->soap_listen_path);
     }
     pthread_mutex_unlock(&soap_settings_lock);

     if ((err = soap_server_run()) != H_OK)
     {
       printf("%s(): %s [%d]\n", herror_func(err), herror_message(err), herror_code(err));
       herror_release(err);
       exit(1);
     }

     soap_server_destroy();

    return NULL;
}

herror_t soap_listen_alert(SoapCtx *request, SoapCtx *result) {
    herror_t err;
    xmlNodePtr method;
    xmlNodePtr children;
    xmlChar* method_src;
    struct ether_addr request_ethernet_address1;
    struct ether_addr request_ethernet_address2;
    struct in6_addr request_ipv6_address;
    char request_reason[ALERT_REASON_SIZE];
    char request_message[ALERT_MESSAGE_SIZE];
    char request_probe_name[PROBE_NAME_SIZE];
    char search_probe_name[PROBE_NAME_SIZE];
    int request_priority=0;
    struct probe* locked_probe;

    /* initialize values: */
    memset(&request_ethernet_address1, 0, sizeof(struct ether_addr));
    memset(&request_ethernet_address2, 0, sizeof(struct ether_addr));
    memset(&request_ipv6_address, 0, sizeof(struct in6_addr));
    memset(request_reason, 0, ALERT_REASON_SIZE);
    memset(request_message, 0, ALERT_MESSAGE_SIZE);
    memset(request_probe_name, 0, PROBE_NAME_SIZE);
    memset(search_probe_name, 0, PROBE_NAME_SIZE);

    /* extract method from SOAP envelope: */
    fprintf(stderr, "[soap] alert recieved.\n");
    if (DEBUG) {
        xmlDocFormatDump(stdout, request->env->root->doc, 1);
    }
    if ((err = soap_env_new_with_response(request->env, &result->env)) != H_OK) {
        fprintf(stderr, "soap_env_new_with_response failed (%s)\n",
                herror_message(err));
        return err;
    }
    if (!(method = soap_env_get_method(request->env))) {
        printf("soap_env_get_method failed\n");
        return herror_new("alert", 0, "Method not found.");
    }
    method_src = xmlGetProp(method, BAD_CAST"source");
    if (method_src==NULL) {
        return herror_new("alert", 1, "missing method source");
    }
    /* parse event information: */
    children = method->children;
    while (children!=NULL) {
        if (children->type!=XML_ELEMENT_NODE) {
            children = children->next;
            continue;
        }
        if (strncmp((char*)children->name, "ethernet_address1", SOAP_STR_SIZE)==0) {
            ether_aton_r((char*)children->children->content, &request_ethernet_address1);
        } else if (strncmp((char*)children->name, "ethernet_address2", SOAP_STR_SIZE)==0) {
            ether_aton_r((char*)children->children->content, &request_ethernet_address2);
        } else if (strncmp((char*)children->name, "ipv6_address", SOAP_STR_SIZE)==0) {
            inet_pton(AF_INET6, (char*) children->children->content, &request_ipv6_address);
        } else if (strncmp((char*)children->name, "reason", SOAP_STR_SIZE)==0) {
            strncpy(request_reason, (char*)children->children->content, ALERT_REASON_SIZE-1);
        } else if (strncmp((char*)children->name, "message", SOAP_STR_SIZE)==0) {
            strncpy(request_message, (char*)children->children->content, ALERT_MESSAGE_SIZE-1);
        } else if (strncmp((char*)children->name, "priority", SOAP_STR_SIZE)==0) {
            request_priority = atoi((char*)children->children->content);
        } else if (strncmp((char*)children->name, "probe", SOAP_STR_SIZE)==0) {
            strncpy(request_probe_name, (char*)children->children->content, PROBE_NAME_SIZE-1);
        }
        children = children->next;
    }
    snprintf(search_probe_name, PROBE_NAME_SIZE-1, "%s/%s", (char*)method_src, request_probe_name);
    xmlFree(method_src);
    /* critical section: */
    locked_probe = probe_lock(search_probe_name);
    if (locked_probe==NULL) {
        /* nothing locked. */
        fprintf(stderr, "[soap] WARNING: recieved alert: Referenced probe \"%s\" not found.\n", search_probe_name);
        return herror_new("alert", 1, "Referenced probe not found.");
    }
    alert_raise(request_priority, locked_probe, request_reason, request_message, &request_ethernet_address1, &request_ethernet_address2, &request_ipv6_address, NULL);
    probe_unlock(search_probe_name);
    /* end critical section. */
    return H_OK;

}

herror_t soap_listen_neighbor_update(SoapCtx *request, SoapCtx *result) {
    herror_t err;
    xmlNodePtr method, children;
    xmlChar* method_src;
    char request_probe_name[PROBE_NAME_SIZE];
    char search_probe_name[PROBE_NAME_SIZE];
    enum neighbor_update_key_type request_key_type = NEIGHBOR_UPDATE_KEY_TYPE_NONE;
    int request_found_key = 0;
    neighbor_list_t request_neighbor;
    neighbor_list_t* neighbor_to_update;
    struct probe* locked_probe;

    /* initialize values: */
    memset(request_probe_name, 0, PROBE_NAME_SIZE);
    memset(search_probe_name, 0, PROBE_NAME_SIZE);
    memset(&request_neighbor, 0, sizeof(neighbor_list_t));

    /* extract method from SOAP envelope: */
    fprintf(stderr, "[soap] neighbor update recieved.\n");
     if (DEBUG) {
         xmlDocFormatDump(stdout, request->env->root->doc, 1);
     }
     if ((err = soap_env_new_with_response(request->env, &result->env)) != H_OK) {
         fprintf(stderr, "soap_env_new_with_response failed (%s)\n",
                 herror_message(err));
         return err;
     }
     if (!(method = soap_env_get_method(request->env))) {
         printf("soap_env_get_method failed\n");
         return herror_new("neighbor_update", 0, "Method not found.");
     }
     method_src = xmlGetProp(method, BAD_CAST"source");
     if (method_src==NULL) {
         return herror_new("neighbor_update", 1, "missing method source");
     }
     children = method->children;
     while (children!=NULL) {
         if (children->type != XML_ELEMENT_NODE) {
             children = children->next;
             continue;
         }
         if (strncmp((char*)children->name, "key", SOAP_STR_SIZE)==0) {
             xmlChar* key_type = xmlGetProp(children, BAD_CAST "type");

             if (strncmp((char*)key_type, "ethernet", SOAP_STR_SIZE)==0) {
                 request_key_type = NEIGHBOR_UPDATE_KEY_TYPE_ETHERNET;
             } else if (strncmp((char*)key_type, "lla", SOAP_STR_SIZE)==0) {
                 request_key_type = NEIGHBOR_UPDATE_KEY_TYPE_LLA;
             } else {
                 request_key_type = NEIGHBOR_UPDATE_KEY_TYPE_NONE;
             }
             request_found_key = 1;
         } else if (strncmp((char*)children->name, "probe", SOAP_STR_SIZE)==0) {
             strncpy(request_probe_name, (char*)children->children->content, PROBE_NAME_SIZE-1);
         } else if (strncmp((char*)children->name, "neighbor", SOAP_STR_SIZE)==0) {
             neighbor_load(children, &request_neighbor);
         }
         children = children->next;
     }
     if (request_found_key!=1) {
         fprintf(stderr, "[soap] WARNING: recieved neighbor_update: No key type given.");
         return herror_new("neighbor_update", 1, "No key given.");
     }
     snprintf(search_probe_name, PROBE_NAME_SIZE-1, "%s/%s", (char*)method_src, request_probe_name);
     xmlFree(method_src);
     if (DEBUG) {
         fprintf(stderr, "[soap] Searching probe \"%s\"...\n", search_probe_name);
     }
     /* critical section: */
     locked_probe = probe_lock(search_probe_name);
     if (locked_probe==NULL) {
         fprintf(stderr, "[soap] WARNING: recieved neighbor_update: Referenced probe \"%s\" not found.\n", search_probe_name);
         return herror_new("neighbor_update", 1, "Referenced probe not found.");
     }
     if (locked_probe->type!=PROBE_TYPE_REMOTE) {
         probe_unlock(search_probe_name);
         fprintf(stderr, "[soap] WARNING: recieved neighbor_update: Referenced probe \"%s\" is not a remote probe.\n", search_probe_name);
         return herror_new("neighbor_update", 1, "Referenced probe is not a remote probe.");
     }
     switch (request_key_type) {
         case NEIGHBOR_UPDATE_KEY_TYPE_ETHERNET:
             /* mac has not changed: */
             neighbor_to_update = (neighbor_list_t*) get_neighbor_by_mac(locked_probe->neighbors, &request_neighbor.mac);
             if (neighbor_to_update==NULL) {
                 probe_unlock(search_probe_name);
                 fprintf(stderr, "[soap] WARNING: recieved neighbor_update: Referenced neighbor not found.\n");
                 return herror_new("neighbor_update", 1, "Referenced neighbor not found.");
             }
             addresses_free(&neighbor_to_update->addresses);
             neighbor_to_update->addresses = request_neighbor.addresses;
             extinfo_list_free(&neighbor_to_update->extinfo);
             neighbor_to_update->extinfo   = request_neighbor.extinfo;
             ethernets_free(&neighbor_to_update->old_mac);
             neighbor_to_update->old_mac   = request_neighbor.old_mac;
             memcpy(&neighbor_to_update->first_mac_seen, &request_neighbor.first_mac_seen, sizeof(struct ether_addr));
             set_neighbor_lla(locked_probe->neighbors, &request_neighbor.mac, &request_neighbor.lla);
             neighbor_set_last_mac(locked_probe->neighbors, &request_neighbor.lla, &request_neighbor.previous_mac);
             set_neighbor_timer(locked_probe->neighbors, &request_neighbor.mac, request_neighbor.timer);
             neighbor_update(search_probe_name, &request_neighbor.mac, NULL, &request_neighbor);
             break;
         case NEIGHBOR_UPDATE_KEY_TYPE_LLA:
             /* lla has not changed: */
             neighbor_to_update = (neighbor_list_t*) get_neighbor_by_mac(locked_probe->neighbors, &request_neighbor.mac);
             if (neighbor_to_update==NULL) {
                 probe_unlock(search_probe_name);
                 fprintf(stderr, "[soap] WARNING: recieved neighbor_update: Referenced neighbor not found.\n");
                 return herror_new("neighbor_update", 1, "Referenced neighbor not found.");
             }
             neighbor_update_mac(locked_probe->neighbors, &request_neighbor.lla, &request_neighbor.mac);
             addresses_free(&neighbor_to_update->addresses);
             neighbor_to_update->addresses = request_neighbor.addresses;
             extinfo_list_free(&neighbor_to_update->extinfo);
             neighbor_to_update->extinfo   = request_neighbor.extinfo;
             ethernets_free(&neighbor_to_update->old_mac);
             neighbor_to_update->old_mac   = request_neighbor.old_mac;
             neighbor_set_last_mac(locked_probe->neighbors, &request_neighbor.lla, &request_neighbor.previous_mac);
             set_neighbor_timer(locked_probe->neighbors, &request_neighbor.mac, request_neighbor.timer);
             memcpy(&neighbor_to_update->first_mac_seen, &request_neighbor.first_mac_seen, sizeof(struct ether_addr));
             neighbor_update(search_probe_name, NULL, &request_neighbor.lla, &request_neighbor);
             break;
         default:
             /* new station: */
             add_neighbor(&locked_probe->neighbors, &request_neighbor.mac);
             set_neighbor_lla(locked_probe->neighbors, &request_neighbor.mac, &request_neighbor.lla);
             set_neighbor_timer(locked_probe->neighbors, &request_neighbor.mac, request_neighbor.timer);
             neighbor_set_last_mac(locked_probe->neighbors, &request_neighbor.lla, &request_neighbor.previous_mac);
             neighbor_to_update = (neighbor_list_t*) get_neighbor_by_mac(locked_probe->neighbors, &request_neighbor.mac);
             if (neighbor_to_update==NULL) {
                 /* something went terribly wrong here: */
                 probe_unlock(search_probe_name);
                 fprintf(stderr, "[soap] ERROR: recieved neighbor_update: Error adding new neighbor.\n");
                 return herror_new("neighbor_update", 1, "Error adding new neighbor.");
             }
             neighbor_to_update->addresses = request_neighbor.addresses;
             neighbor_to_update->extinfo   = request_neighbor.extinfo;
             neighbor_to_update->old_mac   = request_neighbor.old_mac;
             neighbor_update(search_probe_name, NULL, NULL, &request_neighbor);
             break;
     }
     probe_unlock(search_probe_name);
     /* end critical section. */
     return H_OK;

}

herror_t soap_listen_probe_updown(SoapCtx *request, SoapCtx *result) {
    herror_t err;
    xmlNodePtr method;
    xmlNodePtr children;
    xmlNodePtr request_probe_element = NULL;
    xmlChar* method_src;
    enum probe_updown_state state = PROBE_UPDOWN_STATE_DOWN;
    char request_probe_name[PROBE_NAME_SIZE];
    char search_probe_name[PROBE_NAME_SIZE];
    enum probe_type request_probe_type;
    struct extinfo_list* request_probe_extinfo = NULL;
    router_list_t* request_probe_routers = NULL;
    struct probe* locked_probe;

    /* initializes values: */
    memset(request_probe_name, 0, PROBE_NAME_SIZE);
    memset(search_probe_name, 0, PROBE_NAME_SIZE);

    fprintf(stderr, "[soap] probe_updown recieved (HSSL=%i).\n", hssl_enabled());
    if (DEBUG) {
        xmlDocFormatDump(stdout, request->env->root->doc, 1);
    }
    if ((err = soap_env_new_with_response(request->env, &result->env)) != H_OK) {
        fprintf(stderr, "soap_env_new_with_response failed (%s)\n",
                herror_message(err));
        return err;
    }
    if (!(method = soap_env_get_method(request->env))) {
        printf("soap_env_get_method failed\n");
        return herror_new("probe_updown", 0, "Method not found.");
    }
    method_src = xmlGetProp(method, BAD_CAST"source");
    if (method_src==NULL) {
        return herror_new("probe_updown", 1, "missing method source");
    }
    children = method->children;

    while (children!=NULL) {
        if (children->type != XML_ELEMENT_NODE) {
            children = children->next;
            continue;
        }
        if (strncmp((char*) children->name, "state", SOAP_STR_SIZE)==0) {
            if (strncmp((char*) children->children->content, "up", SOAP_STR_SIZE)==0) {
                state = PROBE_UPDOWN_STATE_UP;
            } else {
                state = PROBE_UPDOWN_STATE_DOWN;
            }
        } else if (strncmp((char*) children->name, "probe", SOAP_STR_SIZE)==0) {
            request_probe_element = children;
        }
        children = children->next;
    }
    if (state==PROBE_UPDOWN_STATE_UP) { /* probe up event: */
        if (request_probe_element==NULL) {
            return herror_new("probe_updown", 1, "Missing probe data.");
        }
        if (DEBUG) {
            fprintf(stderr, "[soap] Loading request probe %s information...\n", (char*) request_probe_element->name);
        }
        probe_load_config(request_probe_element, request_probe_name, &request_probe_type, &request_probe_extinfo, &request_probe_routers, 1);
        snprintf(search_probe_name, PROBE_NAME_SIZE-1, "%s/%s", (char*)method_src, request_probe_name);
        if (DEBUG) {
            fprintf(stderr, "[soap] Searching probe \"%s\"...\n", search_probe_name);
        }
        xmlFree(method_src);
        /* critical section: */
        locked_probe = probe_lock(search_probe_name);
        if (locked_probe==NULL) {
            fprintf(stderr, "[soap] WARNING: recieved probe_updown: Referenced probe \"%s\" not found.\n", search_probe_name);
            return herror_new("probe_updown", 1, "Referenced probe not found.");
        }
        if (locked_probe->type!=PROBE_TYPE_REMOTE) {
            probe_unlock(search_probe_name);
            fprintf(stderr, "[soap] WARNING: recieved probe_updown: Referenced probe \"%s\" is not a remote probe.\n", search_probe_name);
            return herror_new("probe_updown", 1, "Referenced probe is not a remote probe.");
        }
        locked_probe->routers = request_probe_routers;
        locked_probe->extinfo = request_probe_extinfo;
        probe_load_neighbors(request_probe_element, locked_probe, 1);
        if (DEBUG) {
                fprintf(stderr, "[soap] Loading request probe information done.\n");
        }
        probe_updown(PROBE_UPDOWN_STATE_UP, locked_probe);
        probe_unlock(search_probe_name);
        parser_config_store();
        /* end critical section */
    } else { /* probe down event: */
        xmlChar* tmp = xmlGetProp(request_probe_element, BAD_CAST "name");
        if (tmp==NULL) {
            return herror_new("probe_updown", 1, "No probe referenced.");
        }
        snprintf(search_probe_name, PROBE_NAME_SIZE-1, "%s/%s", (char*)method_src, (char*)tmp);
        if (DEBUG) {
            fprintf(stderr, "[soap] Searching probe \"%s\"...\n", search_probe_name);
        }
        /* critical section: */
        locked_probe = probe_lock(search_probe_name);
        if (locked_probe==NULL) {
            fprintf(stderr, "[soap] WARNING: recieved probe_updown: Referenced probe \"%s\" not found.\n", search_probe_name);
            return herror_new("probe_updown", 1, "Referenced probe not found.");
        }
        if (locked_probe->type!=PROBE_TYPE_REMOTE) {
            probe_unlock(search_probe_name);
            fprintf(stderr, "[soap] WARNING: recieved probe_updown: Referenced probe \"%s\" is not a remote probe.\n", search_probe_name);
            return herror_new("probe_updown", 1, "Referenced probe is not a remote probe.");
        }
        probe_updown(PROBE_UPDOWN_STATE_DOWN, locked_probe);
        probe_unlock(search_probe_name);
    }

    if (DEBUG) {
        fprintf(stderr, "[soap] probe_updown processed.\n");
    }
    return H_OK;
}

void soap_event_handler(const struct event_info* event) {
    xmlNodePtr soap_body;
    SoapCtx* soap_context;
    struct extinfo_list** locked_extinfo;
    struct soap_settings* settings;
    char url[SOAP_STR_SIZE];
    char src[SOAP_STR_SIZE];

    /* critical section (shared ressource): */
    locked_extinfo = settings_extinfo_lock();
    settings = extinfo_list_get_data(*locked_extinfo, "soap");
    if (settings==NULL || settings->soap_report_enabled!=1) {
        settings_extinfo_unlock();
        return;
    }
    strncpy(url, settings->soap_report_url, SOAP_STR_SIZE);
    strncpy(src, settings->soap_report_src, SOAP_STR_SIZE);
    settings_extinfo_unlock();
    /* end critical section. */

    switch (event->type) {
        case EVENT_TYPE_ALERT:
            if ((soap_body = soap_method_create(&soap_context, "alert", src))
                    == NULL) {
                fprintf(stderr, "[soap] Could not report alert.\n");
            }
            alert_save(soap_body, &event->data->alert);
            break;
        case EVENT_TYPE_NEIGHBOR_UPDATE:
            if ((soap_body = soap_method_create(&soap_context,
                    "neighbor_update", src)) == NULL) {
                fprintf(stderr, "[soap] Could not report neighbor update.\n");
            }
            neighbor_update_save(soap_body, &event->data->neighbor_update);
            break;
        case EVENT_TYPE_PROBE_UPDOWN:
            if ((soap_body = soap_method_create(&soap_context,
                    "probe_updown", src)) == NULL) {
                fprintf(stderr, "[soap] Could not report probe updown.\n");
            }
            fprintf(stderr, "updown sent...\n");
            probe_updown_save(soap_body, &event->data->probe_updown);
            break;
        default:
            fprintf(stderr,
                    "[soap] Could not report event. Unknown event type %i.",
                    event->type);
            soap_ctx_free(soap_context);
            return;
    }
    if (soap_method_send(soap_context, url)==-1) {
        fprintf(stderr, "[soap] ERROR: while sending event to server.\n");
    }
}

xmlNodePtr soap_method_create(SoapCtx** request, const char* method, const char* source) {
    xmlNodePtr soap_body;
    xmlAttrPtr soap_encoding;
    herror_t err;

    if ((err = soap_ctx_new_with_method(SOAP_URN_STR, method, request)) != H_OK) {
        fprintf(stderr, "    %s():%s [%d]\n", herror_func(err), herror_message(
                err), herror_code(err));
        herror_release(err);
        return NULL;
    }
    soap_encoding = xmlHasProp((*request)->env->root, BAD_CAST "encodingStyle");
    xmlRemoveProp(soap_encoding);
    soap_body = soap_env_get_method((*request)->env);
    xmlNewProp(soap_body, BAD_CAST "source", BAD_CAST source);
    xmlNewProp(soap_body, BAD_CAST"schemaLocation", NULL);

    return soap_body;
}

int soap_method_send(SoapCtx* request, const char* url) {
    herror_t err;
    SoapCtx* response;

    /*xmlDocFormatDump(stdout, request->env->root->doc, 1);*/
    if ((err = soap_client_invoke(request, &response, url, "")) != H_OK) {
        printf("[%d] %s(): %s\n", herror_code(err), herror_func(err),
                herror_message(err));
        herror_release(err);
        soap_ctx_free(request);
        return -1;
    }

    xmlDocFormatDump(stdout, response->env->root->doc, 1);
    soap_ctx_free(request);
    soap_ctx_free(response);
    return 0;
}

#if 0
int soap_ssl_verify(X509* cert) {
    ASN1_TIME *notAfter = X509_get_notAfter(cert);

    if (X509_cmp_current_time(notAfter) <= 0) {
        fprintf(stderr, "[soap] WARNING: SSL: Certificate has expired");
        return 0;
    }

    pthread_mutex_lock(&soap_settings_lock);
    if (!verify_sn(cert, CERT_SUBJECT, NID_commonName, soap_settings->ssl_commonname)) {
        fprintf(stderr, "[soap] WARNING: SSL: issuer commonName does not match");
        pthread_mutex_unlock(&soap_settings_lock);
        return 0;
    }
    pthread_mutex_unlock(&soap_settings_lock);

    fprintf(stderr, "Certificate checks out");
    return 1;
}
#endif
