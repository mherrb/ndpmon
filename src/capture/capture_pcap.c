
#include "capture_pcap.h"

#ifdef _CAPTURE_USE_PCAP_

void capture_up_all() {
    struct probe_list** locked_probes;
    struct probe_list* tmp_probes1;
    struct probe_list* tmp_probes2;

    /* critical section: */
    locked_probes = probe_list_lock();
    /* copy the probe list (don't bother if it changes later) */
    tmp_probes1 = *locked_probes;
    tmp_probes2 = *locked_probes;
    probe_list_unlock();
    /* end critical section. */

    /* create probe threads */
    while (tmp_probes1!=NULL) {
        if (tmp_probes1->entry.type==PROBE_TYPE_INTERFACE) {
            tmp_probes1->entry.capture_handle = capture_init(&tmp_probes1->entry);
            if (tmp_probes1->entry.capture_handle!=NULL) {
                pthread_create(&tmp_probes1->entry.capture_handle->capture_thread, NULL, capture_loop, tmp_probes1->entry.capture_handle);
            }
        }
        tmp_probes1 = tmp_probes1->next;
    }
    /* join all threads to keep main program running:  */
    while (tmp_probes2 != NULL) {
        if (tmp_probes2->entry.type == PROBE_TYPE_INTERFACE) {
            if (tmp_probes2->entry.capture_handle != NULL) {
                if (DEBUG) {
                    fprintf(stderr, "[capture_pcap] joining capturing thread..\n");
                }
                pthread_join(tmp_probes2->entry.capture_handle->capture_thread,
                        NULL);
            }
        }
        tmp_probes2 = tmp_probes2->next;
    }
}

void capture_down_all() {
    struct probe_list** locked_probes;
    struct probe_list* tmp_probes;

    /* critical section: */
    locked_probes = probe_list_lock();
    /* copy the probe list (don't bother if it changes later) */
    tmp_probes = *locked_probes;
    probe_list_unlock();
    /* end critical section. */

    while (tmp_probes!=NULL) {
        if (tmp_probes->entry.capture_handle != NULL) {
            if (DEBUG) {
                fprintf(stderr,
                        "[capture_pcap] Stop listening on interface %s...\n",
                        tmp_probes->entry.name);
            }
            pthread_cancel(tmp_probes->entry.capture_handle->capture_thread);
            pthread_join(tmp_probes->entry.capture_handle->capture_thread, NULL);
            capture_release(tmp_probes->entry.capture_handle);
            if (DEBUG) {
                fprintf(stderr, "    Stopped interface %s.\n",
                        tmp_probes->entry.name);
            }
        }
        tmp_probes = tmp_probes->next;
    }
}

capture_handle_t capture_init(struct probe* interface_probe) {
    char* filter = "icmp6"; /* filter to select the packets to grab */
    char* interface = interface_probe->name;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program* filter_program;/* string which contains the filter expression */
    pcap_t* descr = NULL;
    capture_handle_t new_handle;
    bpf_u_int32 maskp; /* mask  */
    bpf_u_int32 netp; /* ip */

    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    /* if the device isn't specified */
    if ( (interface == NULL) && ((interface = pcap_lookupdev(errbuf)) == NULL)) {
        fprintf(stderr,"%s\n",errbuf);
        return NULL; 
    }
    
    /* pcap get information on the interface */
    pcap_lookupnet(interface,&netp,&maskp,errbuf);
    if (capture_pcap_interface_spec(interface,netp,maskp)<0) {
        return NULL;
    }
    
    /* open device for reading */
    descr = pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
    if(descr == NULL) {
        fprintf(stderr,"pcap_open_live(): %s\n",errbuf);
        return NULL;
    }
    
    /* using the filter */
    if ((filter_program=malloc(sizeof(struct bpf_program)))==NULL) {
        perror("malloc");
        pcap_close(descr);
        return NULL;
    }
    if(pcap_compile(descr,filter_program,filter,0,netp) <0) { 
        fprintf(stderr,"Error calling pcap_compile %s.\n", pcap_geterr(descr));
        pcap_close(descr);
        return NULL; 
    }
    if (pcap_setfilter(descr,filter_program) == -1) {
        fprintf(stderr,"Error setting pcap filter.\n");
        pcap_close(descr);
        return NULL;
    }

    /* creating the capture handle containing all information */
    if ((new_handle=malloc(sizeof(struct capture_descriptor)))==NULL) {
        perror("malloc");
        return NULL;
    }
    new_handle->interface_probe = interface_probe;
    new_handle->descr = descr;
    new_handle->filter_program = filter_program;
    return new_handle;
}

void* capture_loop(void* args) {
    capture_handle_t capture_handle = (capture_handle_t) args;
    int nb_packet = 0;
    pcap_t* descr = NULL;

    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    if (capture_handle==NULL) {
        fprintf(stderr, "Error: capture_handle not initialized.\n");
        return NULL;
    }
    descr = capture_handle->descr;
    /* all packets are captured until kill */
    nb_packet=0;
    /* then we can capture the packets */
    probe_updown(PROBE_UPDOWN_STATE_UP, capture_handle->interface_probe);
    fprintf(stderr, "[capture_pcap] Listening on interface %s.\n", capture_handle->interface_probe->name);
    pcap_loop(descr,nb_packet,capture_pcap_callback,(u_char*)capture_handle->interface_probe);
    return NULL;
}

void capture_release(capture_handle_t capture_handle) {
    pcap_t* descr;
    struct bpf_program* fp;

    if (capture_handle==NULL) {
        return;
    }
    descr = capture_handle->descr;
    fp = capture_handle->filter_program;
    if (DEBUG) {
        fprintf(stderr, "    pcap cleanup.\n");
    }
    /* pcap cleanup */
    pcap_freecode(fp);
    pcap_close(descr);
    /* free handle */
    if (DEBUG) {
        fprintf(stderr, "    handle cleanup.\n");
    }
    free(capture_handle);
}

/*Function called each time that a packet pass the filter and is captured*/
void capture_pcap_callback(u_char *args,const struct pcap_pkthdr* hdr,const u_char* packet) {
    const time_t* time = (const time_t*) &(hdr->ts).tv_sec;
    struct probe* interface_probe = (struct probe*) args;

    if(DEBUG) {
        /* General info on the paquet */
        fprintf(stderr,"[capture_pcap] length of this packet: %d\n", hdr->len);
        fprintf(stderr,"[capture_pcap] recieved at: %s", (char*)ctime(time));
    }
    
    capture_process_packet(interface_probe, &hdr->ts, (uint8_t*)packet, hdr->len);
    pthread_testcancel();
    
}

/*To display properly the network address and device's mask */
int capture_pcap_interface_spec(char* interface, bpf_u_int32 netp, bpf_u_int32 maskp) {
    struct in_addr addr;
    char *net; /* network address */
    char *mask;/* network mask */
    
    if(DEBUG) {
        fprintf(stderr,"[capture-pcap] Initializing interface \"%s\" {\n", interface);
    }
    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL) {
        fprintf(stderr,"Problem with net address"); 
        return -1;
    }
    if (DEBUG) {
        fprintf(stderr,"    Net: %s\n",net);
    }
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (mask == NULL) {
        fprintf(stderr,"Problem with mask"); 
        return -1;
    }
    if (DEBUG) {
        fprintf(stderr,"    Mask: %s\n",mask);
        fprintf(stderr,"}\n");
    }
    return 0;
}

#else
#define _CAPTURE_PCAP_NOT_USED_
#endif
