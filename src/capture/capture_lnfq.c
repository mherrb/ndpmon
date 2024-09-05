#include "capture_lnfq.h"

#ifdef _CAPTURE_USE_LNFQ_

static capture_handle_t capture_handle;

/** Initializes packet capturing.
    Opens a netfilter library handle and a queue handle for queue-num CAPTURE_LNFQ_QUEUE_NUM.
*/
void capture_up_all() {
    capture_handle_t new_handle;
    struct nfq_handle *library_handle;
    struct nfq_q_handle *queue_handle;
    struct nlif_handle *interface_resolving_handle;

    capture_handle = NULL;
    library_handle = nfq_open();
    if (!library_handle) {
        fprintf(stderr, "[capture_lnfq] Error during nfq_open()\n");
        exit(1);
    }
    if (nfq_unbind_pf(library_handle, PF_INET6) < 0) {
        fprintf(stderr, "[capture_lnfq] WARNING: could not nfq_unbind_pf()\n");
    }
    if (nfq_bind_pf(library_handle, PF_INET6) < 0) {
        fprintf(stderr, "[capture_lnfq] ERROR: during nfq_bind_pf()\n");
        exit(1);
    }
    queue_handle = nfq_create_queue(library_handle,  CAPTURE_LNFQ_QUEUE_NUM, &capture_lnfq_callback, NULL);
    if (!queue_handle) {
        fprintf(stderr, "[capture_lnfq] ERROR: during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_queue_maxlen(queue_handle, 4096) < 0) {
        fprintf(stderr, "[capture_lnfq] ERROR: can't set maxlength\n");
        exit(1);
    }
    if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[capture_lnfq] ERROR: can't set packet_copy mode\n");
        exit(1);
    }
    /* prepare the resolving of interface IDs to names: */
    interface_resolving_handle = nlif_open();
    if (interface_resolving_handle == NULL) {
        fprintf(stderr, "[capture_lnfq] ERROR: can't init interface name resolving (nlif).\n");
        exit(1);
    }
    nlif_query(interface_resolving_handle);

    /* creating the capture handle containing all information */
    if ((new_handle=malloc(sizeof(struct capture_descriptor)))==NULL) {
        perror("[capture_lnfq] malloc failed.");
        exit(1);
    }
    new_handle->library_handle = library_handle;
    new_handle->queue_handle = queue_handle;
    new_handle->interface_resolving_handle = interface_resolving_handle;
    new_handle->file_descriptor = 0;
    capture_handle = new_handle;
    pthread_create(&new_handle->capture_thread, NULL, capture_loop, NULL);
    /* join the capturing thread to prevent the main program from exiting. */
    pthread_join(new_handle->capture_thread, NULL);

}

/** Starts the packet capturing loop.
    @param unused This thread does not recieve any params.
*/
void* capture_loop(void* unused) {
    int file_descriptor;
    int recieved;
    char buffer[4096] __attribute__ ((aligned));
    struct probe_list** locked_probes;
    struct probe_list*  tmp_probes;

    pthread_setcanceltype(capture_handle->capture_thread, PTHREAD_CANCEL_DEFERRED);
    if (capture_handle==NULL) {
        fprintf(stderr, "[capture_lnfq] Error: capture_handle not initialized.\n");
        return NULL;
    }
    /* critical section: */
    locked_probes = probe_list_lock();
    tmp_probes = *locked_probes;
    while (tmp_probes!=NULL) {
        probe_updown(PROBE_UPDOWN_STATE_UP, &tmp_probes->entry);
        tmp_probes = tmp_probes->next;
    }
    locked_probes = NULL;
    tmp_probes = NULL;
    probe_list_unlock();
    /* end critical section: */
    file_descriptor = nfq_fd(capture_handle->library_handle);
    fprintf(stderr, "[capture_lnfq] netfilter_queue up and listening on queue %u...\n", CAPTURE_LNFQ_QUEUE_NUM);
    if (DEBUG) {
        fprintf(stderr, "    file descriptor is %i.\n", file_descriptor);
    }
    fprintf(stderr, "    if nothing is captured, use ip6tables to configure NFQUEUE 0.\n");
    while ((recieved = recv(file_descriptor, buffer, sizeof(buffer), 0)) && recieved >= 0) {
        nfq_handle_packet(capture_handle->library_handle, buffer, recieved);
        pthread_testcancel();
    }
    return NULL;
}

void capture_down_all(void) {

    if (capture_handle==NULL) {
        return;
    }
    if (DEBUG) {
        fprintf(stderr, "[capture_lnfq] Stop listening on netfilter_queue... \n");
    }
    pthread_cancel(capture_handle->capture_thread);
    pthread_join(capture_handle->capture_thread, NULL);
    /* lnfq cleanup: */
    if (DEBUG) {
        fprintf(stderr, "    unbinding from queue %u\n", CAPTURE_LNFQ_QUEUE_NUM);
    }
    nfq_destroy_queue(capture_handle->queue_handle);
    /* closing interface resolving library (nlif):
     * (must be released AFTER destroying the queue!)
     * */
    if (DEBUG) {
        fprintf(stderr, "    closing interface resolving handle\n");
    }
    nlif_close(capture_handle->interface_resolving_handle);
    if (DEBUG) {
        fprintf(stderr, "    closing library handle\n");
    }
    nfq_close(capture_handle->library_handle);
    /* free handle: */
    if (DEBUG) {
        fprintf(stderr, "    handle cleanup.\n");
    }
    free(capture_handle);
    if (DEBUG) {
        fprintf(stderr, "    Stopped netfilter_queue.\n");
    }
}

#if 0
/** Prints packet information for debug mode.
*/
static u_int32_t print_pkt (struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    u_int32_t mark,ifi; 
    int ret;
    char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph){
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }
    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);
    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);
    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);
    return id;
}
#endif

/** Function called each time that a packet pass the filter and is captured.
*/
int capture_lnfq_callback(struct nfq_q_handle *queue_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    const time_t* time;

    /* packet information: */
    struct nfqnl_msg_packet_hdr* packet_header; /* lnfq */
    uint32_t                     packet_id;
    int                          packet_length;
    unsigned char*               packet_data;
    char                         packet_interface[PROBE_NAME_SIZE];
    uint8_t*                     packet_with_pseudo;
    struct timeval               timestamp;
    struct ether_header*         pseudo_ether_header;
    struct nfqnl_msg_packet_hw*  packet_hw;
    struct probe_list**          locked_probes;
    struct probe_list*           tmp_probes;
    /* result of the packet processing: */
    int packet_result;

    memset(&packet_interface, 0, PROBE_NAME_SIZE);

    /* get the netfilter id of the packet, to raise verdicts after processing: */
    packet_header = nfq_get_msg_packet_hdr(nfa);
    if (packet_header) {
        packet_id = ntohl(packet_header->packet_id);
    } else {
        return 0;
    }
    
    /* get the packet's data and length: */
    packet_length = nfq_get_payload(nfa, &packet_data);

    /* get the packet's source hardware address */
    packet_hw = nfq_get_packet_hw(nfa);
    if (packet_hw==NULL) {
        fprintf(stderr, "[capture_lnfq] error retrieving packet source hardware address.");
        return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
    }
    
    /* build a pseudo ethernet header: */
    if ((packet_with_pseudo=malloc(sizeof(struct ether_header)+packet_length))==NULL) {
        perror("malloc");
        exit(1);
    }
    pseudo_ether_header = (struct ether_header*) packet_with_pseudo;
    /* initialise pseudo ethernet header: */
    memset(pseudo_ether_header, 0, sizeof(struct ether_header));
    pseudo_ether_header->ether_type = packet_header->hw_protocol;
    memcpy(&pseudo_ether_header->ether_shost, &packet_hw->hw_addr, sizeof(struct ether_addr));
    /* append the captured packet: */
    memcpy((uint8_t*)packet_with_pseudo+sizeof(struct ether_header), packet_data, packet_length);
    /* now adjust packet_length: */
    packet_length = packet_length + sizeof(struct ether_header);

    /* get the packet's indev name: */
    if (nfq_get_indev_name(capture_handle->interface_resolving_handle, nfa, packet_interface)<0) {
        fprintf(stderr, "[capture_lnfq] error resolving interface name, packet ignored");
        return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
    }
    /* get the packet's timestamp: */
    /* cannot use nfq_get_timestamp(nfa, &timestamp), keeps on failing. seems to be an lnfq issue according to internet research.
       http://lists.netfilter.org/pipermail/netfilter-devel/2006-February/023490.html
       REM
          fprintf(stderr, "[capture_lnfq] error getting timestamp, packet ignored");
          return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
       END REM
    */
    gettimeofday(&timestamp, NULL);
    time =  (const time_t*) &timestamp.tv_sec;

    if(DEBUG) {
        printf("[capture_lnfq] length of this packet: %d\n", packet_length);
        printf("[capture_lnfq] recieved at: %s\n",  (char*)ctime(time) );
        printf("[capture_lnfq] captured on interface: %s\n", packet_interface);
    }

    /* check whether the packet comes from an interface that is being listened: */
    /* begin critical section: */
    locked_probes = probe_list_lock();
    tmp_probes = *locked_probes;
    probe_list_unlock();
    /* end critical section. */
    while (tmp_probes!=NULL) {
        if (tmp_probes->entry.type==PROBE_TYPE_INTERFACE) {
            if (strncmp(tmp_probes->entry.name, packet_interface, PROBE_NAME_SIZE)==0) {
                /* call the packet processing: */
                packet_result = capture_process_packet(&tmp_probes->entry,
                        &timestamp, packet_with_pseudo,
                        packet_length);
                free(packet_with_pseudo);
                if (packet_result==0) {
                    if (DEBUG) {
                        fprintf(stderr, "[capture_lnfq] result==0 => NF_ACCEPT\n\n");
                    }
                    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
                } else {
                    if (DEBUG) {
                        fprintf(stderr, "[capture_lnfq] result!=0 => NF_DROP\n\n");
                    }
                    return nfq_set_verdict(queue_handle, packet_id, NF_DROP, 0, NULL);
                }
            }
        }
        tmp_probes = tmp_probes->next;
    }
    /* no configured interface found with the name of the packet's indev: */
    if (DEBUG) {
        fprintf(stderr,
                "[capture_lnfq] interface is not configured, ignoring packet.\n");
    }
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
}

#else
#define _CAPTURE_LNFQ_NOT_USED
#endif
