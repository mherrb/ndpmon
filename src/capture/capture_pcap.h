#ifndef _CAPTURE_PCAP_H_
#define _CAPTURE_PCAP_H_

#include "../core/capture.h"

#ifdef _CAPTURE_USE_PCAP_

#include <pthread.h>
#include <pcap.h>              /*lib pcap*/

#ifdef _COUNTERMEASURES_
#include "../plugins/countermeasures/countermeasures.h"
#endif
#ifdef _WEBINTERFACE_
#include "../plugins/webinterface/webinterface.h"
#endif

struct capture_descriptor {
    struct probe* interface_probe;
    pthread_t capture_thread;
    pcap_t* descr;
    struct bpf_program* filter_program;
};


capture_handle_t capture_init(struct probe* interface_probe);

void capture_release(capture_handle_t capture_handle);

void* capture_loop(void* args);

void capture_down_all();

void capture_up_all();

void capture_pcap_callback(u_char *args,const struct pcap_pkthdr* hdr,const u_char* packet);

int capture_pcap_interface_spec(char* interface, bpf_u_int32 netp, bpf_u_int32 maskp);

#else
#define _CAPTURE_PCAP_NOT_USED
#endif

#endif
