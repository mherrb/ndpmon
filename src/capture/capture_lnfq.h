#ifndef _CAPTURE_LNFQ_H_
#define _CAPTURE_LNFQ_H_

#include "../core/capture.h"
#include "../core/probes.h"

#ifdef _CAPTURE_USE_LNFQ_

#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h> /* libnetfilter_queue*/
#include <sys/time.h> /* gettimeofday - timestamp substitute */
#include <pthread.h>

/** Which queue is to be used (option --queue-num in ip6tables). */
#define CAPTURE_LNFQ_QUEUE_NUM 1

struct capture_descriptor {
    struct probe* interface_probe;
    struct nfq_handle *library_handle;
    struct nfq_q_handle *queue_handle;
    struct nlif_handle *interface_resolving_handle;
    int file_descriptor;
    pthread_t capture_thread;
};

void capture_up_all();

void* capture_loop(void* unused);

void capture_down_all();

int capture_lnfq_callback(struct nfq_q_handle *queue_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

#else
#define _CAPTURE_LNFQ_NOT_USED_
#endif

#endif
