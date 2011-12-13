//
//  trustrouter.h
//  trustrouter
//
//  Created by Michael Goderbauer on 02.12.11.
//  Copyright (c) 2011 Michael Goderbauer. All rights reserved.
//

#ifndef trustrouter_trustrouter_h
#define trustrouter_trustrouter_h

kern_return_t trustrouter_start(kmod_info_t *ki, void *d);
kern_return_t trustrouter_stop(kmod_info_t *ki, void *d);

errno_t input_fn(void *cookie, mbuf_t *data, int offset, u_int8_t protocol);

errno_t ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
errno_t ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);

typedef enum action {
    ACCEPT = 0,
    REJECT = -1
} action;

struct pktQueueItem {
	TAILQ_ENTRY(pktQueueItem) entries;
	mbuf_t *packet;
};
TAILQ_HEAD(packet_queue, pktQueueItem);

struct result {
    void *packet_id;
    action action;
};

#endif
