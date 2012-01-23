//
//  trustrouter.c
//  trustrouter
//
//  Created by Michael Goderbauer on 22.11.11.
//  Copyright (c) 2011 Michael Goderbauer. All rights reserved.
//

#include <mach/mach_types.h>

#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <sys/kern_control.h>
#include <sys/malloc.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#include <netinet/kpi_ipfilter.h>

#include "trustrouter.h"

#define BUNDLENAME "org.trustrouter.kext"

static ipfilter_t installed_filter;
static kern_ctl_ref ctlref;
static u_int32_t ctrl_unit = 0;

static lck_grp_t *lck_grp;
static lck_mtx_t *packet_queue_mtx;
static struct packet_queue packet_queue;

kern_return_t trustrouter_start(kmod_info_t * ki, void *d) {
    printf("[TrustRouter] Kext is loading...\n");
    
    struct ipf_filter filter;
    bzero(&filter, sizeof(filter));
    filter.cookie = (void*)0xdeadbeef;
    filter.name = "TrustRouter filter";
    filter.ipf_input = &input_fn;
    
    if (ipf_addv6(&filter, &installed_filter) != 0) {
        return KERN_FAILURE;
    }
    
    struct kern_ctl_reg userctl;
    bzero(&userctl, sizeof(userctl));
    strncpy(userctl.ctl_name, BUNDLENAME, sizeof(userctl.ctl_name));
    userctl.ctl_flags = CTL_FLAG_REG_SOCK_STREAM;
    userctl.ctl_send = &ctl_send_fn;
    userctl.ctl_connect = &ctl_connect_fn;
    userctl.ctl_disconnect = &ctl_disconnect_fn;
    
    if (ctl_register(&userctl, &ctlref) != 0) {
        //TODO: Clean-up? (e. g. unregister filter)
        return KERN_FAILURE;
    }
    
    TAILQ_INIT(&packet_queue);
    lck_grp = lck_grp_alloc_init(BUNDLENAME, LCK_GRP_ATTR_NULL);
    if (lck_grp == NULL) {
        //TODO: Clean-up?
        return KERN_FAILURE;
    }
    packet_queue_mtx = lck_mtx_alloc_init(lck_grp, LCK_ATTR_NULL);
    if (packet_queue_mtx == NULL) {
        //TODO: Clean-up?
        return KERN_FAILURE;
    }
    
    printf("[TrustRouter] Kext is active.\n");
    return KERN_SUCCESS;
}

kern_return_t trustrouter_stop(kmod_info_t *ki, void *d) {
    printf("[TrustRouter] Unloadeding kext...\n");
    
    //TODO: Check errorcode
    ipf_remove(installed_filter);
    
    //TODO: Check errorcode
    ctl_deregister(ctlref);
    
    struct pktQueueItem *item;
    struct pktQueueItem *temp_item;
    
    lck_mtx_lock(packet_queue_mtx);
    TAILQ_FOREACH_SAFE(item, &packet_queue, entries, temp_item) {
        TAILQ_REMOVE(&packet_queue, item, entries);
        mbuf_freem(*item->packet);
        _FREE(item, M_TEMP);
    }
    lck_mtx_unlock(packet_queue_mtx);
    
    lck_mtx_free(packet_queue_mtx, lck_grp);
    lck_grp_free(lck_grp);

    return KERN_SUCCESS;
}

static errno_t input_fn(void *cookie, mbuf_t *data, int offset, u_int8_t protocol) {
    if (protocol != IPPROTO_ICMPV6) {
        return ACCEPT;
    }
    
    u_int8_t icmp_type;
    if (mbuf_copydata(*data, offset, sizeof(icmp_type), &icmp_type) != 0) {
        return REJECT;
    }
    
    if (icmp_type != ND_ROUTER_ADVERT) {
        return ACCEPT;
    }
    
    printf("[TrustRouter] Router Advertisment! Yeah...\n");
    
    struct pktQueueItem *item = _MALLOC(sizeof(struct pktQueueItem), M_TEMP, M_WAITOK);
    item->packet = _MALLOC(sizeof(mbuf_t), M_TEMP, M_WAITOK);
    
    if (mbuf_dup(*data, MBUF_WAITOK, item->packet) != 0) {
        _FREE(item->packet, M_TEMP);
        _FREE(item, M_TEMP);
        return REJECT;
    }
    
    lck_mtx_lock(packet_queue_mtx);
    TAILQ_INSERT_TAIL(&packet_queue, item, entries);
    lck_mtx_unlock(packet_queue_mtx);
    
    void *packet_id = item->packet;
    mbuf_t usermode_mbuf;
    
    // Send packet id followed by packet
    if (mbuf_dup(*data, MBUF_WAITOK, &usermode_mbuf) != 0 ||
        ctl_enqueuedata(ctlref, ctrl_unit, &packet_id, sizeof(packet_id), 0) != 0 ||
        ctl_enqueuembuf(ctlref, ctrl_unit, usermode_mbuf, 0) != 0) {
        
        printf("[TrustRouter] Could not send to userspace\n");
        
        lck_mtx_lock(packet_queue_mtx);
        TAILQ_REMOVE(&packet_queue, item, entries);
        lck_mtx_unlock(packet_queue_mtx);
        
        mbuf_freem(*item->packet);
        _FREE(item, M_TEMP);
        
        return REJECT;
    }
    
    printf("[TrustRouter] Sent to userspace :-)\n");
    return REJECT;
}

static errno_t ctl_connect_fn(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo) {
    if (ctrl_unit == 0) {
        ctrl_unit = sac->sc_unit;
        printf("[TrustRouter] Connected\n");
        return 0;
    }
    return -1;
}

static errno_t ctl_disconnect_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo) {
    if (unit == ctrl_unit) {
        ctrl_unit = 0;
        printf("[TrustRouter] Disconnected\n");
        return 0;
    }
    return -1;
}


static errno_t ctl_send_fn(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags) {
    struct result result;
    if (mbuf_copydata(m, 0, sizeof(result), &result)  != 0) {
        return -1;
    }
    
    struct pktQueueItem *item;
    
    lck_mtx_lock(packet_queue_mtx);
    TAILQ_FOREACH(item, &packet_queue, entries) {
        if (item->packet == result.packet_id) {
            TAILQ_REMOVE(&packet_queue, item, entries);    
            break;
        }
    }
    lck_mtx_unlock(packet_queue_mtx);
    
    if (item == NULL) {
        printf("[TrustRouter] Unkown packet id.\n");
        return -1;
    }
    
    if (result.action == ACCEPT) {
        printf("[TrustRouter] Accepted.\n");
        if (ipf_inject_input(*(item->packet), installed_filter) != 0) {
            mbuf_freem(*item->packet);
            printf("[TrustRouter] Cannot re-inject packet.\n");
        } else {
            printf("[TrustRouter] Injected.\n");
        }
    } else {
        printf("[TrustRouter] Rejected.\n");
    }
    
    _FREE(item, M_TEMP);
    return 0;
}


