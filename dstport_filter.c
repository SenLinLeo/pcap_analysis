#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dstport_filter.h"

static int dstport_filter_handler(pcap_packet_st *packet, filter_ctrl_st *expr, void *userdata)
{
    if (NULL == packet || NULL == expr) {
        return FILTER_FALSE;
    }

    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct iphdr *iph = pcap_get_packet_iphdr(packet);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)pcap_get_packet_l4hdr(packet);
        if (NULL == tcph) {
            printf("get tcp head fail, msg:[]\n");
            return FILTER_FALSE;
        }

    } else if (iph->protocol == IPPROTO_UDPLITE) {
        udph = (struct udphdr *)pcap_get_packet_l4hdr(packet);
        if (NULL == udph) {
            printf("get udp head fail, msg:[]\n");
            return FILTER_FALSE;
        }
    } else {
        // printf("Not support dstport!!!!!\n");
        return FILTER_FALSE;
    }
    return filter_check_uint(expr, tcph ? ntohs(tcph->dest) : ntohs(udph->dest));
}

int dstport_register_filter()
{
    if (filter_register_module(DSTPORT_MODULE_NAME, dstport_filter_handler, NULL) != 0) {
        return -1;
    }
    return 0;
}

void dstport_unregister_filter()
{
    filter_unregister_module(DSTPORT_MODULE_NAME);
}
