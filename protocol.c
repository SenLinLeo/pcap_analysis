#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "protocol.h"


static int protocal_filter_handler(pcap_packet_st *packet, filter_ctrl_st *expr, void *userdata)
{
    if (NULL == packet || NULL == expr)
        return FILTER_FALSE;
    struct iphdr *iph = NULL;
    iph = pcap_get_packet_iphdr(packet);
    if (NULL == iph)
        return FILTER_FALSE;
    if (iph->protocol == IPPROTO_TCP) {
        return filter_check_string(expr, TCP_PRO);
    }
    else if (iph->protocol == IPPROTO_UDPLITE) {
        return filter_check_string(expr, UDP_PRO);
    }
    else {
        fprintf(stderr,"unsupport type protocal [%d].\n", iph->protocol);
        return FILTER_FALSE;
    }

}

int protocal_register_filter()
{
    if (filter_register_module(PRO_MODULE_NAME, protocal_filter_handler, NULL) != 0) {
        return -1;
    }
    return 0;
}

void protocal_unregister_filter()
{
    filter_unregister_module(PRO_MODULE_NAME);
}
