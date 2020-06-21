#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dstip_filter.h"


static int dstip_filter_handler(pcap_packet_st *packet, filter_ctrl_st *expr, void *userdata)
{
    if (NULL == packet || NULL == expr)
        return FILTER_FALSE;
    struct iphdr *iph = NULL;
    iph = pcap_get_packet_iphdr(packet);
    if (NULL == iph)
        return FILTER_FALSE;
    struct in_addr st= {0};
    st.s_addr = iph->daddr;
    return filter_check_string(expr, inet_ntoa(st));
}

int dstip_register_filter()
{
    if (filter_register_module(DSTIP_MODULE_NAME, dstip_filter_handler, NULL) != 0) {
        return -1;
    }
    return 0;
}

void dstip_unregister_filter()
{
    filter_unregister_module(DSTIP_MODULE_NAME);
}