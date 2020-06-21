#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "srcip_filter.h"

#define PQUAD(addr) \
    ((const unsigned char *)&addr)[0], \
    ((const unsigned char *)&addr)[1], \
    ((const unsigned char *)&addr)[2], \
    ((const unsigned char *)&addr)[3]

static int ip_filter_handler(pcap_packet_st *packet, filter_ctrl_st *expr, void *userdata)
{
    char buf[64] = {0};

    if (NULL == packet || NULL == expr) {
        return FILTER_FALSE;
    }

    struct iphdr *iph = pcap_get_packet_iphdr(packet);
    if (NULL == iph) {
        return FILTER_FALSE;
    }

    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", PQUAD(iph->saddr));

    return filter_check_string(expr, buf);
}

int srcip_register_filter()
{
    if (filter_register_module(IP_MODULE_NAME, ip_filter_handler, NULL) != 0) {
        return -1;
    }
    return 0;
}

void srcip_unregister_filter()
{
    filter_unregister_module(IP_MODULE_NAME);
}