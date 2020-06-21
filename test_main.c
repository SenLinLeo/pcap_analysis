#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "pcap.h"
#include "ldapexpr.h"

#define BUFFER_LEN 64

#define NIPQUAD(addr)                      \
    ((const unsigned char *)&addr)[0],     \
        ((const unsigned char *)&addr)[1], \
        ((const unsigned char *)&addr)[2], \
        ((const unsigned char *)&addr)[3]

void print_msg_in_packet(pcap_packet_st *packet)
{
    if (NULL == packet)
    {
        printf("packet null\n");
        return;
    }
    char buffer[BUFFER_LEN] = {0};
    struct tm *lt = NULL;
    time_t timestamp = (time_t)pcap_get_packet_timestamp(packet);
    if (timestamp < 0)
    {
        printf("get timestamp fail\n");
        return;
    }
    lt = localtime(&timestamp);
    strftime(buffer, BUFFER_LEN, "%Y-%m-%d %H:%M:%S", lt);
    int packetseq = pcap_get_packet_seq(packet);
    if (packetseq < 0)
    {
        printf("get packetseq fail\n");
        return;
    }
    l2_head_st *l2head = pcap_get_packet_l2header(packet);
    if (NULL == l2head)
    {
        printf("get l2head fail\n");
        return;
    }

    struct iphdr *iph = pcap_get_packet_iphdr(packet);
    if (NULL == iph)
    {
        printf("get ip head fail\n");
        return;
    }
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = (struct tcphdr *)pcap_get_packet_l4hdr(packet);
        if (NULL == tcph)
        {
            printf("get tcp head fail, errmsg:%s\n");
            return;
        }
    }
    else if (iph->protocol == IPPROTO_UDPLITE)
    {
        udph = (struct udphdr *)pcap_get_packet_l4hdr(packet);
        if (NULL == udph)
        {
            printf("get udp head fail, errmsg:%s\n");
            return;
        }
    }
    else {
        //un support
        return;
    }
    printf("time:%s, seq:%d, %s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n",
           buffer, packetseq, tcph ? "TCP" : "UDP",
           NIPQUAD(iph->saddr), tcph ? ntohs(tcph->source) : ntohs(udph->source),
           NIPQUAD(iph->daddr), tcph ? ntohs(tcph->dest) : ntohs(udph->dest));
}

int pcapCallBack(pcap_packet_st *packet, void *user)
{
    if (NULL == packet)
        return -1;
    filter_ctrl_st *filter = (filter_ctrl_st *)user;
    if (filter && !filter_check_packet(filter, packet))
        return 0;
    print_msg_in_packet(packet);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("input param error\n param[1] filename param\n[2] expression\n");
        return -1;
    }
    filter_ctrl_st *filter = NULL;
    pcap_st *pcap = pcap_load_file(argv[1]);
    if (NULL == pcap)
    {
        printf("load file\n");
        return -1;
    }
    if (NULL != argv[2])
    {
        filter = filter_create(argv[2]);
        if (NULL == filter)
        {
            printf("create filter [%s]\n", argv[2]);
            return -1;
        }
    }
    int ret = pcap_foreach_file(pcap, pcapCallBack, filter);
    if (ret < 0)
    {
        printf("foreach pcap file\n");
        goto out;
    }
    if (pcap_rewind_file(pcap) != 0)
    {
        printf("reset file failed\n");
        goto out;
    }
#if 0
    printf("\n\n");

    pcap_packet_st *pkg = NULL;
    int packet_count = 0;
    for (pkg = pcap_read_packet(pcap); pkg; pkg = pcap_read_packet(pcap))
    {
        packet_count++;
        if (filter && !filter_check_packet(filter, pkg))
            continue;
        print_msg_in_packet(pkg);
        pcap_free_packet(pkg);
    }
#endif
out:
    filter_destroy(filter);
    pcap_close_file(pcap);
}
