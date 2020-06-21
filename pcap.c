#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap.h"

#define MAX_PACKET_LEN  65536
#define PCAP_MAGIC      0xa1b2c3d4
#define BUFFER_LEN      2000
#define ERROR_BUFLEN    64

/* 二层头，ethhdr，为了避免引入linux/if_ether.h，这里单独定义 */
struct l2_head_
{
    unsigned char dest[6];	 /* 目的mac地址 */
    unsigned char source[6]; /* 源mac地址 */
    uint16_t proto;			 /* 三层协议 */
};

/* pcap头部信息 */
typedef struct pcap_info_st
{
    uint32_t magic;			/* 主标识:a1b2c3d4 */
    uint16_t version_major; /* 主版本号 */
    uint16_t version_minor; /* 次版本号 */
    uint32_t thiszone;		/* 区域时间0 */
    uint32_t sigfigs;		/* 时间戳0 */
    uint32_t snaplen;		/* 数据包最大长度 */
    uint32_t linktype;		/* 链路层类型 */
} pcap_info_st;

/* pcap每包头部 */
typedef struct packet_head_st
{
    uint32_t gmt_sec;  /* 时间戳，秒部分 */
    uint32_t gmt_msec; /* 时间戳，微秒部分 */
    uint32_t caplen;   /* 被抓取部分的长度 */
    uint32_t len;	   /* 数据包原长度 */
} packet_head_st;

typedef struct ipv4_addr_
{
    uint32_t ip;
} ipv4_addr_st;

typedef struct ipv6_addr_
{
    uint64_t high;
    uint64_t low;
} ipv6_addr_st;

typedef struct ip_addr_
{
    union {
        ipv4_addr_st ipv4;
        ipv6_addr_st ipv6;
    };

} ip_addr_st;

typedef struct filter_param_
{
    ip_addr_st src_ip;
    ip_addr_st dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;

} filter_param_st;

struct pcap_ctrl_
{
    filter_param_st *param;
    pcap_info_st *pcap_info;
    FILE *fp;
    int32_t packet_seq;
};

struct pcap_packet_
{
    packet_head_st data_header;
    uint32_t packet_num;
    char *data;
};

/** 检查pcap文件头部信息 **/
static int check_pcap_header(pcap_st *ctrl)
{
    if (NULL == ctrl) {
        fprintf(stderr, "pcap ctrl null\n");
        return -1;
    }
    pcap_info_st pi;
    if (fread(&pi, sizeof(pi), 1, ctrl->fp) != 1) {
        fprintf(stderr, "pcap header read failed\n");
        return -1;
    }
    if (pi.magic != PCAP_MAGIC) {
        fprintf(stderr, "Invalid pcap file magic\n");
        return -1;
    }
    if (pi.linktype != 1) {
        fprintf(stderr, "Unsupport pcap linktype(%u)\n", pi.linktype);
        return -1;
    }
    memcpy(ctrl->pcap_info, &pi, sizeof(pcap_info_st));
    return 0;
}

/** 加载pcap file 检查文件头部合法性 **/
pcap_st *pcap_load_file(const char *filename)
{
    if (NULL == filename) {
        fprintf(stderr, "filename invalid\n");
        return NULL;
    }
    pcap_st *ctrl = (pcap_st *)malloc(sizeof(pcap_st));
    if (NULL == ctrl) {
        fprintf(stderr, "malloc fail %s\n", filename);
        goto error;
    }
    ctrl->param = (filter_param_st *)malloc(sizeof(filter_param_st));
    if (NULL == ctrl->param) {
        fprintf(stderr, "malloc fail %s\n", filename);
        goto error;
    }
    ctrl->pcap_info = (pcap_info_st *)malloc(sizeof(pcap_info_st));
    if (NULL == ctrl->pcap_info) {
        fprintf(stderr, "malloc fail %s\n", filename);
        goto error;
    }

    memset(ctrl->param, 0, sizeof(filter_param_st));
    memset(ctrl->pcap_info, 0, sizeof(pcap_info_st));
    ctrl->packet_seq = 0;
    ctrl->fp = fopen(filename, "rb");
    if (NULL == ctrl->fp) {
        fprintf(stderr, "open file fail %s\n", filename);
        goto error;
    }
    if (check_pcap_header(ctrl) != 0) {
        fprintf(stderr, "check pcap header failed\n");
        goto error;
    }
    return ctrl;

error:
    pcap_close_file(ctrl);
    return NULL;
}

/** 获取时间戳 **/
uint64_t pcap_get_packet_timestamp(const pcap_packet_st *packet)
{
    if (NULL == packet)
    {
        fprintf(stderr, "packet null\n");
        return -1;
    }
    uint64_t time = packet->data_header.gmt_sec;
    return time;
}

/** 获取包序号**/
uint32_t pcap_get_packet_seq(const pcap_packet_st *packet)
{
    if (NULL == packet) {
        fprintf(stderr, "packet null\n");
        return -1;
    }
    return packet->packet_num;
}

/** 获取二层头部 **/
l2_head_st *pcap_get_packet_l2header(const pcap_packet_st *packet)
{
    if (NULL == packet || NULL == packet->data)
    {
        fprintf(stderr, "packet data null\n");
        return NULL;
    }
    if (packet->data_header.caplen < sizeof(l2_head_st))
    {
        fprintf(stderr, "data is too short for get l2header\n");
        return NULL;
    }
    l2_head_st *l2hdr = (l2_head_st *)packet->data;
    return l2hdr;
}

/** 获取三层头部 **/
struct iphdr *pcap_get_packet_iphdr(const pcap_packet_st *packet)
{
    if (NULL == packet) {
        fprintf(stderr, "packet null\n");
        return NULL;
    }
    if (packet->data_header.caplen < (sizeof(l2_head_st) + sizeof(struct iphdr))) {
        fprintf(stderr, "packet data len too short for l3header\n");
        return NULL;
    }
    struct iphdr *iph = (struct iphdr *)(packet->data + sizeof(l2_head_st));
    return iph;
}

/* 获取四层头部 */
void *pcap_get_packet_l4hdr(const pcap_packet_st *packet)
{
    struct iphdr *iph = NULL;
    uint8_t *curr = NULL;
    int diff = 0;
    if (NULL == packet) {
        fprintf(stderr, "packet null\n");
        return NULL;
    }
    iph = pcap_get_packet_iphdr(packet);
    if (NULL == iph) {
        fprintf(stderr, "iphdr get error\n");
        return NULL;
    }
    diff = sizeof(l2_head_st) + iph->ihl * 4;
    if (packet->data_header.caplen < diff) {
        fprintf(stderr, "packet data too short for l4header\n");
        return NULL;
    }
    curr = packet->data + diff;
    return curr;
}

/** 读取单个包 **/
pcap_packet_st *pcap_read_packet(pcap_st *ctrl)
{
    if (NULL == ctrl || NULL == ctrl->fp)
        return NULL;
    if (feof(ctrl->fp)) {
        fprintf(stderr, "read end of file\n");
        return NULL;
    }
    pcap_packet_st *packet = (pcap_packet_st *)malloc(sizeof(pcap_packet_st));
    if (NULL == packet) {
        fprintf(stderr, "Packet malloc failed\n");
        goto error;
    }
    if (fread(&packet->data_header, sizeof(packet->data_header), 1, ctrl->fp) != 1) {
        fprintf(stderr, "Packet read header failed\n");
        goto error;
    }
    int size = packet->data_header.caplen;
    if (size > ctrl->pcap_info->snaplen || size > MAX_PACKET_LEN) {
        fprintf(stderr, "Invalid packet head(caplen: %u > snaplen: %u)\n",
                size, ctrl->pcap_info->snaplen);
        goto error;
    }

    packet->data = (char *)malloc(size);
    if (NULL == packet->data) {
        fprintf(stderr, "Packet data malloc failed\n");
        goto error;
    }
    if (fread(packet->data, 1, size, ctrl->fp) != size) {
        fprintf(stderr, "Packet read failed\n");
        goto error;
    }
    ctrl->packet_seq++;
    packet->packet_num = ctrl->packet_seq;
    return packet;

error:
    if (packet->data) {
        free(packet->data);
        packet->data = NULL;
    }
    if (packet) {
        free(packet);
        packet = NULL;
    }
    return NULL;
}

/* 释放单个包*/
void pcap_free_packet(pcap_packet_st *packet)
{
    if (NULL == packet) {
        return;
    }
    if (packet->data) {
        free(packet->data);
        packet->data = NULL;
    }
    free(packet);
    packet = NULL;
}

/* 遍历pcap文件 传入回调函数 用户数据 */
int pcap_foreach_file(pcap_st *ctrl, getPacketCallBack callback, void *userdata)
{
    if (NULL == ctrl || NULL == callback) {
        return -1;
    }

    int packetsize = 0;
    int pkt_counter = 1;
    int buf_len = MAX_PACKET_LEN;
    pcap_packet_st packet;
    packet.data = (char *)malloc(buf_len);
    if (NULL == packet.data) {
        fprintf(stderr, "packet data malloc fail\n");
        return -1;
    }

    // memset(packet.data, 0, buf_len);
    while (fread(&packet.data_header, sizeof(packet.data_header), 1, ctrl->fp) == 1) {
        if (packet.data_header.caplen > ctrl->pcap_info->snaplen || packet.data_header.caplen > MAX_PACKET_LEN) {
            fprintf(stderr, "Packet %d: Invalid packet head(caplen: %u > snaplen: %u)\n",
                    pkt_counter, packet.data_header.caplen, ctrl->pcap_info->snaplen);
            goto fail;
        }
        memset(packet.data, 0, MAX_PACKET_LEN);
        if (fread(packet.data, 1, packet.data_header.caplen, ctrl->fp) != packet.data_header.caplen) {
            fprintf(stderr, "Packet %d: Read packet data failed\n", pkt_counter);
            goto fail;
        }
        packet.packet_num = pkt_counter;
        if (callback(&packet, userdata) < 0) {
            fprintf(stderr, "Packet %d: handle data failed\n", pkt_counter);
            goto fail;
        }
        pkt_counter++;
    }

    free(packet.data);
    packet.data = NULL;
    return 0;

fail:
    free(packet.data);
    packet.data = NULL;
    return -1;
}

/* 关闭文件 释放资源
*/
void pcap_close_file(pcap_st *ctrl)
{
    if (NULL == ctrl) {
        return;
    }

    if (ctrl->fp) {
        fclose(ctrl->fp);
    }

    if (ctrl->param) {
        free(ctrl->param);
        ctrl->param = NULL;
    }
    if (ctrl->pcap_info) {
        free(ctrl->pcap_info);
        ctrl->pcap_info = NULL;
    }
    free(ctrl);
    ctrl = NULL;
    return;
}

/* 重置读取文件最初状态 */
int pcap_rewind_file(pcap_st *ctrl)
{
    if (NULL == ctrl) {
        return -1;
    }

    if (ctrl->fp) {
        //重置文件指针值到开头
        rewind(ctrl->fp);
        if (check_pcap_header(ctrl) != 0) {
            fprintf(stderr, "check pcap header failed\n");
            return -1;
        }
        ctrl->packet_seq = 0;
    }

    return 0;
}
