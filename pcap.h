#ifndef __PCAP_H__
#define __PCAP_H__

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct pcap_ctrl_ pcap_st;
typedef struct pcap_packet_ pcap_packet_st;
typedef struct l2_head_ l2_head_st;
typedef int(*getPacketCallBack)(pcap_packet_st *packet, void *user);

/** 加载pcap file 检查文件头部合法性 **/
extern pcap_st *pcap_load_file(const char *filename);

/** 关闭文件 释放资源 **/
extern void pcap_close_file(pcap_st *ctrl);

/** 读取单个包**/
extern pcap_packet_st *pcap_read_packet(pcap_st *ctrl);

/** 释放单个包 **/
extern void	pcap_free_packet(pcap_packet_st *packet);

/** 获取时间戳 **/
extern uint64_t	pcap_get_packet_timestamp(const pcap_packet_st *packet);

/** 获取包序号 **/
extern uint32_t	pcap_get_packet_seq(const pcap_packet_st *packet);

/** 获取二层头部 **/
extern l2_head_st *pcap_get_packet_l2header(const pcap_packet_st *packet);

/** 获取三层头部 **/
extern struct iphdr *pcap_get_packet_iphdr(const pcap_packet_st *packet);

/** 获取四层头部 **/
extern void *pcap_get_packet_l4hdr(const pcap_packet_st *packet);

/** 重置 重新读取文件 **/
extern int pcap_rewind_file(pcap_st *ctrl);

/** 遍历整个文件，用户回调处理 **/
extern int pcap_foreach_file(pcap_st *ctrl, getPacketCallBack callback, void *user);

#endif
