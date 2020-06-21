#ifndef __LDAP_H__
#define __LDAP_H__
#include "pcap.h"
typedef struct filter_ctrl_ filter_ctrl_st;

#define FILTER_TRUE 1
#define FILTER_FALSE 0

typedef int(*filter_cmp_handler)(pcap_packet_st *packet, filter_ctrl_st *expr, void *userdata);

/**提供api层 使用 parse **/
filter_ctrl_st *filter_create(const char *expr);

void filter_destroy(filter_ctrl_st *filter);

/** 过滤器输入包结构 匹配规则 **/
int filter_check_packet(filter_ctrl_st *filter, pcap_packet_st *packet);

/** 扩展接口 过滤器注册条件模块 **/
int filter_register_module(const char *key, filter_cmp_handler handler, void *user);

/** 过滤器注销条件模块**/
void filter_unregister_module(const char *key);

const char *filter_get_last_error();

const char *filter_get_name(filter_ctrl_st *filter);

int filter_check_string(filter_ctrl_st *filter, char *str);

int filter_check_uint(filter_ctrl_st *filter, uint32_t number);

#endif
