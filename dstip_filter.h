#ifndef __DST_IP_H__
#define __DST_IP_H__

#include "pcap.h"
#include "ldapexpr.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#if 0
typedef int (*filter_parse_fn_t)(filter_st* filt, const char *value, filter_engine_st* eng);
typedef int (*subject_cmp_fn_t)(filter_st* filt, filter_pack_st *pkt, filter_engine_st* eng);

struct filter_engine_st {
    const char* subject;
    filter_parse_fn_t parse;
    subject_cmp_fn_t compare;
};
#endif

#define DSTIP_MODULE_NAME "dstip"

int dstip_register_filter();
void dstip_unregister_filter();

#endif
