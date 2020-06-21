#ifndef __SRCIP_FILTER_H__
#define __SRCIP_FILTER_H__

#include "ldapexpr.h"
#include "pcap.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#define IP_MODULE_NAME      "srcip"

int srcip_register_filter();
void srcip_unregister_filter();

#endif