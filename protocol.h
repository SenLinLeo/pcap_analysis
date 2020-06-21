#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include "ldapexpr.h"
#include "pcap.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#define PRO_MODULE_NAME "protocol"
#define TCP_PRO         "tcp"
#define UDP_PRO         "udp"

int protocal_register_filter();
void protocal_unregister_filter();

#endif
