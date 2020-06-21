#ifndef __DST_PORT_H__
#define __DST_PORT_H__

#include "pcap.h"
#include "ldapexpr.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#define    DSTPORT_MODULE_NAME       "dstport"

int dstport_register_filter();
void dstport_unregister_filter();

#endif
