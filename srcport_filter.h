#ifndef __SRCPORT_FILTER_H__
#define __SRCPORT_FILTER_H__

#include "ldapexpr.h"
#include "pcap.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define SRCPORT_MODULE_NAME       "srcport"

int srcport_register_filter();
void srcport_unregister_filter();

#endif
