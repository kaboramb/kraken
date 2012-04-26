#ifndef _KRAKEN_NETWORK_ADDR_H
#define _KRAKEN_NETWORK_ADDR_H

#include <arpa/inet.h>

#define NETADDR_CIDR_ADDRSTRLEN 24

typedef struct network_info {
	struct in_addr network;
	struct in_addr subnetmask;
} network_info;

int netaddr_cidr_str_to_nwk(char *netstr, struct network_info *network);
int netaddr_ip_in_nwk(struct in_addr *ip, struct network_info *network);

#endif
