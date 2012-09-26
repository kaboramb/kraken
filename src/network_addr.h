#ifndef _KRAKEN_NETWORK_ADDR_H
#define _KRAKEN_NETWORK_ADDR_H

#include <arpa/inet.h>

#define NETADDR_CIDR_ADDRSTRLEN 24

typedef struct network_addr {
	struct in_addr network;
	struct in_addr subnetmask;
} network_addr;

int netaddr_cidr_str_to_nwk(struct network_addr *network, char *netstr);
int netaddr_ip_in_nwk(struct network_addr *network, struct in_addr *ip);
int netaddr_range_str_to_nwk(struct network_addr *network, char *iplow, char *iphigh);
int netaddr_nwk_to_cidr_str(struct network_addr *network, char *netstr, size_t sz_netstr);
int netaddr_ip_is_rfc1918(struct in_addr *ip);
int netaddr_ip_is_rfc3330(struct in_addr *ip);

#endif
