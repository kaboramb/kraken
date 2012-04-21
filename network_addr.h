#ifndef _KRAKEN_NETWORK_ADDR_H
#define _KRAKEN_NETWORK_ADDR_H

typedef struct network_info {
	struct in_addr network;
	struct in_addr subnetmask;
} network_info;

netaddr_cidr_str_to_nwk(char *netstr, struct network_info* network);
netaddr_ip_in_nwk(struct *in_addr, struct network_info* network);
#endif
