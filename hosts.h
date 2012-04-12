#ifndef _KRAKEN_HOSTS_H
#define _KRAKEN_HOSTS_H

#include <arpa/inet.h>

#define DNS_MAX_FQDN_LENGTH 255 /* also defined in dns_enum.h */

typedef struct single_host_info {
	unsigned char is_up;
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	struct in_addr ipv4_addr;
	char os[16];
} single_host_info;

typedef struct host_master {
	unsigned int known_hosts;
	unsigned int current_capacity;
	single_host_info *hosts;
} host_master;

#endif
