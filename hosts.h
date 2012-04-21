#ifndef _KRAKEN_HOSTS_H
#define _KRAKEN_HOSTS_H

#include <arpa/inet.h>
#include "whois_lookup.h"

#define DNS_MAX_FQDN_LENGTH 255 /* also defined in dns_enum.h */

typedef struct single_host_info {
	unsigned char is_up;
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	struct in_addr ipv4_addr;
	struct whois_response *whois_data;
	char os[16];
} single_host_info;

typedef struct host_manager {
	unsigned int known_hosts;
	unsigned int current_capacity;
	single_host_info *hosts;
} host_manager;

#endif
