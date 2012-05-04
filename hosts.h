#ifndef _KRAKEN_HOSTS_H
#define _KRAKEN_HOSTS_H

#include <arpa/inet.h>

#ifndef _KRAKEN_WHOIS_LOOKUP_H					/* if it hasn't been included yet, include it */
#define _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS	/* but skil the function definitions at the end */
#include "whois_lookup.h"
#undef _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS		/* don't skip the function definitions next time */
#undef _KRAKEN_WHOIS_LOOKUP_H 					/* next time do include it again because we'll need the function definitions */

#define DNS_MAX_FQDN_LENGTH 255 /* also defined in dns_enum.h */

typedef struct single_host_info {
	struct in_addr ipv4_addr;
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	char (*aliases)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned char n_aliases;
	char is_up;
	struct whois_record *whois_data;
	char os[16];
} single_host_info;

typedef struct host_manager {
	unsigned int known_hosts;
	unsigned int current_capacity;
	unsigned int known_whois_records;
	unsigned int current_whois_record_capacity;
	single_host_info *hosts;
	whois_record *whois_records;
} host_manager;

#endif

#endif
