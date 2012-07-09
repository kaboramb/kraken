#ifndef _KRAKEN_KRAKEN_H
#define _KRAKEN_KRAKEN_H

#include <arpa/inet.h>

#ifndef _KRAKEN_WHOIS_LOOKUP_H					/* if it hasn't been included yet, include it */
#define _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS	/* but skil the function definitions at the end */
#include "whois_lookup.h"
#undef _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS		/* don't skip the function definitions next time */
#undef _KRAKEN_WHOIS_LOOKUP_H 					/* next time do include it again because we'll need the function definitions */

#include "kraken_thread.h"
#include "kraken_options.h"
#include "logging.h"

#define MAX_LINE 512

#define DNS_MAX_FQDN_LENGTH 255 /* also defined in dns_enum.h */
#define KRAKEN_HOST_UP 1
#define KRAKEN_HOST_UNKNOWN 0
#define KRAKEN_HOST_DOWN -1

#define KRAKEN_ACTION_RUN 0
#define KRAKEN_ACTION_STOP 1

typedef struct single_host_info {
	struct in_addr ipv4_addr;
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	struct whois_record *whois_data;
	char (*aliases)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned char n_aliases;
	unsigned char os;
	char is_up;
} single_host_info;

typedef struct host_manager {
	kraken_thread_mutex k_mutex;
	char lw_domain[DNS_MAX_FQDN_LENGTH + 1];	/* last working domain, so we can keep track in the GUI if we want */
	char *save_file_path;
	unsigned int known_hosts;
	unsigned int current_capacity;
	unsigned int known_whois_records;
	unsigned int current_whois_record_capacity;
	single_host_info *hosts;
	whois_record *whois_records;
} host_manager;

#endif

#endif
