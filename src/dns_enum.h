#ifndef _KRAKEN_DNS_ENUM_H
#define _KRAKEN_DNS_ENUM_H

#include "network_addr.h"

#define DNS_MAX_SIM_QUERIES 8
#define DNS_MAX_FQDN_LENGTH 255 /* also defined in hosts.h */
#define DNS_MAX_NS_HOSTS 4

/* more in arpa/namesr.h */
#define DNS_QRY_A 1
#define DNS_QRY_NS 2
#define DNS_QRY_CNAME 5
#define DNS_QRY_PTR 12
#define DNS_QRY_MX 15
#define DNS_QRY_TXT 16
#define DNS_QRY_AAAA 28
#define DNS_QRY_SRV 33
#define DNS_QRY_IXFR 251
#define DNS_QRY_AXFR 252

#define DNS_SHOULD_STOP(d_opts) (d_opts->action_status != NULL) && (*d_opts->action_status != KRAKEN_ACTION_RUN)

typedef struct domain_ns_list { /* hold information for up to DNS_MAX_NS_HOSTS name servers */
	char domain[DNS_MAX_FQDN_LENGTH + 1];
	char servers[DNS_MAX_NS_HOSTS][DNS_MAX_FQDN_LENGTH + 1];
	struct in_addr ipv4_addrs[DNS_MAX_NS_HOSTS];
} domain_ns_list;

typedef struct dns_enum_opts {
	void (*progress_update)(unsigned int current, unsigned int last, void *userdata);
	void *progress_update_data;
	int *action_status;
	int max_sim_queries;
	char *wordlist;
} dns_enum_opts;

char *dns_get_domain(char *originalname);
int dns_host_in_domain(char *hostname, char *domain);

void dns_enum_opts_init(dns_enum_opts *d_opts);
void dns_enum_opts_destroy(dns_enum_opts *d_opts);
int dns_enum_opts_set_wordlist(dns_enum_opts *d_opts, const char *wordlist);

int dns_get_nameservers_for_domain(char *target_domain, domain_ns_list *nameservers);
int dns_bruteforce_names_for_domain(char *target_domain, host_manager *c_host_manager, domain_ns_list *nameservers, dns_enum_opts *d_opts);
int dns_bruteforce_names_in_range(network_info *target_net, host_manager *c_host_manager, domain_ns_list *nameservers, dns_enum_opts *d_opts);
int dns_enum_domain(host_manager *c_host_manager, char *target_domain, const char *hostfile);
int dns_enum_domain_ex(host_manager *c_host_manager, char *target_domain, dns_enum_opts *d_opts);
int dns_enum_network_ex(host_manager *c_host_manager, char *target_domain, network_info *target_net, dns_enum_opts *d_opts);

#endif
