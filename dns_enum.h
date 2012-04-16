#ifndef _KRAKEN_DNS_ENUM_H
#define _KRAKEN_DNS_ENUM_H

#define DNS_MAX_SIM_QUERIES 16
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

#define FIERCE_PREFIXES_PATH "/opt/fierce/hosts.txt"
#define MAX_LINE 512

typedef struct domain_ns_list { /* hold information for up to DNS_MAX_NS_HOSTS name servers */
	char domain[DNS_MAX_FQDN_LENGTH + 1];
	char servers[DNS_MAX_NS_HOSTS][DNS_MAX_FQDN_LENGTH + 1];
	struct in_addr ipv4_addrs[DNS_MAX_NS_HOSTS];
} domain_ns_list;

int bruteforce_names_for_domain(char *target_domain, host_master *c_host_master, domain_ns_list *nameservers);
int dns_enumerate_domain(char *target_domain, host_master *c_host_master);

#endif
