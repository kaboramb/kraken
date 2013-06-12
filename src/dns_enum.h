// dns_enum.h
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of SecureState Consulting nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef _KRAKEN_DNS_ENUM_H
#define _KRAKEN_DNS_ENUM_H

#include "network_addr.h"

#define DNS_MAX_SIM_QUERIES 8
#define DNS_MAX_FQDN_LENGTH 255 /* also defined in hosts.h */
#define DNS_MAX_NS_HOSTS 4
#define DNS_DEFAULT_ARES_OPTS_TRIES 2
#define DNS_DEFAULT_ARES_OPTS_TIMEOUTMS 2500

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
int dns_bruteforce_names_in_range(network_addr *target_net, host_manager *c_host_manager, domain_ns_list *nameservers, dns_enum_opts *d_opts);
int dns_enum_domain(host_manager *c_host_manager, char *target_domain, const char *hostfile);
int dns_enum_domain_ex(host_manager *c_host_manager, char *target_domain, dns_enum_opts *d_opts);
int dns_enum_network_ex(host_manager *c_host_manager, char *target_domain, network_addr *target_net, dns_enum_opts *d_opts);

#endif
