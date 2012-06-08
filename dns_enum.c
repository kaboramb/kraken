#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "hosts.h"
#include "host_manager.h"
#include "dns_enum.h"
#include "logging.h"
#include "network_addr.h"

static void callback_nameserver_servers(void *args, int status, int timeouts, unsigned char *abuf, int alen) {
	if(status != ARES_SUCCESS){
		return;
	}
	struct hostent *host;
	struct domain_ns_list *nameservers;
	ares_parse_ns_reply(abuf, alen, &host);
    int i = 0;

	nameservers = args;
    for (i = 0; (host->h_aliases[i] && (i < DNS_MAX_NS_HOSTS)); ++i) {
		strncpy((char *)&nameservers->servers[i], host->h_aliases[i], DNS_MAX_FQDN_LENGTH);
    }
    
    ares_free_hostent(host);
	return;
}

static void callback_nameserver_hosts(void *args, int status, int timeouts, struct hostent *host) {
	if(!host || status != ARES_SUCCESS){
		logging_log("kraken.dns_enum", LOGGING_ERROR, "lookup of IP address failed with error: %s", ares_strerror(status));
		return;
	}
	struct domain_ns_list *nameservers;
	int i = 0;
	
	nameservers = args;
	for (i = 0; i < DNS_MAX_NS_HOSTS; ++i) {
		if (strncmp(host->h_name, nameservers->servers[i], strlen(nameservers->servers[i])) == 0) {
			memcpy(&nameservers->ipv4_addrs[i], host->h_addr_list[0], sizeof(struct in_addr));
			break;
		}
	}
	return;
}

static void callback_host(void *c_host_manager, int status, int timeouts, struct hostent *host) {
	if(!host || status != ARES_SUCCESS){
		logging_log("kraken.dns_enum", LOGGING_TRACE, "lookup of IP address failed with error: %s", ares_strerror(status));
		return;
	}
	int i = 0;
	single_host_info new_host;
	init_single_host(&new_host);
	for (i = 0; host->h_addr_list[i]; ++i) {
		memcpy(&new_host.ipv4_addr, host->h_addr_list[i], sizeof(struct in_addr));
		strncpy(new_host.hostname, host->h_name, DNS_MAX_FQDN_LENGTH);
		host_manager_add_host(c_host_manager, &new_host);
	}
	if (*host->h_aliases) {
		host_manager_add_alias_to_host(c_host_manager, host->h_name, *host->h_aliases);
	}
	destroy_single_host(&new_host);
	return;
}

static void wait_ares(ares_channel channel, int max_allowed) {
	if (max_allowed > 0) {
		max_allowed = max_allowed - 1;
	}
	for(;;){
		struct timeval *tvp, tv;
		fd_set read_fds, write_fds;
		int nfds;

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if(nfds <= max_allowed){
			break;
		}
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

char *dns_get_domain(char *originalname) {
	/* this returns a pointer to the second-to-top-level domain */
	char *pCur = originalname;
	int dotfound = 0;
	
	pCur += strlen(originalname);
	while (pCur != originalname) {
		if (*pCur == '.') {
			if (dotfound == 1) {
				return (pCur + 1);
			} else {
				dotfound = 1;
			}
		}
		pCur -= 1;
	}
	if (dotfound == 1) {
		return pCur;
	}
	return NULL;
}

int dns_host_in_domain(char *hostname, char *domain) {
	char *hdomain;
	hdomain = dns_get_domain(hostname);
	if (hdomain == NULL) {
		return 0;
	}
	if (strncasecmp(hdomain, domain, strlen(domain)) == 0) {
		return 1;
	}
	return 0;
}

int dns_get_nameservers_for_domain(char *target_domain, domain_ns_list *nameservers) {
	/* 
	 * returns a negative on an error
	 * otherwise returns the number of nameservers identified up to
	 * the DNS_MAX_NS_HOSTS variable
	 */
	ares_channel channel;
	int status;
	int i;
	
	logging_log("kraken.dns_enum", LOGGING_INFO, "querying nameservers for domain: %s", target_domain);
	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares with error: %s", ares_strerror(status));
		return -1;
	}

	status = ares_init(&channel);
	if(status != ARES_SUCCESS) {
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares options with error: %s", ares_strerror(status));
		return -1;
	}
	
	ares_query(channel, target_domain, 1, DNS_QRY_NS, callback_nameserver_servers, (domain_ns_list *)nameservers);
	wait_ares(channel, 0);
	
	if (nameservers->servers[0][0] == '\0') {
		logging_log("kraken.dns_enum", LOGGING_WARNING, "failed to identify any name servers for domain: %s", target_domain);
		ares_destroy(channel);
		ares_library_cleanup();
		return 0;
	}
	
	for (i = 0; (nameservers->servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); ++i) {
		logging_log("kraken.dns_enum", LOGGING_INFO, "looking up IP for name server %s", nameservers->servers[i]);
		ares_gethostbyname(channel, nameservers->servers[i], AF_INET, callback_nameserver_hosts, (domain_ns_list *)nameservers);
	}
	wait_ares(channel, 0);
	
	ares_destroy(channel);
	ares_library_cleanup();
	LOGGING_QUICK_INFO("kraken.dns_enum", "finished determining name servers")
	return (i + 1);
}

int dns_bruteforce_names_for_domain(char *target_domain, host_manager *c_host_manager, domain_ns_list *nameservers) {
	ares_channel channel;
	int status;
	unsigned int query_counter = 0;
	FILE *fierceprefixes;
	char line[MAX_LINE];
	char hostname[MAX_LINE];
	int i;
	
	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares with error: %s", ares_strerror(status));
		return 1;
	}

	status = ares_init(&channel);
	if(status != ARES_SUCCESS) {
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares options with error: %s", ares_strerror(status));
		return 1;
	}
	
	if (nameservers != NULL) {
		// set the name servers //
		LOGGING_QUICK_INFO("kraken.dns_enum", "switching to use supplied name servers")
		struct ares_addr_node servers_addr_node[DNS_MAX_NS_HOSTS];
		struct in_addr blank_address;
		memset(&servers_addr_node, '\0', sizeof(servers_addr_node));
		memset(&blank_address, '\0', sizeof(blank_address));
		
		for (i = 0; (nameservers->servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
			if (memcmp(&nameservers->ipv4_addrs[i], &blank_address, sizeof(blank_address))) {
				servers_addr_node[i].family = AF_INET;
				servers_addr_node[i].addr.addr4 = nameservers->ipv4_addrs[i];
				servers_addr_node[i].next = &servers_addr_node[i+1];
			}
		}
		servers_addr_node[i].next = NULL;
		ares_set_servers(channel, &servers_addr_node[0]);
	}
	
	logging_log("kraken.dns_enum", LOGGING_INFO, "bruteforcing names for domain: %s", target_domain);

	if ((fierceprefixes = fopen(FIERCE_PREFIXES_PATH, "r")) == NULL) {
		LOGGING_QUICK_ERROR("kraken.dns_enum", "cannot open file containing host name prefixes")
		ares_destroy(channel);
		ares_library_cleanup();
		return 2;
	}

	while (fgets(line, MAX_LINE, fierceprefixes)) {
		line[strlen(line) - 1] = '\0'; /* kill the newline byte */
		snprintf(hostname, MAX_LINE, "%s.%s", line, target_domain);
		//printf("Searching for %s\n", hostname);
		ares_gethostbyname(channel, hostname, AF_INET, callback_host, (host_manager *)c_host_manager);
		query_counter += 1;
		wait_ares(channel, DNS_MAX_SIM_QUERIES);
	}
	
	wait_ares(channel, 0);
	
	ares_destroy(channel);
	ares_library_cleanup();
	logging_log("kraken.dns_enum", LOGGING_INFO, "finished bruteforcing, %u queries were used", query_counter);
	return 0;
}

int dns_bruteforce_names_in_range(network_info *target_net, host_manager *c_host_manager, domain_ns_list *nameservers) {
	ares_channel channel;
	single_host_info *h_info_chk = NULL;
	int status;
	unsigned int query_counter = 0;
	int i;
	struct in_addr c_ip;
	char ipstr[INET6_ADDRSTRLEN];
	char netstr[INET6_ADDRSTRLEN];
	
	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares with error: %s", ares_strerror(status));
		return 1;
	}

	status = ares_init(&channel);
	if(status != ARES_SUCCESS) {
		logging_log("kraken.dns_enum", LOGGING_ERROR, "could not initialize ares options with error: %s", ares_strerror(status));
		return 1;
	}
	
	if (nameservers != NULL) {
		// set the name servers //
		LOGGING_QUICK_INFO("kraken.dns_enum", "switching to use supplied name servers")
		struct ares_addr_node servers_addr_node[DNS_MAX_NS_HOSTS];
		struct in_addr blank_address;
		memset(&servers_addr_node, '\0', sizeof(servers_addr_node));
		memset(&blank_address, '\0', sizeof(blank_address));
		
		for (i = 0; (nameservers->servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
			if (memcmp(&nameservers->ipv4_addrs[i], &blank_address, sizeof(blank_address))) {
				servers_addr_node[i].family = AF_INET;
				servers_addr_node[i].addr.addr4 = nameservers->ipv4_addrs[i];
				servers_addr_node[i].next = &servers_addr_node[i+1];
			}
		}
		servers_addr_node[i].next = NULL;
		ares_set_servers(channel, &servers_addr_node[0]);
	}
	
	inet_ntop(AF_INET, &target_net->network, ipstr, sizeof(ipstr));
	inet_ntop(AF_INET, &target_net->subnetmask, netstr, sizeof(netstr));
	logging_log("kraken.dns_enum", LOGGING_INFO, "bruteforcing names in network: %s %s", ipstr, netstr);
	
	memcpy(&c_ip, &target_net->network, sizeof(c_ip));
	
	while (netaddr_ip_in_nwk(&c_ip, target_net) == 1) {
		host_manager_get_host_by_addr(c_host_manager, &c_ip, &h_info_chk);
		if (h_info_chk != NULL) {
			c_ip.s_addr = htonl(ntohl(c_ip.s_addr) + 1);
			continue;
		}
		ares_gethostbyaddr(channel, &c_ip, sizeof(c_ip), AF_INET, callback_host, (host_manager *)c_host_manager);
		query_counter += 1;
		c_ip.s_addr = htonl(ntohl(c_ip.s_addr) + 1);
		wait_ares(channel, DNS_MAX_SIM_QUERIES);
	}
	
	wait_ares(channel, 0);
	
	ares_destroy(channel);
	ares_library_cleanup();
	logging_log("kraken.dns_enum", LOGGING_INFO, "finished bruteforcing, %u queries were used", query_counter);
	return 0;
}

int dns_enumerate_domain(char *target_domain, host_manager *c_host_manager) {
	domain_ns_list nameservers;
	single_host_info c_host;
	char ipstr[INET_ADDRSTRLEN];
	int i;
	strncpy(c_host_manager->lw_domain, target_domain, DNS_MAX_FQDN_LENGTH);
	memset(&nameservers, '\0', sizeof(nameservers));
	logging_log("kraken.dns_enum", LOGGING_INFO, "enumerating domain: %s", target_domain);
	
	if (dns_get_nameservers_for_domain(target_domain, &nameservers) == 0) {
		return -1;
	}
	for (i = 0; (nameservers.servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
		inet_ntop(AF_INET, &nameservers.ipv4_addrs[i], ipstr, sizeof(ipstr));
		logging_log("kraken.dns_enum", LOGGING_INFO, "found name server %s %s", nameservers.servers[i], ipstr);
		init_single_host(&c_host);
		memcpy(&c_host.ipv4_addr, &nameservers.ipv4_addrs[i], sizeof(struct in_addr));
		strncpy(c_host.hostname, nameservers.servers[i], DNS_MAX_FQDN_LENGTH);
		host_manager_add_host(c_host_manager, &c_host);
		destroy_single_host(&c_host);
	}
	
	dns_bruteforce_names_for_domain(target_domain, c_host_manager, &nameservers);
	
	LOGGING_QUICK_INFO("kraken.dns_enum", "dns enumerate domain finished")
	return 0;
}

int dns_enumerate_network(char *target_domain, network_info *target_net, host_manager *c_host_manager) {
	domain_ns_list nameservers;
	char ipstr[INET6_ADDRSTRLEN];
	char netstr[INET6_ADDRSTRLEN];
	int i;
	strncpy(c_host_manager->lw_domain, target_domain, DNS_MAX_FQDN_LENGTH);
	memset(&nameservers, '\0', sizeof(nameservers));
	
	inet_ntop(AF_INET, &target_net->network, ipstr, sizeof(ipstr));
	inet_ntop(AF_INET, &target_net->subnetmask, netstr, sizeof(netstr));
	logging_log("kraken.dns_enum", LOGGING_INFO, "enumerating network: %s %s", ipstr, netstr);
	
	dns_get_nameservers_for_domain(target_domain, &nameservers);
	for (i = 0; (nameservers.servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
		inet_ntop(AF_INET, &nameservers.ipv4_addrs[i], ipstr, sizeof(ipstr));
		logging_log("kraken.dns_enum", LOGGING_INFO, "found name server %s %s", nameservers.servers[i], ipstr);
	}
	
	dns_bruteforce_names_in_range(target_net, c_host_manager, &nameservers);
	
	LOGGING_QUICK_INFO("kraken.dns_enum", "dns enumerate network finished")
	return 0;
}
