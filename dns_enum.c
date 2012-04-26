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

static void callback_nameserver_servers(void *args, int status, int timeouts, unsigned char *abuf, int alen) {
	if(status != ARES_SUCCESS){
		printf("ERROR: lookup of nameservers failed with error: %s\n", ares_strerror(status));
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
		printf("ERROR: lookup of IP address failed with error: %s\n", ares_strerror(status));
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
		/* printf("INFO: lookup of IP address failed with error: %s\n", ares_strerror(status)); */
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

int dns_get_nameservers_for_domain(char *target_domain, domain_ns_list *nameservers) {
	ares_channel channel;
	int status;
	int i;

	printf("INFO: querying nameservers for domain: %s\n", target_domain);

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS){
		printf("ERROR: ares_library_init: %s\n", ares_strerror(status));
		return 1;
	}

	status = ares_init(&channel);
	if(status != ARES_SUCCESS) {
		printf("ERROR: ares_init_options: %s\n", ares_strerror(status));
		return 1;
	}
	
	ares_query(channel, target_domain, 1, DNS_QRY_NS, callback_nameserver_servers, (domain_ns_list *)nameservers);
	wait_ares(channel, 0);
	
	for (i = 0; (nameservers->servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); ++i) {
		printf("INFO: looking up IP for name server %s\n", nameservers->servers[i]);
		ares_gethostbyname(channel, nameservers->servers[i], AF_INET, callback_nameserver_hosts, (domain_ns_list *)nameservers);
	}
	wait_ares(channel, 0);
	
	ares_destroy(channel);
	ares_library_cleanup();
	printf("INFO: finished determining name servers\n");
	return 0;
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
		printf("ERROR: ares_library_init: %s\n", ares_strerror(status));
		return 1;
	}

	status = ares_init(&channel);
	if(status != ARES_SUCCESS) {
		printf("ERROR: ares_init_options: %s\n", ares_strerror(status));
		return 1;
	}
	
	if (nameservers != NULL) {
		// set the name servers //
		printf("INFO: swithcing to use supplied name servers\n");
		struct ares_addr_node servers_addr_node[DNS_MAX_NS_HOSTS];
		//struct ares_addr_node *current_server_node;
		struct in_addr blank_address;
		memset(&servers_addr_node, '\0', sizeof(servers_addr_node));
		//current_server_node = &servers_addr_node;
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
	
	printf("INFO: bruteforcing names for domain: %s\n", target_domain);

	if ((fierceprefixes = fopen(FIERCE_PREFIXES_PATH, "r")) == NULL) {
		printf("ERROR: cannot open file from fierce containing prefixes\n");
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
	printf("INFO: finished bruteforcing %u queries\n", query_counter);
	return 0;
}

int dns_enumerate_domain(char *target_domain, host_manager *c_host_manager) {
	domain_ns_list nameservers;
	char ip[INET_ADDRSTRLEN];
	int i;
	memset(&nameservers, '\0', sizeof(nameservers));
	printf("INFO: enumerating domain: %s\n", target_domain);
	
	dns_get_nameservers_for_domain(target_domain, &nameservers);
	for (i = 0; (nameservers.servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
		inet_ntop(AF_INET, &nameservers.ipv4_addrs[i], ip, sizeof(ip));
		printf("INFO: found name server %s %s\n", nameservers.servers[i], ip);
	}
	
	dns_bruteforce_names_for_domain(target_domain, c_host_manager, &nameservers);
	
	printf("INFO: dns enumeration finished\n");
	return 0;
}
