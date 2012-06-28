#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "hosts.h"
#include "host_manager.h"
#include "logging.h"
#include "whois_lookup.h"
#include "network_addr.h"

int single_host_init(single_host_info *c_host) {
	memset(c_host, 0, sizeof(struct single_host_info));
	c_host->aliases = NULL;
	c_host->whois_data = NULL;
	return 0;
}

int single_host_destroy(single_host_info *c_host) {
	if (c_host->aliases) {
		free(c_host->aliases);
	}
	c_host->aliases = NULL;
	c_host->n_aliases = 0;
	return 0;
}

int single_host_add_alias(single_host_info *c_host, const char *alias) {
	char (*block)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned int current_name_i;
	if (c_host->aliases == NULL) {
		/* adding the first alias */
		c_host->aliases = malloc(DNS_MAX_FQDN_LENGTH + 1);
		if (c_host->aliases == NULL) {
			return 1;
		}
		memset(c_host->aliases, '\0', DNS_MAX_FQDN_LENGTH + 1);
		strncpy(c_host->aliases[0], alias, DNS_MAX_FQDN_LENGTH);
		c_host->n_aliases = 1;
	} else {
		/* adding an additional alias */
		for (current_name_i = 0; current_name_i < c_host->n_aliases; current_name_i++) {
			if (strncasecmp(c_host->aliases[current_name_i], alias, DNS_MAX_FQDN_LENGTH) == 0) {
				return 0;
			}
		}
		block = malloc((DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_aliases + 1));
		if (block == NULL) {
			return 1;
		}
		memset(block, '\0', (DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_aliases + 1));
		memcpy(block, c_host->aliases, (DNS_MAX_FQDN_LENGTH + 1) * c_host->n_aliases);
		strncpy(block[c_host->n_aliases], alias, DNS_MAX_FQDN_LENGTH);
		free(c_host->aliases);
		c_host->aliases = block;
		c_host->n_aliases += 1;
	}
	return 0;
}

int host_manager_init(host_manager *c_host_manager) {
	c_host_manager->hosts = malloc(sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE);
	if (c_host_manager->hosts == NULL) {
		return 1;
	}
	memset(c_host_manager->lw_domain, '\0', DNS_MAX_FQDN_LENGTH + 1);
	c_host_manager->save_file_path = NULL;
	c_host_manager->known_hosts = 0;
	c_host_manager->current_capacity = HOST_CAPACITY_INCREMENT_SIZE;
	memset(c_host_manager->hosts, 0, (sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE));
	
	c_host_manager->whois_records = malloc(sizeof(struct whois_record) * WHOIS_CAPACITY_INCREMENT_SIZE);
	if (c_host_manager->whois_records == NULL) {
		free(c_host_manager->hosts);
		return 1;
	}
	kraken_thread_mutex_init(&c_host_manager->k_mutex);
	c_host_manager->known_whois_records = 0;
	c_host_manager->current_whois_record_capacity = WHOIS_CAPACITY_INCREMENT_SIZE;
	memset(c_host_manager->whois_records, 0, (sizeof(struct whois_record) * WHOIS_CAPACITY_INCREMENT_SIZE));
	return 0;
}

int host_manager_destroy(host_manager *c_host_manager) {
	kraken_thread_mutex_destroy(&c_host_manager->k_mutex);
	if (c_host_manager->save_file_path != NULL) {
		free(c_host_manager->save_file_path);
		c_host_manager->save_file_path = NULL;
	}
	memset(c_host_manager->hosts, '\0', (sizeof(struct single_host_info) * c_host_manager->current_capacity));
	free(c_host_manager->hosts);
	c_host_manager->known_hosts = 0;
	c_host_manager->current_capacity = 0;
	
	memset(c_host_manager->whois_records, 0, (sizeof(struct whois_record) * c_host_manager->current_whois_record_capacity));
	free(c_host_manager->whois_records);
	c_host_manager->known_whois_records = 0;
	c_host_manager->current_capacity = 0;
	return 0;
}

int host_manager_add_host(host_manager *c_host_manager, single_host_info *c_host) {
	char (*block)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned int current_host_i;
	whois_record *who_data;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		if ((strncasecmp(c_host->hostname, c_host_manager->hosts[current_host_i].hostname, DNS_MAX_FQDN_LENGTH) == 0) && (memcmp(&c_host->ipv4_addr, &c_host_manager->hosts[current_host_i].ipv4_addr, sizeof(struct in_addr)) == 0)) {
			logging_log("kraken.host_manager", LOGGING_DEBUG, "skipping dupplicate host: %s", c_host->hostname);
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 0;
		}
	}
	
	if (c_host_manager->known_hosts >= c_host_manager->current_capacity) {
		void *tmpbuffer = malloc(sizeof(struct single_host_info) * (c_host_manager->current_capacity + HOST_CAPACITY_INCREMENT_SIZE));
		if (tmpbuffer == NULL) {
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 1;
		}
		c_host_manager->current_capacity += HOST_CAPACITY_INCREMENT_SIZE;
		memset(tmpbuffer, 0, (sizeof(single_host_info) * c_host_manager->current_capacity));
		memcpy(tmpbuffer, c_host_manager->hosts, (sizeof(struct single_host_info) * c_host_manager->known_hosts));
		free(c_host_manager->hosts);
		c_host_manager->hosts = tmpbuffer;
	}
	
	if (c_host->whois_data == NULL) {
		kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
		host_manager_get_whois(c_host_manager, &c_host->ipv4_addr, &who_data);
		kraken_thread_mutex_lock(&c_host_manager->k_mutex);
		if (who_data != NULL) {
			c_host->whois_data = who_data;
		}
	}
	
	memcpy(&c_host_manager->hosts[c_host_manager->known_hosts], c_host, sizeof(single_host_info));
	if (c_host->aliases != NULL) {
		block = malloc((DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_aliases));
		if (block == NULL) {
			c_host_manager->hosts[c_host_manager->known_hosts].aliases = NULL;
			c_host_manager->hosts[c_host_manager->known_hosts].n_aliases = 0;
			c_host_manager->known_hosts++;
			LOGGING_QUICK_WARNING("kraken.host_manager", "aliases have been lost due to a failed malloc")
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 1;
		} else {
			memset(block, '\0', (DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_aliases));
			memcpy(block, c_host->aliases, (DNS_MAX_FQDN_LENGTH + 1) * c_host->n_aliases);
			c_host_manager->hosts[c_host_manager->known_hosts].aliases = block;
		}
	}
	c_host_manager->known_hosts++;
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

void host_manager_delete_host(host_manager *c_host_manager, const char *hostname, struct in_addr *target_ip) {
	unsigned int current_host_i = 0;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (current_host_i < c_host_manager->known_hosts) {
		if (strncasecmp(c_host_manager->hosts[current_host_i].hostname, hostname, strlen(hostname)) != 0) {
			current_host_i++;
			continue;
		} else if (memcmp(&c_host_manager->hosts[current_host_i].ipv4_addr, target_ip, sizeof(struct in_addr)) != 0) {
			current_host_i++;
			continue;
		}
		c_host_manager->known_hosts--;
		memmove(&c_host_manager->hosts[current_host_i], &c_host_manager->hosts[(current_host_i + 1)], (sizeof(struct single_host_info) * (c_host_manager->known_hosts - current_host_i)));
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}

int host_manager_quick_add_by_name(host_manager *c_host_manager, const char *hostname) {
	single_host_info new_host;
	single_host_info *check_host;
	whois_record tmp_who_resp;
	whois_record *cur_who_resp = NULL;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sockaddr_in *sin;
	int ret_val;
	int s;
	char ipstr[INET6_ADDRSTRLEN];
	
	host_manager_get_host_by_name(c_host_manager, hostname, &check_host);
	if (check_host != NULL) {
		return 0;
	}
	
	memset(&hints, '\0', sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	s = getaddrinfo(hostname, NULL, &hints, &result);
	if (s != 0) {
		LOGGING_QUICK_ERROR("kraken.host_manager", "could not resolve the hostname")
		return 1;
	}
	
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET) {
			sin = (struct sockaddr_in *)rp->ai_addr;
			host_manager_get_host_by_addr(c_host_manager, &sin->sin_addr, &check_host);
			if (check_host != NULL) {
				single_host_add_alias(check_host, hostname);
				continue;
			}
			single_host_init(&new_host);
			memcpy(&new_host.ipv4_addr, &sin->sin_addr, sizeof(struct in_addr));
			strncpy(new_host.hostname, hostname, DNS_MAX_FQDN_LENGTH);
			
			host_manager_get_whois(c_host_manager, &new_host.ipv4_addr, &cur_who_resp);
			if (cur_who_resp != NULL) {
				new_host.whois_data = cur_who_resp;
			} else {
				ret_val = whois_lookup_ip(&new_host.ipv4_addr, &tmp_who_resp);
				if (ret_val == 0) {
					inet_ntop(AF_INET, &new_host.ipv4_addr, ipstr, sizeof(ipstr));
					logging_log("kraken.host_manager", LOGGING_INFO, "got whois record for %s, %s", ipstr, tmp_who_resp.cidr_s);
					host_manager_add_whois(c_host_manager, &tmp_who_resp);
					host_manager_get_whois(c_host_manager, &new_host.ipv4_addr, &cur_who_resp);
					new_host.whois_data = cur_who_resp;
				}
			}
			host_manager_add_host(c_host_manager, &new_host);
			single_host_destroy(&new_host);
		}
	}
	return 0;
}

void host_manager_add_alias_to_host_by_name(host_manager *c_host_manager, char *hostname, char *alias) {
	unsigned int current_host_i;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		if (strncmp(hostname, c_host_manager->hosts[current_host_i].hostname, DNS_MAX_FQDN_LENGTH) == 0) {
			single_host_add_alias(&c_host_manager->hosts[current_host_i], alias);
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}

void host_manager_set_host_status(host_manager *c_host_manager, struct in_addr *target_ip, const char status) {
	unsigned int current_host_i;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		if (memcmp(target_ip, &c_host_manager->hosts[current_host_i].ipv4_addr, sizeof(struct in_addr)) == 0) {
			c_host_manager->hosts[current_host_i].is_up = status;
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}

int host_manager_get_host_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, single_host_info **desired_host) {
	unsigned int current_host_i;
	*desired_host = NULL;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		if (memcmp(target_ip, &c_host_manager->hosts[current_host_i].ipv4_addr, sizeof(struct in_addr)) == 0) {
			*desired_host = &c_host_manager->hosts[current_host_i];
			break;
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

void host_manager_get_host_by_name(host_manager *c_host_manager, const char *hostname, single_host_info **desired_host) {
	unsigned int current_host_i;
	single_host_info *c_host;
	int c_alias;
	
	*desired_host = NULL;
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		c_host = &c_host_manager->hosts[current_host_i];
		if (strncasecmp(hostname, c_host->hostname, strlen(hostname)) == 0) {
			*desired_host = c_host;
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return;
		}
		for (c_alias = 0; c_alias < c_host->n_aliases; c_alias++) {
			if (strncasecmp(hostname, c_host->aliases[c_alias], strlen(hostname)) == 0) {
				*desired_host = c_host;
				kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
				return;
			}
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}

int host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record) {
	unsigned int current_who_i;
	whois_record *cur_who_rec;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_who_i = 0; current_who_i < c_host_manager->known_whois_records; current_who_i ++) {
		cur_who_rec = &c_host_manager->whois_records[current_who_i];
		if (strncmp(cur_who_rec->cidr_s, new_record->cidr_s, strlen(cur_who_rec->cidr_s)) == 0) {
			logging_log("kraken.host_manager", LOGGING_DEBUG, "skipping dupplicate whois record for network: %s", cur_who_rec->cidr_s);
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 0;
		}
	}
	if (c_host_manager->known_whois_records >= c_host_manager->current_whois_record_capacity) {
		void *tmpbuffer = malloc(sizeof(struct whois_record) * (c_host_manager->current_whois_record_capacity + WHOIS_CAPACITY_INCREMENT_SIZE));
		if (tmpbuffer == NULL) {
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 1;
		}
		c_host_manager->current_whois_record_capacity += WHOIS_CAPACITY_INCREMENT_SIZE;
		memset(tmpbuffer, 0, (sizeof(whois_record) * c_host_manager->current_whois_record_capacity));
		memcpy(tmpbuffer, c_host_manager->whois_records, (sizeof(struct whois_record) * c_host_manager->known_whois_records));
		free(c_host_manager->whois_records);
		c_host_manager->whois_records = tmpbuffer;
		kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
		host_manager_sync_whois_data(c_host_manager);
		kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	}
	
	memcpy(&c_host_manager->whois_records[c_host_manager->known_whois_records], new_record, sizeof(whois_record));
	c_host_manager->known_whois_records++;
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

int host_manager_get_whois(host_manager *c_host_manager, struct in_addr *target_ip, whois_record **desired_record) {
	/* 
	 * If there is a whois record that corresponds to the target ip then desired_record will be set to point to it
	 * otherwise, desired_record is NULL
	 */
	unsigned int current_who_i;
	whois_record *cur_who_resp;
	network_info network;
	int ret_val = 0;
	
	*desired_record = NULL;
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_who_i = 0; current_who_i < c_host_manager->known_whois_records; current_who_i ++) {
		cur_who_resp = &c_host_manager->whois_records[current_who_i];
		ret_val = netaddr_cidr_str_to_nwk(cur_who_resp->cidr_s, &network);
		if (ret_val == 0) {
			if (netaddr_ip_in_nwk(target_ip, &network) == 1) {
				*desired_record = cur_who_resp;
				break;
			}
		} else {
			logging_log("kraken.host_manager", LOGGING_ERROR, "could not parse cidr address: %s", (char *)&cur_who_resp->cidr_s);
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

void host_manager_sync_whois_data(host_manager *c_host_manager) {
	unsigned int current_host_i;
	single_host_info *current_host;
	whois_record *cur_who_resp = NULL;
	
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		current_host = &c_host_manager->hosts[current_host_i];
		host_manager_get_whois(c_host_manager, &current_host->ipv4_addr, &cur_who_resp);
		if (cur_who_resp != NULL) {
			current_host->whois_data = cur_who_resp;
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}
