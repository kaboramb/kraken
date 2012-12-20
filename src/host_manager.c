// host_manager.c
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

#include "kraken.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "host_manager.h"
#include "plugins.h"
#include "whois_lookup.h"

int single_host_init(single_host_info *c_host) {
	memset(c_host, 0, sizeof(struct single_host_info));
	c_host->names = NULL;
	c_host->whois_data = NULL;
	return 0;
}

int single_host_destroy(single_host_info *c_host) {
	if (c_host->names) {
		free(c_host->names);
	}
	c_host->names = NULL;
	c_host->n_names = 0;
	return 0;
}

void single_host_iter_hostname_init(single_host_info *c_host, hostname_iter *iter) {
	iter->status = KRAKEN_ITER_STATUS_NEW;
	iter->position = 0;
	return;
}

int single_host_iter_hostname_next(single_host_info *c_host, hostname_iter *iter, char **hostname) {
	if (iter->status == KRAKEN_ITER_STATUS_NEW) {
		iter->status = KRAKEN_ITER_STATUS_USED;
	} else {
		iter->position += 1;
	}
	if (iter->position >= c_host->n_names) {
		*hostname = NULL;
		return 0;
	}
	*hostname = (char *)&c_host->names[iter->position];
	return 1;
}

int single_host_add_hostname(single_host_info *c_host, const char *name) {
	char (*block)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned int current_name_i;

	if (c_host->names == NULL) {
		/* adding the first name */
		c_host->names = malloc(DNS_MAX_FQDN_LENGTH + 1);
		if (c_host->names == NULL) {
			return -1;
		}
		memset(c_host->names, '\0', DNS_MAX_FQDN_LENGTH + 1);
		strncpy(c_host->names[0], name, DNS_MAX_FQDN_LENGTH);
		c_host->n_names = 1;
	} else {
		/* adding an additional name */
		for (current_name_i = 0; current_name_i < c_host->n_names; current_name_i++) {
			if (strncasecmp(c_host->names[current_name_i], name, DNS_MAX_FQDN_LENGTH) == 0) {
				return 0;
			}
		}
		block = malloc((DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_names + 1));
		if (block == NULL) {
			return -1;
		}
		memset(block, '\0', (DNS_MAX_FQDN_LENGTH + 1) * (c_host->n_names + 1));
		memcpy(block, c_host->names, (DNS_MAX_FQDN_LENGTH + 1) * c_host->n_names);
		strncpy(block[c_host->n_names], name, DNS_MAX_FQDN_LENGTH);
		free(c_host->names);
		c_host->names = block;
		c_host->n_names += 1;
	}
	return 0;
}

int single_host_delete_hostname(single_host_info *c_host, const char *name) {
	unsigned int current_name_i;
	char *found_name = NULL;
	size_t sz_names = 0;

	for (current_name_i = 0; current_name_i < c_host->n_names; current_name_i++) {
		if (strncasecmp(c_host->names[current_name_i], name, DNS_MAX_FQDN_LENGTH) == 0) {
			found_name = c_host->names[current_name_i];
			break;
		}
	}
	if (found_name == NULL) {
		return -1;
	}
	c_host->n_names--;
	memset(found_name, '\0', DNS_MAX_FQDN_LENGTH);
	if (c_host->n_names == 0) {
		return 0;
	}
	if (current_name_i < (c_host->n_names - 1)) {
		sz_names = (sizeof(c_host->names[0]) * (c_host->n_names - current_name_i - 1));
		memmove(c_host->names[current_name_i], c_host->names[current_name_i + 1], sz_names);
	}
	return 0;
}

int single_host_merge(single_host_info *dst, single_host_info *src) {
	/* returns 0 when nothing changed, otherwise 1 */
	hostname_iter src_hostname_i;
	char *src_hostname;
	hostname_iter dst_hostname_i;
	char *dst_hostname;
	int found;
	int changed = 0;

	if (dst->whois_data == NULL) {
		dst->whois_data = src->whois_data;
		changed = 1;
	}
	if (dst->status != src->status) {
		dst->status = src->status;
	}

	single_host_iter_hostname_init(src, &src_hostname_i);
	while (single_host_iter_hostname_next(src, &src_hostname_i, &src_hostname)) {
		found = 0;
		single_host_iter_hostname_init(dst, &dst_hostname_i);
		while (single_host_iter_hostname_next(dst, &dst_hostname_i, &dst_hostname)) {
			if (strncasecmp(dst_hostname, src_hostname, DNS_MAX_FQDN_LENGTH) == 0) {
				found = 1;
				break;
			}
		}
		if (found == 0) {
			single_host_add_hostname(dst, src_hostname); // this is not the fastest way to do this
			changed = 1;
		}
	}
	return changed;
}

void single_host_set_status(single_host_info *c_host, char status) {
	if ((c_host->status != KRAKEN_HOST_STATUS_UP) && (status == KRAKEN_HOST_STATUS_UP)) {
		plugins_all_run_callback(PLUGIN_CALLBACK_ID_HOST_STATUS_UP, c_host, NULL, 0);
	}
	c_host->status = status;
	return;
}

int host_manager_init(host_manager *c_host_manager) {
	c_host_manager->hosts = malloc(sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE);
	if (c_host_manager->hosts == NULL) {
		return -1;
	}
	memset(c_host_manager->lw_domain, '\0', DNS_MAX_FQDN_LENGTH + 1);
	c_host_manager->save_file_path = NULL;
	c_host_manager->known_hosts = 0;
	c_host_manager->current_capacity = HOST_CAPACITY_INCREMENT_SIZE;
	memset(c_host_manager->hosts, 0, (sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE));

	c_host_manager->whois_records = malloc(sizeof(struct whois_record) * WHOIS_CAPACITY_INCREMENT_SIZE);
	if (c_host_manager->whois_records == NULL) {
		free(c_host_manager->hosts);
		return -1;
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

void host_manager_iter_host_init(host_manager *c_host_manager, host_iter *iter) {
	iter->status = KRAKEN_ITER_STATUS_NEW;
	iter->position = 0;
	return;
}

int host_manager_iter_host_next(host_manager *c_host_manager, host_iter *iter, single_host_info **c_host) {
	if (iter->status == KRAKEN_ITER_STATUS_NEW) {
		iter->status = KRAKEN_ITER_STATUS_USED;
	} else {
		iter->position += 1;
	}
	if (iter->position >= c_host_manager->known_hosts) {
		*c_host = NULL;
		return 0;
	}
	*c_host = &c_host_manager->hosts[iter->position];
	return 1;
}

void host_manager_iter_whois_init(host_manager *c_host_manager, whois_iter *iter) {
	iter->status = KRAKEN_ITER_STATUS_NEW;
	iter->position = 0;
	return;
}

int host_manager_iter_whois_next(host_manager *c_host_manager, whois_iter *iter, whois_record **c_who_rcd) {
	if (iter->status == KRAKEN_ITER_STATUS_NEW) {
		iter->status = KRAKEN_ITER_STATUS_USED;
	} else {
		iter->position += 1;
	}
	if (iter->position >= c_host_manager->known_whois_records) {
		*c_who_rcd = NULL;
		return 0;
	}
	*c_who_rcd = &c_host_manager->whois_records[iter->position];
	return 1;
}

int host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host) {
	char (*block)[DNS_MAX_FQDN_LENGTH + 1];
	host_iter host_i;
	single_host_info *c_host;
	whois_record *who_data;

	host_manager_iter_host_init(c_host_manager, &host_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		if (memcmp(&new_host->ipv4_addr, &c_host->ipv4_addr, sizeof(struct in_addr)) == 0) {
			if (single_host_merge(c_host, new_host)) {
				plugins_all_run_callback(PLUGIN_CALLBACK_ID_HOST_ON_ADD, new_host, NULL, 0);
			}
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 0;
		}
	}

	if (c_host_manager->known_hosts >= c_host_manager->current_capacity) {
		void *tmpbuffer = malloc(sizeof(struct single_host_info) * (c_host_manager->current_capacity + HOST_CAPACITY_INCREMENT_SIZE));
		if (tmpbuffer == NULL) {
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return -1;
		}
		c_host_manager->current_capacity += HOST_CAPACITY_INCREMENT_SIZE;
		memset(tmpbuffer, 0, (sizeof(single_host_info) * c_host_manager->current_capacity));
		memcpy(tmpbuffer, c_host_manager->hosts, (sizeof(struct single_host_info) * c_host_manager->known_hosts));
		free(c_host_manager->hosts);
		c_host_manager->hosts = tmpbuffer;
	}

	if (new_host->whois_data == NULL) {
		kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
		host_manager_get_whois_by_addr(c_host_manager, &new_host->ipv4_addr, &who_data);
		kraken_thread_mutex_lock(&c_host_manager->k_mutex);
		if (who_data != NULL) {
			new_host->whois_data = who_data;
		}
	}

	plugins_all_run_callback(PLUGIN_CALLBACK_ID_HOST_ON_ADD, new_host, NULL, 0);
	memcpy(&c_host_manager->hosts[c_host_manager->known_hosts], new_host, sizeof(single_host_info));
	if (new_host->names != NULL) {
		block = malloc((DNS_MAX_FQDN_LENGTH + 1) * (new_host->n_names));
		if (block == NULL) {
			c_host_manager->hosts[c_host_manager->known_hosts].names = NULL;
			c_host_manager->hosts[c_host_manager->known_hosts].n_names = 0;
			c_host_manager->known_hosts++;
			LOGGING_QUICK_WARNING("kraken.host_manager", "aliases have been lost due to a failed malloc")
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return -2;
		} else {
			memset(block, '\0', (DNS_MAX_FQDN_LENGTH + 1) * (new_host->n_names));
			memcpy(block, new_host->names, (DNS_MAX_FQDN_LENGTH + 1) * new_host->n_names);
			c_host_manager->hosts[c_host_manager->known_hosts].names = block;
		}
	}
	c_host_manager->known_hosts++;
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

void host_manager_delete_host_by_ip(host_manager *c_host_manager, struct in_addr *target_ip) {
	unsigned int current_host_i = 0;
	struct in_addr preserved_ip; /* preserve it incase the target_ip is actually in the record we're deleting */

	memcpy(&preserved_ip, target_ip, sizeof(struct in_addr));
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (current_host_i < c_host_manager->known_hosts) {
		if (memcmp(&c_host_manager->hosts[current_host_i].ipv4_addr, &preserved_ip, sizeof(struct in_addr)) != 0) {
			current_host_i++;
			continue;
		}
		c_host_manager->known_hosts--;
		single_host_destroy(&c_host_manager->hosts[current_host_i]);
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
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET) {
			sin = (struct sockaddr_in *)rp->ai_addr;
			host_manager_get_host_by_addr(c_host_manager, &sin->sin_addr, &check_host);
			if (check_host != NULL) {
				single_host_add_hostname(check_host, hostname);
				continue;
			}
			single_host_init(&new_host);
			memcpy(&new_host.ipv4_addr, &sin->sin_addr, sizeof(struct in_addr));
			single_host_add_hostname(&new_host, hostname);

			host_manager_get_whois_by_addr(c_host_manager, &new_host.ipv4_addr, &cur_who_resp);
			if (cur_who_resp != NULL) {
				new_host.whois_data = cur_who_resp;
			} else {
				ret_val = whois_lookup_ip(&new_host.ipv4_addr, &tmp_who_resp);
				if (ret_val == 0) {
					inet_ntop(AF_INET, &new_host.ipv4_addr, ipstr, sizeof(ipstr));
					logging_log("kraken.host_manager", LOGGING_INFO, "got whois record for %s, %s", ipstr, tmp_who_resp.cidr_s);
					host_manager_add_whois(c_host_manager, &tmp_who_resp);
					host_manager_get_whois_by_addr(c_host_manager, &new_host.ipv4_addr, &cur_who_resp);
					new_host.whois_data = cur_who_resp;
				}
			}
			host_manager_add_host(c_host_manager, &new_host);
			single_host_destroy(&new_host);
		}
	}
	return 0;
}

int host_manager_get_host_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, single_host_info **desired_host) {
	/* Returns 1 on found, 0 on failure */
	host_iter host_i;
	single_host_info *c_host;
	*desired_host = NULL;

	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	host_manager_iter_host_init(c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		if (memcmp(target_ip, &c_host->ipv4_addr, sizeof(struct in_addr)) == 0) {
			*desired_host = c_host;
			kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
			return 1;
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

int host_manager_get_host_by_name(host_manager *c_host_manager, const char *target_hostname, single_host_info **desired_host) {
	/* Returns 1 on found, 0 on failure */
	host_iter host_i;
	single_host_info *c_host;
	hostname_iter hostname_i;
	char *hostname;

	*desired_host = NULL;
	host_manager_iter_host_init(c_host_manager, &host_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		single_host_iter_hostname_init(c_host, &hostname_i);
		while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
			if (strlen(target_hostname) != strlen(hostname)) {
				continue;
			}
			if (strcasecmp(hostname, target_hostname) == 0) {
				*desired_host = c_host;
				kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
				return 1;
			}
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

int host_manager_get_host_by_id(host_manager *c_host_manager, unsigned int id, single_host_info **desired_host) {
	/* Returns 1 on found, 0 on failure */
	*desired_host = NULL;
	if (id >= c_host_manager->known_hosts) {
		return 0;
	}
	*desired_host = &c_host_manager->hosts[id];
	return 1;
}

int host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record) {
	whois_iter whois_i;
	whois_record *cur_who_rec;

	host_manager_iter_whois_init(c_host_manager, &whois_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_whois_next(c_host_manager, &whois_i, &cur_who_rec)) {
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
			return -1;
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

	plugins_all_run_callback(PLUGIN_CALLBACK_ID_NETWORK_ON_ADD, new_record, NULL, 0);
	memcpy(&c_host_manager->whois_records[c_host_manager->known_whois_records], new_record, sizeof(whois_record));
	c_host_manager->known_whois_records++;
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return 0;
}

int host_manager_get_whois(host_manager *c_host_manager, network_addr *network, whois_record **desired_record) {
	/*
	 * If there is a whois record that corresponds to the target ip then desired_record will be set to point to it
	 * otherwise, desired_record is NULL
	 */
	whois_iter whois_i;
	whois_record *cur_who_resp;
	network_addr tmp_network;

	*desired_record = NULL;
	host_manager_iter_whois_init(c_host_manager, &whois_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_whois_next(c_host_manager, &whois_i, &cur_who_resp)) {
		if (netaddr_cidr_str_to_nwk(&tmp_network, cur_who_resp->cidr_s)) {
			if (memcmp(network, &tmp_network, sizeof(network_addr)) == 0) {
				*desired_record = cur_who_resp;
				break;
			}
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	if (*desired_record != NULL) {
		return 1;
	}
	return 0;
}

int host_manager_get_whois_by_id(host_manager *c_host_manager, unsigned int id, whois_record **desired_record) {
	/* Returns 1 on found, 0 on failure */
	*desired_record = NULL;
	if (id >= c_host_manager->known_whois_records) {
		return 0;
	}
	*desired_record = &c_host_manager->whois_records[id];
	return 1;
}

int host_manager_get_whois_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, whois_record **desired_record) {
	/*
	 * If there is a whois record that corresponds to the target ip then desired_record will be set to point to it
	 * otherwise, desired_record is NULL
	 */
	whois_iter whois_i;
	whois_record *cur_who_resp;
	network_addr network;

	*desired_record = NULL;
	host_manager_iter_whois_init(c_host_manager, &whois_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_whois_next(c_host_manager, &whois_i, &cur_who_resp)) {
		if (netaddr_cidr_str_to_nwk(&network, cur_who_resp->cidr_s)) {
			if (netaddr_ip_in_nwk(&network, target_ip)) {
				*desired_record = cur_who_resp;
				break;
			}
		} else {
			logging_log("kraken.host_manager", LOGGING_ERROR, "could not parse cidr address: %s", (char *)&cur_who_resp->cidr_s);
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	if (*desired_record != NULL) {
		return 1;
	}
	return 0;
}

void host_manager_sync_whois_data(host_manager *c_host_manager) {
	/* Sync with existing data (don't get unknown records)*/
	host_iter host_i;
	single_host_info *c_host;
	whois_record *cur_who_resp = NULL;

	host_manager_iter_host_init(c_host_manager, &host_i);
	kraken_thread_mutex_lock(&c_host_manager->k_mutex);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		host_manager_get_whois_by_addr(c_host_manager, &c_host->ipv4_addr, &cur_who_resp);
		if (cur_who_resp != NULL) {
			c_host->whois_data = cur_who_resp;
		}
	}
	kraken_thread_mutex_unlock(&c_host_manager->k_mutex);
	return;
}
