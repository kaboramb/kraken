#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hosts.h"
#include "host_manager.h"

int init_single_host(single_host_info *c_host) {
	memset(c_host, 0, sizeof(struct single_host_info));
	c_host->whois_data = NULL;
	return 0;
}

int destroy_single_host(single_host_info *c_host) {
	return 0;
}

int init_host_manager(host_manager *c_host_manager) {
	c_host_manager->hosts = malloc(sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE);
	if (c_host_manager->hosts == NULL) {
		return 1;
	}
	c_host_manager->known_hosts = 0;
	c_host_manager->current_capacity = HOST_CAPACITY_INCREMENT_SIZE;
	memset(c_host_manager->hosts, 0, (sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE));
	return 0;
}

int destroy_host_manager(host_manager *c_host_manager) {
	memset(c_host_manager->hosts, 0, (sizeof(struct single_host_info) * c_host_manager->current_capacity));
	free(c_host_manager->hosts);
	c_host_manager->known_hosts = 0;
	c_host_manager->current_capacity = 0;
	return 0;
}

int host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host) {
	if (c_host_manager->known_hosts >= c_host_manager->current_capacity) {
		void *tmpbuffer = malloc(sizeof(struct single_host_info) * (c_host_manager->current_capacity + HOST_CAPACITY_INCREMENT_SIZE));
		if (tmpbuffer == NULL) {
			return 1;
		}
		c_host_manager->current_capacity += HOST_CAPACITY_INCREMENT_SIZE;
		memset(tmpbuffer, 0, (sizeof(single_host_info) * c_host_manager->current_capacity));
		memcpy(tmpbuffer, c_host_manager->hosts, (sizeof(struct single_host_info) * c_host_manager->known_hosts));
		free(c_host_manager->hosts);
		c_host_manager->hosts = tmpbuffer;
	}
	
	memcpy(&c_host_manager->hosts[c_host_manager->known_hosts], new_host, sizeof(single_host_info));
	c_host_manager->known_hosts++;
	
	return 0;
}
