#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hosts.h"
#include "host_manager.h"

int init_single_host(single_host_info *c_host) {
	memset(c_host, 0, sizeof(struct single_host_info));
	return 0;
}

int destroy_single_host(single_host_info *c_host) {
	return 0;
}

int init_host_master(host_master *c_host_master) {
	c_host_master->hosts = malloc(sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE);
	if (c_host_master->hosts == NULL) {
		return 1;
	}
	c_host_master->known_hosts = 0;
	c_host_master->current_capacity = HOST_CAPACITY_INCREMENT_SIZE;
	memset(c_host_master->hosts, 0, (sizeof(struct single_host_info) * HOST_CAPACITY_INCREMENT_SIZE));
	return 0;
}

int destroy_host_master(host_master *c_host_master) {
	memset(c_host_master->hosts, 0, (sizeof(struct single_host_info) * c_host_master->current_capacity));
	free(c_host_master->hosts);
	c_host_master->known_hosts = 0;
	c_host_master->current_capacity = 0;
	return 0;
}

int host_master_add_host(host_master *c_host_master, single_host_info *new_host) {
	if (c_host_master->known_hosts >= c_host_master->current_capacity) {
		void *tmpbuffer = malloc(sizeof(struct single_host_info) * (c_host_master->current_capacity + HOST_CAPACITY_INCREMENT_SIZE));
		if (tmpbuffer == NULL) {
			return 1;
		}
		c_host_master->current_capacity += HOST_CAPACITY_INCREMENT_SIZE;
		memset(tmpbuffer, 0, (sizeof(single_host_info) * c_host_master->current_capacity));
		memcpy(tmpbuffer, c_host_master->hosts, (sizeof(struct single_host_info) * c_host_master->known_hosts));
		free(c_host_master->hosts);
		c_host_master->hosts = tmpbuffer;
	}
	
	memcpy(&c_host_master->hosts[c_host_master->known_hosts], new_host, sizeof(single_host_info));
	c_host_master->known_hosts++;
	
	return 0;
}
