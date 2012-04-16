#ifndef _KRAKEN_HOST_MANAGER_H
#define _KRAKEN_HOST_MANAGER_H

#define HOST_CAPACITY_INCREMENT_SIZE 256

int init_single_host(single_host_info *c_host);
int destroy_single_host(single_host_info *c_host);

int init_host_master(host_master *c_host_master);
int destroy_host_master(host_master *c_host_master);
int host_master_add_host(host_master *c_host_master, single_host_info *new_host);

#endif
