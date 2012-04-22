#ifndef _KRAKEN_HOST_MANAGER_H
#define _KRAKEN_HOST_MANAGER_H

#define HOST_CAPACITY_INCREMENT_SIZE 256
#define WHOIS_CAPACITY_INCREMENT_SIZE 16

int init_single_host(single_host_info *c_host);
int destroy_single_host(single_host_info *c_host);

int init_host_manager(host_manager *c_host_manager);
int destroy_host_manager(host_manager *c_host_manager);
int host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host);
int host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record);
#endif
