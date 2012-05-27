#ifndef _KRAKEN_HOST_MANAGER_H
#define _KRAKEN_HOST_MANAGER_H

#define HOST_CAPACITY_INCREMENT_SIZE 256
#define WHOIS_CAPACITY_INCREMENT_SIZE 16

int init_single_host(single_host_info *c_host);
int destroy_single_host(single_host_info *c_host);

int init_host_manager(host_manager *c_host_manager);
int destroy_host_manager(host_manager *c_host_manager);
int host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host);
int host_manager_quick_add_by_name(host_manager *c_host_manager, char *hostname);
int host_manager_add_alias_to_host(host_manager *c_host_manager, char *hostname, char* alias);
int host_manager_get_host_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, single_host_info **desired_host);
int host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record);
int host_manager_get_whois(host_manager *c_host_manager, struct in_addr *target_ip, whois_record **desired_record);
void host_manager_sync_whois_data(host_manager *c_host_manager);

#endif
