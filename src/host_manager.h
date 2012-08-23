#ifndef _KRAKEN_HOST_MANAGER_H
#define _KRAKEN_HOST_MANAGER_H

#define HOST_CAPACITY_INCREMENT_SIZE 256
#define WHOIS_CAPACITY_INCREMENT_SIZE 16

typedef kraken_basic_iter host_iter;
typedef kraken_basic_iter whois_iter;

int single_host_init(single_host_info *c_host);
int single_host_destroy(single_host_info *c_host);
int single_host_add_hostname(single_host_info *c_host, const char *name);
int single_host_merge(single_host_info *dst, single_host_info *src);

int  host_manager_init(host_manager *c_host_manager);
int  host_manager_destroy(host_manager *c_host_manager);
void host_manager_iter_host_init(host_manager *c_host_manager, host_iter *iter);
int  host_manager_iter_host_next(host_manager *c_host_manager, host_iter *iter, single_host_info **c_host);
void host_manager_iter_whois_init(host_manager *c_host_manager, whois_iter *iter);
int  host_manager_iter_whois_next(host_manager *c_host_manager, whois_iter *iter, whois_record **c_whorcd);
int  host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host);
void host_manager_delete_host_by_ip(host_manager *c_host_manager, struct in_addr *target_ip);
int  host_manager_quick_add_by_name(host_manager *c_host_manager, const char *hostname);
void host_manager_set_host_status(host_manager *c_host_manager, struct in_addr *target_ip, const char status);
int  host_manager_get_host_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, single_host_info **desired_host);
void host_manager_get_host_by_name(host_manager *c_host_manager, const char *hostname, single_host_info **desired_host);
int  host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record);
int  host_manager_get_whois(host_manager *c_host_manager, struct in_addr *target_ip, whois_record **desired_record);
void host_manager_sync_whois_data(host_manager *c_host_manager);

#endif
