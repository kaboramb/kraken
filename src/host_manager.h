// host_manager.h
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

#ifndef _KRAKEN_HOST_MANAGER_H
#define _KRAKEN_HOST_MANAGER_H

#define HOST_CAPACITY_INCREMENT_SIZE 256
#define WHOIS_CAPACITY_INCREMENT_SIZE 16

typedef kraken_basic_iter host_iter;
typedef kraken_basic_iter whois_iter;
typedef kraken_basic_iter hostname_iter;

int  single_host_init(single_host_info *c_host);
int  single_host_destroy(single_host_info *c_host);
void single_host_iter_hostname_init(single_host_info *c_host, hostname_iter *iter);
int  single_host_iter_hostname_next(single_host_info *c_host, hostname_iter *iter, char **hostname);
int  single_host_add_hostname(single_host_info *c_host, const char *name);
int  single_host_merge(single_host_info *dst, single_host_info *src);
void single_host_set_status(single_host_info *c_host, char status);

int  host_manager_init(host_manager *c_host_manager);
int  host_manager_destroy(host_manager *c_host_manager);
void host_manager_iter_host_init(host_manager *c_host_manager, host_iter *iter);
int  host_manager_iter_host_next(host_manager *c_host_manager, host_iter *iter, single_host_info **c_host);
void host_manager_iter_whois_init(host_manager *c_host_manager, whois_iter *iter);
int  host_manager_iter_whois_next(host_manager *c_host_manager, whois_iter *iter, whois_record **c_whorcd);
int  host_manager_add_host(host_manager *c_host_manager, single_host_info *new_host);
void host_manager_delete_host_by_ip(host_manager *c_host_manager, struct in_addr *target_ip);
int  host_manager_quick_add_by_name(host_manager *c_host_manager, const char *hostname);
int  host_manager_quick_add_by_addr(host_manager *c_host_manager, struct in_addr *target_ip);
int  host_manager_get_host_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, single_host_info **desired_host);
int  host_manager_get_host_by_name(host_manager *c_host_manager, const char *hostname, single_host_info **desired_host);
int  host_manager_get_host_by_id(host_manager *c_host_manager, unsigned int id, single_host_info **desired_host);
int  host_manager_add_whois(host_manager *c_host_manager, whois_record *new_record);
int  host_manager_get_whois(host_manager *c_host_manager, network_addr *network, whois_record **desired_record);
int  host_manager_get_whois_by_addr(host_manager *c_host_manager, struct in_addr *target_ip, whois_record **desired_record);
void host_manager_sync_whois_data(host_manager *c_host_manager);
int  host_manager_set_host_whois(host_manager *c_host_manager, single_host_info *c_host);

#endif
