// import.c
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

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "dns_enum.h"
#include "network_addr.h"
#include "utilities.h"

typedef struct update_progress_proxy {
	unsigned int real_total;
	unsigned int real_done;
	void *original_data;
	void (*original_function)(unsigned int current, unsigned int last, void *userdata);
} update_progress_proxy;

void callback_update_progress_proxy(unsigned int current, unsigned int high, update_progress_proxy *up_data) {
	current += up_data->real_done;
	high += up_data->real_total;
	up_data->original_function(current, high, up_data->original_data);
	return;
}

int import_file(host_manager *c_host_manager, char *filename, void (*progress_update)(unsigned int current, unsigned int last, void *userdata), void *progress_update_data, int *action_status) {
	FILE *file_h;
	unsigned int hosts_total = 0;
	unsigned int hosts_done = 0;
	char current_line[DNS_MAX_FQDN_LENGTH + 1]; /* +1 for \n */
	network_addr tmp_network;
	dns_enum_opts d_opts;
	update_progress_proxy up_data;
	struct in_addr ip;

	file_h = fopen(filename, "rb");
	if (file_h == NULL) {
		return -1;
	}
	/* count the lines and hosts in ranges */
	while (fgets(current_line, sizeof(current_line), file_h)) {
		util_str_strip(current_line);
		if (strlen(current_line) < 3) {
			continue;
		}
		if (netaddr_cidr_str_to_nwk(&tmp_network, current_line) == 1) {
			hosts_total += netaddr_ips_in_nwk(&tmp_network);
			continue;
		}
		hosts_total += 1;
	}
	logging_log("kraken.import", LOGGING_INFO, "importing %u hosts", hosts_total);
	fseek(file_h, 0, SEEK_SET);

	while (fgets(current_line, sizeof(current_line), file_h)) {
		if (action_status) {
			if (*action_status != KRAKEN_ACTION_RUN) {
				break;
			}
		}
		util_str_strip(current_line);
		if (strlen(current_line) < 3) {
			continue;
		}
		progress_update(hosts_done, hosts_total, progress_update_data);
		if (netaddr_cidr_str_to_nwk(&tmp_network, current_line) == 1) {
			memset(&up_data, '\0', sizeof(up_data));
			up_data.real_total = hosts_total;
			up_data.real_done = hosts_done;
			up_data.original_data = progress_update_data;
			up_data.original_function = progress_update;
			dns_enum_opts_init(&d_opts);
			d_opts.progress_update = (void *)&callback_update_progress_proxy;
			d_opts.progress_update_data = &up_data;
			d_opts.action_status = action_status;
			dns_bruteforce_names_in_range(&tmp_network, c_host_manager, NULL, &d_opts);
			dns_enum_opts_destroy(&d_opts);
			hosts_done += netaddr_ips_in_nwk(&tmp_network);
			continue;
		}
		if (inet_pton(AF_INET, current_line, &ip) == 1) {
			host_manager_quick_add_by_addr(c_host_manager, &ip);
		} else if (util_str_is_printable(current_line) == 1) {
			host_manager_quick_add_by_name(c_host_manager, current_line);
		}
		hosts_done += 1;
	}
	progress_update(hosts_done, hosts_total, progress_update_data);
	fclose(file_h);
	return 0;
}
