#ifndef _KRAKEN_GUI_POPUPS_THREADS_H
#define _KRAKEN_GUI_POPUPS_THREADS_H

#include "hosts.h"
#include "dns_enum.h"
#include "http_scan.h"
#include "network_addr.h"

typedef struct gpt_dns_enum {
	host_manager *c_host_manager;
	char *target_domain;
	network_info *target_net;
	dns_enum_opts *d_opts;
	int response;
} gpt_dns_enum;

typedef struct gpt_http_enum {
	host_manager *c_host_manager;
	char *target_domain;
	http_link **link_anchor;
	http_enum_opts *h_opts;
	int response;
} gpt_http_enum;

void gui_popup_thread_dns_enumerate_domain(gpt_dns_enum *gpt_data);
void gui_popup_thread_dns_enumerate_network(gpt_dns_enum *gpt_data);
void gui_popup_thread_http_enumerate_hosts(gpt_http_enum *gpt_data);
void gui_popup_thread_http_search_engine_bing(gpt_http_enum *gpt_data);

#endif
