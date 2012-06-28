#include "gui_popups_threads.h"
#include "logging.h"

void gui_popup_thread_dns_enumerate_domain(gpt_dns_enum *gpt_data) {
	gpt_data->response = dns_enumerate_domain_ex(gpt_data->c_host_manager, gpt_data->target_domain, gpt_data->d_opts);
	return;
}

void gui_popup_thread_dns_enumerate_network(gpt_dns_enum *gpt_data) {
	gpt_data->response = dns_enumerate_network_ex(gpt_data->c_host_manager, gpt_data->target_domain, gpt_data->target_net, gpt_data->d_opts);
	return;
}

void gui_popup_thread_http_enumerate_hosts(gpt_http_enum *gpt_data) {
	gpt_data->response = http_enumerate_hosts_ex(gpt_data->c_host_manager, gpt_data->link_anchor, gpt_data->h_opts);
	return;
}

void gui_popup_thread_http_search_engine_bing(gpt_http_enum *gpt_data) {
	gpt_data->response = http_search_engine_bing_ex(gpt_data->c_host_manager, gpt_data->target_domain, gpt_data->h_opts);
	return;
}
