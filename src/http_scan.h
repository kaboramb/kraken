#ifndef _KRAKEN_HTTP_SCAN_H
#define _KRAKEN_HTTP_SCAN_H

#include "dns_enum.h"

#define HTTP_DEFAULT_TIMEOUT 2
#define HTTP_DEFAULT_TIMEOUT_MS 0
#define HTTP_MAX_REDIRECTS 3
#define HTTP_SCHEME_SZ 5
#define HTTP_RESOURCE_SZ 1023
#define HTTP_BING_API_KEY_SZ 63
#define HTTP_BING_NUM_RESULTS 50
#define HTTP_BING_MAX_RESULTS 500

typedef struct http_link {
	char scheme[HTTP_SCHEME_SZ + 1];
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	char path[HTTP_RESOURCE_SZ + 1];
	void *next;
} http_link;

typedef struct http_enum_opts {
	long timeout;
	long timeout_ms;
	char *bing_api_key;
	void (*progress_update)(unsigned int current, unsigned int last, void *userdata);
	void *progress_update_data;
} http_enum_opts;

void http_enum_opts_init(http_enum_opts *h_opts);
void http_enum_opts_destroy(http_enum_opts *h_opts);
int http_enum_opts_set_bing_api_key(http_enum_opts *h_opts, const char *bing_api_key);
int http_redirect_on_same_server(const char *original_url, const char *redirect_url);
void http_free_link(http_link *current_link);
int http_scrape_for_links(char *target_url, http_link **link_anchor);
int http_scrape_for_links_ip(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor);
int http_scrape_for_links_ip_ex(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor, http_enum_opts *h_opts);
int http_enumerate_hosts_ex(host_manager *c_host_manager, http_link **link_anchor, http_enum_opts *h_opts);
int http_search_engine_bing_ex(host_manager *c_host_manager, const char *target_domain, http_enum_opts *h_opts);

#endif
