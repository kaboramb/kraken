// http_scan.h
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

#ifndef _KRAKEN_HTTP_SCAN_H
#define _KRAKEN_HTTP_SCAN_H

#include "dns_enum.h"

#define HTTP_DEFAULT_TIMEOUT_MS 7500
#define HTTP_MAX_REDIRECTS 3
#define HTTP_MAX_TIMEOUTS 3
#define HTTP_SCHEME_SZ 5
#define HTTP_RESOURCE_SZ 1023
#define HTTP_BING_API_KEY_SZ 63
#define HTTP_BING_NUM_RESULTS 50
#define HTTP_BING_MAX_RESULTS 500

#define HTTP_SHOULD_STOP(h_opts) (h_opts->action_status != NULL) && (*h_opts->action_status != KRAKEN_ACTION_RUN)

typedef struct http_link {
	char scheme[HTTP_SCHEME_SZ + 1];
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	char path[HTTP_RESOURCE_SZ + 1];
	void *next;
} http_link;

typedef struct http_enum_opts {
	void (*progress_update)(unsigned int current, unsigned int last, void *userdata);
	void *progress_update_data;
	int *action_status;
	long timeout_ms;
	long no_signal;
	char *bing_api_key;
	int use_ssl;
} http_enum_opts;

void http_enum_opts_init(http_enum_opts *h_opts);
void http_enum_opts_destroy(http_enum_opts *h_opts);
int http_enum_opts_set_bing_api_key(http_enum_opts *h_opts, const char *bing_api_key);
int http_redirect_in_same_domain(const char *original_url, const char *redirect_url);
void http_free_link(http_link *current_link);
int http_scrape_url_for_links(char *target_url, http_link **link_anchor);
int http_scrape_ip_for_links(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor);
int http_scrape_ip_for_links_ex(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor, http_enum_opts *h_opts);
int http_scrape_hosts_for_links_ex(host_manager *c_host_manager, http_link **link_anchor, http_enum_opts *h_opts);
int http_search_engine_bing_site_ex(host_manager *c_host_manager, const char *target_domain, http_enum_opts *h_opts);

#endif
