#ifndef _KRAKEN_HTTP_SCAN_H
#define _KRAKEN_HTTP_SCAN_H

#include "dns_enum.h"

#define HTTP_INITIAL_BUFFER_SZ 8192
#define HTTP_RESOURCE_SZ 1023

#define HTTP_SCHEME_SZ 5

typedef struct http_link {
	char scheme[HTTP_SCHEME_SZ + 1];
	char hostname[DNS_MAX_FQDN_LENGTH + 1];
	char path[HTTP_RESOURCE_SZ + 1];
	void *next;
} http_link;

void http_free_link(http_link *current_link);
int http_scrape_for_links(char *target_url, http_link **link_anchor);

#endif
