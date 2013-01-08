// http_scan.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <uriparser/Uri.h>

#include "host_manager.h"
#include "http_scan.h"

void http_enum_opts_init(http_enum_opts *h_opts) {
	curl_version_info_data *curl_info;

	curl_info = curl_version_info(CURLVERSION_NOW);
	memset(h_opts, '\0', sizeof(struct http_enum_opts));
	h_opts->timeout_ms = HTTP_DEFAULT_TIMEOUT_MS;
	if ((curl_info->features & CURL_VERSION_ASYNCHDNS)) {
		h_opts->no_signal = 0;
	} else {
		h_opts->no_signal = 1;
	}
	h_opts->bing_api_key = NULL;
	h_opts->progress_update = NULL;
	h_opts->progress_update_data = NULL;
	h_opts->action_status = NULL;
	h_opts->use_ssl = 0;
	return;
}

void http_enum_opts_destroy(http_enum_opts *h_opts) {
	if (h_opts->bing_api_key != NULL) {
		free(h_opts->bing_api_key);
	}
	memset(h_opts, '\0', sizeof(struct http_enum_opts));
	return;
}

void http_enum_opts_config_curl_easy(http_enum_opts *h_opts, CURL *curl_h) {
	curl_easy_setopt(curl_h, CURLOPT_TIMEOUT_MS, h_opts->timeout_ms);

	if (h_opts->no_signal != 0) {
		curl_easy_setopt(curl_h, CURLOPT_NOSIGNAL, 1);
	}
	return;
}

int http_enum_opts_set_bing_api_key(http_enum_opts *h_opts, const char *bing_api_key) {
	size_t bing_api_key_len;
	if (h_opts->bing_api_key != NULL) {
		free(h_opts->bing_api_key);
		h_opts->bing_api_key = NULL;
	}
	if (strlen(bing_api_key) > HTTP_BING_API_KEY_SZ) {
		return -1;
	}
	bing_api_key_len = strlen(bing_api_key);
	h_opts->bing_api_key = malloc(bing_api_key_len + 1);
	assert(h_opts->bing_api_key != NULL);
	strncpy(h_opts->bing_api_key, bing_api_key, bing_api_key_len);
	h_opts->bing_api_key[bing_api_key_len] = '\0';
	return 0;
}

int http_redirect_in_same_domain(const char *original_url, const char *redirect_url) {
	/*
	 * Returns 0 on "No, the redirect url is to a different server"
	 * Returns 1 on "Yes the redirect url is in the same domain"
	 * Returns 2 on "Yes, and the redirect url is on the same server"
	 */
	UriParserStateA uri_state;
	UriUriA orig_uri;
	UriUriA redir_uri;
	char *original_domain;
	char original_host[DNS_MAX_FQDN_LENGTH + 1];
	char redirect_host[DNS_MAX_FQDN_LENGTH + 1];

	uri_state.uri = &redir_uri;
	if (uriParseUriA(&uri_state, redirect_url) != URI_SUCCESS) {
		uriFreeUriMembersA(&redir_uri);
		return -1;
	}
	if ((redir_uri.hostText.afterLast - redir_uri.hostText.first) == 0) {
		uriFreeUriMembersA(&redir_uri);
		return 2;
	}

	uri_state.uri = &orig_uri;
	if (uriParseUriA(&uri_state, original_url) != URI_SUCCESS) {
		uriFreeUriMembersA(&redir_uri);
		uriFreeUriMembersA(&orig_uri);
		return -1;
	}

	memset(original_host, '\0', sizeof(original_host));
	memset(redirect_host, '\0', sizeof(redirect_host));

	if ((orig_uri.hostText.afterLast - orig_uri.hostText.first) > DNS_MAX_FQDN_LENGTH) {
		return -1;
	}
	if ((redir_uri.hostText.afterLast - redir_uri.hostText.first) > DNS_MAX_FQDN_LENGTH) {
		return -1;
	}
	strncpy(original_host, orig_uri.hostText.first, (orig_uri.hostText.afterLast - orig_uri.hostText.first));
	strncpy(redirect_host, redir_uri.hostText.first, (redir_uri.hostText.afterLast - redir_uri.hostText.first));

	uriFreeUriMembersA(&redir_uri);
	uriFreeUriMembersA(&orig_uri);

	if (strlen(original_host) == strlen(redirect_host)) {
		if (strncasecmp(original_host, redirect_host, strlen(original_host)) == 0) {
			return 2;
		}
	}

	original_domain = dns_get_domain(original_host);
	if (original_domain == NULL) {
		return -1;
	}
	if (dns_host_in_domain(redirect_host, original_domain)) {
		return 1;
	}
	return 0;
}

void http_free_link(http_link *current_link) {
	http_link *next_link = NULL;
	while (current_link != NULL) {
		next_link = current_link->next;
		free(current_link);
		current_link = next_link;
	}
	return;
}

static void process_html_nodes_for_links(xmlNode *a_node, http_link **tmp_link) {
	xmlNode *cur_node = NULL;
	xmlAttr *attribute = NULL;
	UriParserStateA uri_state;
	UriUriA uri;
	int processTag = 0;
	int processLink = 1;
	unsigned int len;
	char targetHtmlAttribute[7]; /* largest is form's action */
	http_link *current_link = NULL;
	http_link *anchor_link = *tmp_link;

	for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			processTag = 0;
			if (strncasecmp((char *)cur_node->name, "a", 1) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "href");
			} else if (strncasecmp((char *)cur_node->name, "img", 3) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			} else if (strncasecmp((char *)cur_node->name, "form", 4) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "action");
			} else if (strncasecmp((char *)cur_node->name, "script", 6) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			} else if (strncasecmp((char *)cur_node->name, "iframe", 6) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			} else if (strncasecmp((char *)cur_node->name, "div", 3) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			} else if (strncasecmp((char *)cur_node->name, "frame", 5) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			} else if (strncasecmp((char *)cur_node->name, "embed", 5) == 0) {
				processTag = 1;
				strcpy(targetHtmlAttribute, "src");
			}

			if (processTag) {
				for (attribute = cur_node->properties; attribute != NULL; attribute = attribute->next) {
					if (strncasecmp((char *)attribute->name, targetHtmlAttribute, sizeof(targetHtmlAttribute)) != 0) {
						continue;
					}
					xmlChar *value = xmlNodeListGetString(cur_node->doc, attribute->children, 1);
					assert(value != NULL);
					/* if we wanted to continue to crawl additional pages on the same server, the
					 * code would go here before we run strncasecmp() on the scheme */
					if (strncasecmp((char *)value, "http", 4) == 0) { /* matches http and https */
						uri_state.uri = &uri;
						if (uriParseUriA(&uri_state, (char *)value) != URI_SUCCESS) {
							LOGGING_QUICK_ERROR("kraken.http_scan", "uriparser could not parse a URI extracted from the HTML")
							uriFreeUriMembersA(&uri);
							continue;
						}
						processLink = 1;
						if (anchor_link != NULL) {
							for (current_link = anchor_link; current_link; current_link = current_link->next) {
								if (strncmp(current_link->scheme, uri.scheme.first, strlen(current_link->scheme)) == 0) {
									if (strncmp(current_link->hostname, uri.hostText.first, strlen(current_link->hostname)) == 0) {
										if ((uri.pathHead == NULL) && (strlen(current_link->path) == 0)) {
											processLink = 0;
											break;
										} else if ((uri.pathHead == NULL) && (strlen(current_link->path) != 0)) {
											continue;
										}
										if ((strlen(uri.pathHead->text.first) < 2) || (strncmp(current_link->path, uri.pathHead->text.first, strlen(current_link->path)) == 0)) {
											processLink = 0;
											break; /* got a duplicate link, ignore it */
										}
									}
								}
							}
							if (processLink == 0) {
								continue;
							}
						}
						if (anchor_link == NULL) {
							anchor_link = malloc(sizeof(http_link));
							current_link = anchor_link;
						} else if (anchor_link->next == NULL) {
							anchor_link->next = malloc(sizeof(http_link));
							current_link = anchor_link->next;
						} else {
							current_link = anchor_link->next;
							while (current_link->next != NULL) {
								current_link = current_link->next;
							}
							current_link->next = malloc(sizeof(http_link));
							current_link = current_link->next;
						}
						memset(current_link, '\0', sizeof(http_link));
						len = (uri.scheme.afterLast - uri.scheme.first);
						if (len < HTTP_SCHEME_SZ) {
							strncpy(current_link->scheme, uri.scheme.first, len);
						} else {
							strncpy(current_link->scheme, uri.scheme.first, HTTP_SCHEME_SZ);
						}
						len = (uri.hostText.afterLast - uri.hostText.first);
						if (len < DNS_MAX_FQDN_LENGTH) {
							strncpy(current_link->hostname, uri.hostText.first, len);
						} else {
							strncpy(current_link->hostname, uri.hostText.first, DNS_MAX_FQDN_LENGTH);
						}
						if ((uri.pathHead != NULL) && (strlen(uri.pathHead->text.first) > 1)) {
							strncpy(current_link->path, uri.pathHead->text.first, HTTP_RESOURCE_SZ);
						}
						uriFreeUriMembersA(&uri);
					}
					xmlFree(value);
				}
			}
		}
		if (*tmp_link == NULL && anchor_link != NULL) {
			*tmp_link = anchor_link;
		}
		process_html_nodes_for_links(cur_node->children, tmp_link);
	}
}

int http_get_links_from_html(char *tPage, http_link **link_anchor) {
	xmlDoc *page;
	xmlNode *root_element = NULL;
	http_link *link_current = *link_anchor;

	page = xmlReadMemory(tPage, strlen(tPage), "noname.xml", NULL, (XML_PARSE_RECOVER | XML_PARSE_NOERROR));
	if (page == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "libxml2 failed to parse provided data")
		return -1;
	}
	root_element = xmlDocGetRootElement(page);
	if (root_element == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "could not retrieve the root element of the HTML document")
		xmlFreeDoc(page);
		return -1;
	}
	process_html_nodes_for_links(root_element, &link_current);
	*link_anchor = link_current;
	if (*link_anchor == NULL) {
		LOGGING_QUICK_INFO("kraken.http_scan", "processed html and got no links")
		xmlFreeDoc(page);
		return 0;
	}
	xmlFreeDoc(page);
	return 0;
}

int http_process_request_for_links(CURL *curl, const char *target_url, char **webpage_b, http_link **link_anchor, http_link **pvt_link_anchor, http_enum_opts *h_opts) {
	CURLcode curl_res;
	CURL *curl_redir = NULL;
	size_t webpage_sz = 0;
	http_link *link_current = *link_anchor;
	FILE *webpage_f = NULL;
	long http_code = 0;
	int redirect_count = 0;
	unsigned int link_counter = 0;
	char *content_type;
	char *redirected_url = NULL;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code != 200) {
		logging_log("kraken.http_scan", LOGGING_DEBUG, "web server responded with: %lu", http_code);
	}
	while (((http_code == 301) || (http_code == 302)) && (redirect_count < HTTP_MAX_REDIRECTS)) {
		redirect_count++;
		curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirected_url);
		if (http_redirect_in_same_domain(target_url, redirected_url)) {
			if (curl_redir != NULL) {
				curl_easy_cleanup(curl_redir);
			}
			free(*webpage_b);
			*webpage_b = NULL;
			webpage_f = open_memstream(webpage_b, &webpage_sz);
			if (webpage_f == NULL) {
				LOGGING_QUICK_ERROR("kraken.http_scan", "could not open a memory stream")
				return 1;
			}
			curl_redir = curl_easy_init();
			assert(curl_redir != NULL);
			http_enum_opts_config_curl_easy(h_opts, curl_redir);
			curl_easy_setopt(curl_redir, CURLOPT_URL, redirected_url);
			curl_easy_setopt(curl_redir, CURLOPT_WRITEDATA, webpage_f);

			curl_res = curl_easy_perform(curl_redir);
			fclose(webpage_f);

			if (curl_res != 0) {
				LOGGING_QUICK_ERROR("kraken.http_scan", "the HTTP request failed")
				curl_easy_cleanup(curl_redir);
				return 2;
			}
			curl_easy_getinfo(curl_redir, CURLINFO_RESPONSE_CODE, &http_code);
			if (http_code != 200) {
				logging_log("kraken.http_scan", LOGGING_DEBUG, "web server responded with: %lu", http_code);
			}
		} else {
			logging_log("kraken.http_scan", LOGGING_ERROR, "web server attempted to redirect us off site to: %s", redirected_url);
			return 3;
		}
	}
	if (redirect_count == HTTP_MAX_REDIRECTS) {
		LOGGING_QUICK_WARNING("kraken.http_scan", "received too many redirects")
		return 6;
	}

	logging_log("kraken.http_scan", LOGGING_DEBUG, "%lu bytes were read from the http response", webpage_sz);
	if (redirected_url == NULL) {
		curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
	} else {
		curl_easy_getinfo(curl_redir, CURLINFO_CONTENT_TYPE, &content_type);
	}
	if (curl_redir != NULL) {
		curl_easy_cleanup(curl_redir);
	}
	if (content_type == NULL) {
		LOGGING_QUICK_WARNING("kraken.http_scan", "the content type was not provided in the servers response")
		return 4;
	}
	if (strstr(content_type, "text/html")) {
		http_get_links_from_html(*webpage_b, &link_current);
		*link_anchor = link_current;
	} else {
		logging_log("kraken.http_scan", LOGGING_WARNING, "received an invalid content type from %s", target_url);
		return 5;
	}
	if (link_current && (*pvt_link_anchor == NULL)) {
		for (link_current = *link_anchor; link_current; link_current = link_current->next) {
			link_counter++;
		}
	} else if (*pvt_link_anchor) {
		for (link_current = *pvt_link_anchor; link_current; link_current = link_current->next) {
			link_counter++;
		}
	}

	logging_log("kraken.http_scan", LOGGING_INFO, "gathered %u new links", link_counter);
	return 0;
}

int http_scrape_url_for_links(char *target_url, http_link **link_anchor) {
	/* link_anchor should either be NULL or an existing list returned by
	 * a previous call to this or a similar function */
	size_t webpage_sz;
	FILE *webpage_f = NULL;
	char *webpage_b = NULL;
	CURL *curl;
	CURLcode curl_res;
	http_link *pvt_link_anchor = *link_anchor; /* used for calculating differences */
	http_enum_opts h_opts;

	if (pvt_link_anchor) {
		while (pvt_link_anchor->next) {
			pvt_link_anchor = pvt_link_anchor->next;
		}
	}

	webpage_f = open_memstream(&webpage_b, &webpage_sz);
	if (webpage_f == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "could not open a memory stream")
		return -1;
	}

	http_enum_opts_init(&h_opts);
	curl = curl_easy_init();
	assert(curl != NULL);
	http_enum_opts_config_curl_easy(&h_opts, curl);
	curl_easy_setopt(curl, CURLOPT_URL, target_url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, webpage_f);

	curl_res = curl_easy_perform(curl);
	fclose(webpage_f);

	assert(webpage_b != NULL);
	if (curl_res != 0) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "the HTTP request failed")
		free(webpage_b);
		curl_easy_cleanup(curl);
		http_enum_opts_destroy(&h_opts);
		return -2;
	}

	http_process_request_for_links(curl, target_url, &webpage_b, link_anchor, &pvt_link_anchor, &h_opts);

	if (webpage_b != NULL) {
		free(webpage_b);
	}
	curl_easy_cleanup(curl);
	http_enum_opts_destroy(&h_opts);
	return 0;
}

int http_scrape_ip_for_links(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor) {
	http_enum_opts h_opts;
	int response;

	http_enum_opts_init(&h_opts);
	response = http_scrape_ip_for_links_ex(hostname, addr, resource, link_anchor, &h_opts);
	if (response < 0) {
		h_opts.use_ssl = 1;
		response = http_scrape_ip_for_links_ex(hostname, addr, resource, link_anchor, &h_opts);
	}
	http_enum_opts_destroy(&h_opts);
	return response;
}

int http_scrape_ip_for_links_ex(const char *hostname, const struct in_addr *addr, const char *resource, http_link **link_anchor, http_enum_opts *h_opts) {
	/* link_anchor should either be NULL or an existing list returned by
	 * a previous call to this or a similar function */
	size_t webpage_sz;
	FILE *webpage_f = NULL;
	char *webpage_b = NULL;
	CURL *curl;
	CURLcode curl_res;
	struct curl_slist *headers = NULL;
	char ipstr[INET_ADDRSTRLEN];
	char hoststr[DNS_MAX_FQDN_LENGTH + 7];
	char *target_url = NULL;
	http_link *pvt_link_anchor = *link_anchor; /* used for calculating differences */

	if (pvt_link_anchor) {
		while (pvt_link_anchor->next) {
			pvt_link_anchor = pvt_link_anchor->next;
		}
	}

	inet_ntop(AF_INET, addr, ipstr, sizeof(ipstr));
	target_url = malloc(strlen(ipstr) + strlen(resource) + 9);
	assert(target_url != NULL);
	if (h_opts->use_ssl) {
		snprintf(target_url, (strlen(ipstr) + strlen(resource) + 9), "https://%s%s", ipstr, resource);
	} else {
		snprintf(target_url, (strlen(ipstr) + strlen(resource) + 9), "http://%s%s", ipstr, resource);
	}
	snprintf(hoststr, (DNS_MAX_FQDN_LENGTH + 7), "Host: %s", hostname);

	webpage_f = open_memstream(&webpage_b, &webpage_sz);
	if (webpage_f == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "could not open a memory stream")
		return -1;
	}

	curl = curl_easy_init();
	assert(curl != NULL);
	http_enum_opts_config_curl_easy(h_opts, curl);
	curl_easy_setopt(curl, CURLOPT_URL, target_url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, webpage_f);
	headers = curl_slist_append(headers, hoststr);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_res = curl_easy_perform(curl);
	free(target_url);

	target_url = malloc(strlen(hostname) + strlen(resource) + 9);
	assert(target_url != NULL);
	snprintf(target_url, (strlen(hostname) + strlen(resource) + 9), "http://%s%s", hostname, resource);

	curl_slist_free_all(headers);
	fclose(webpage_f);
	assert(webpage_b != NULL);
	if (curl_res != 0) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "the HTTP request failed")
		free(webpage_b);
		curl_easy_cleanup(curl);
		return -2;
	}

	http_process_request_for_links(curl, target_url, &webpage_b, link_anchor, &pvt_link_anchor, h_opts);

	free(target_url);
	if (webpage_b != NULL) {
		free(webpage_b);
	}
	curl_easy_cleanup(curl);
	return 0;
}

int http_scrape_hosts_for_links_ex(host_manager *c_host_manager, http_link **link_anchor, http_enum_opts *h_opts) {
	char ipstr[INET_ADDRSTRLEN];
	host_iter host_i;
	single_host_info *c_host;
	hostname_iter hostname_i;
	char *hostname;
	unsigned int done = 0;
	unsigned int total = 0;
	int check_http = 1;
	int check_https = 1;

	host_manager_iter_host_init(c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		total++;
		if (c_host->names != NULL) {
			single_host_iter_hostname_init(c_host, &hostname_i);
			while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
				total++;
			}
		}
	}

	host_manager_iter_host_init(c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
		check_http = 1;
		check_https = 1;

		if (HTTP_SHOULD_STOP(h_opts)) {
			break;
		}
		h_opts->use_ssl = 0;
		if (http_scrape_ip_for_links_ex(ipstr, &c_host->ipv4_addr, "/", link_anchor, h_opts) < 0) {
			check_http = 0;
			logging_log("kraken.http_scan", LOGGING_DEBUG, "skipping http scans on host: %s due to a connection error", ipstr);
		}
		if (HTTP_SHOULD_STOP(h_opts)) {
			break;
		}
		h_opts->use_ssl = 1;
		if (http_scrape_ip_for_links_ex(ipstr, &c_host->ipv4_addr, "/", link_anchor, h_opts) < 0) {
			check_https = 0;
			logging_log("kraken.http_scan", LOGGING_DEBUG, "skipping https scans on host: %s due to a connection error", ipstr);
		}
		if (check_http || check_https) {
			single_host_set_status(c_host, KRAKEN_HOST_STATUS_UP);
		}

		done++;
		if (h_opts->progress_update != NULL) {
			h_opts->progress_update(done, total, h_opts->progress_update_data);
		}

		if (c_host->names != NULL) {
			single_host_iter_hostname_init(c_host, &hostname_i);
			while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
				if (check_http || check_https) {
					if (HTTP_SHOULD_STOP(h_opts)) {
						break;
					}
					if (check_http) {
						h_opts->use_ssl = 0;
						if (http_scrape_ip_for_links_ex(hostname, &c_host->ipv4_addr, "/", link_anchor, h_opts) < 0) {
							check_http = 0;
							logging_log("kraken.http_scan", LOGGING_DEBUG, "skipping http scans on host: %s due to a connection error", ipstr);
						}
					}
					if (HTTP_SHOULD_STOP(h_opts)) {
						break;
					}
					if (check_https) {
						h_opts->use_ssl = 1;
						if (http_scrape_ip_for_links_ex(hostname, &c_host->ipv4_addr, "/", link_anchor, h_opts) < 0) {
							check_https = 0;
							logging_log("kraken.http_scan", LOGGING_DEBUG, "skipping https scans on host: %s due to a connection error", ipstr);
						}
					}
				} else {
					logging_log("kraken.http_scan", LOGGING_NOTICE, "skipping alises due to scan error");
				}
				done++;
				if (h_opts->progress_update != NULL) {
					h_opts->progress_update(done, total, h_opts->progress_update_data);
				}
			}
		}
	}
	return 0;
}

int http_add_hosts_from_bing_xml(host_manager *c_host_manager, const char *target_domain, char *tPage) {
	xmlDoc *page;
	xmlNode *root_element = NULL;
	xmlNode *cur_node = NULL;
	xmlNode *ent_node = NULL;
	xmlNode *con_node = NULL;
	xmlNode *url_node = NULL;
	xmlChar *url = NULL;
	UriParserStateA uri_state;
	UriUriA uri;
	size_t len;
	int num_entries = 0;
	char hostname[DNS_MAX_FQDN_LENGTH + 1];

	page = xmlReadMemory(tPage, strlen(tPage), "noname.xml", NULL, (XML_PARSE_RECOVER | XML_PARSE_NOERROR));
	if (page == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "libxml2 failed to parse provided data")
		return -1;
	}
	root_element = xmlDocGetRootElement(page);
	if (root_element == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "could not retrieve the root element of the Bing XML document")
		xmlFreeDoc(page);
		return -1;
	}

	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrncmp(cur_node->name, (xmlChar *)"entry", 5) != 0) {
			continue;
		}
		num_entries++;
		for (ent_node = cur_node->children; ent_node; ent_node = ent_node->next) {
			if (ent_node->type != XML_ELEMENT_NODE) {
				continue;
			}
			if (xmlStrncmp(ent_node->name, (xmlChar *)"content", 7) != 0) {
				continue;
			}
			for (con_node = ent_node->children; con_node; con_node = con_node->next) {
				if (con_node->type != XML_ELEMENT_NODE) {
					continue;
				}
				if (xmlStrncmp(con_node->name, (xmlChar *)"properties", 10) != 0) {
					continue;
				}
				for (url_node = con_node->children; url_node; url_node = url_node->next) {
					if (url_node->type != XML_ELEMENT_NODE) {
						continue;
					}
					if (xmlStrncmp(url_node->name, (xmlChar *)"Url", 3) != 0) {
						continue;
					}
					url = xmlNodeGetContent(url_node);
					if (url == NULL) {
						continue;
					}
					if (xmlStrlen(url) == 0) {
						xmlFree(url);
						continue;
					}
					if (xmlStrncmp(url, (xmlChar *)"http", 4) != 0) {
						xmlFree(url);
						break;
					}
					uri_state.uri = &uri;
					if (uriParseUriA(&uri_state, (char *)url) != URI_SUCCESS) {
						LOGGING_QUICK_ERROR("kraken.http_scan", "uriparser could not parse a URI extracted from the Bing XML")
						uriFreeUriMembersA(&uri);
						xmlFree(url);
						break;
					}
					len = (uri.hostText.afterLast - uri.hostText.first);
					if (len > DNS_MAX_FQDN_LENGTH) {
						LOGGING_QUICK_WARNING("kraken.http_scan", "dropping host name due to length")
						uriFreeUriMembersA(&uri);
						xmlFree(url);
						break;
					}
					memset(hostname, '\0', sizeof(hostname));
					strncpy(hostname, uri.hostText.first, len);
					if (dns_host_in_domain(hostname, (char *)target_domain) == 1) {
						if (host_manager_quick_add_by_name(c_host_manager, hostname) != 0) {
							logging_log("kraken.http_scan", LOGGING_ERROR, "failed to add host name %s from Bing XML", hostname);
						}
					} else {
						logging_log("kraken.http_scan", LOGGING_WARNING, "identified host: %s that is not in the target domain", hostname);
					}
					uriFreeUriMembersA(&uri);
					xmlFree(url);
					break;
				}
			}
		}
	}

	xmlFreeDoc(page);
	return num_entries;
}

int http_search_engine_bing_ex(host_manager *c_host_manager, const char *target_domain, http_enum_opts *h_opts) {
	size_t webpage_sz;
	FILE *webpage_f = NULL;
	char *webpage_b = NULL;
	CURL *curl = NULL;
	CURLcode curl_res;
	char request_url[512];
	long http_code;
	int num_queries = 0;
	int num_entries = 0;
	int num_entries_total = 0;
	int num_timeouts = 0;

	if (h_opts->bing_api_key == NULL) {
		logging_log("kraken.http_scan", LOGGING_WARNING, "bing app id was not set");
		return -1;
	}
	if ((strlen(h_opts->bing_api_key) > HTTP_BING_API_KEY_SZ) || (strlen(target_domain) > DNS_MAX_FQDN_LENGTH)) {
		logging_log("kraken.http_scan", LOGGING_ERROR, "bing app id or domain is too large");
		return -1;
	}

	strncpy(c_host_manager->lw_domain, target_domain, DNS_MAX_FQDN_LENGTH);
	logging_log("kraken.http_scan", LOGGING_INFO, "enumerating domain: %s", target_domain);

	do {
		webpage_f = open_memstream(&webpage_b, &webpage_sz);
		if (webpage_f == NULL) {
			LOGGING_QUICK_ERROR("kraken.http_scan", "could not open a memory stream")
			return -1;
		}
		memset(request_url, '\0', sizeof(request_url));
		snprintf(request_url, sizeof(request_url), "https://api.datamarket.azure.com/Bing/Search/Web?Query=%%27site:%%20%s%%27&$top=%u&$skip=%u&$format=ATOM&Market=%%27en-US%%27", target_domain, HTTP_BING_NUM_RESULTS, (num_queries * HTTP_BING_NUM_RESULTS));

		if (curl != NULL) {
			curl_easy_cleanup(curl);
		}
		curl = curl_easy_init();
		assert(curl != NULL);
		http_enum_opts_config_curl_easy(h_opts, curl);
		curl_easy_setopt(curl, CURLOPT_URL, request_url);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, webpage_f);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERNAME, "");
		curl_easy_setopt(curl, CURLOPT_PASSWORD, h_opts->bing_api_key);

		curl_res = curl_easy_perform(curl);
		fclose(webpage_f);

		assert(webpage_b != NULL);
		if (curl_res != 0) {
			if (curl_res == CURLE_OPERATION_TIMEDOUT) {
				LOGGING_QUICK_WARNING("kraken.http_scan", "the HTTP request timed out")
				num_timeouts++;
				if (num_timeouts == HTTP_MAX_TIMEOUTS) {
					LOGGING_QUICK_ERROR("kraken.http_scan", "the maximum number of permissable timeouts has occured")
					free(webpage_b);
					curl_easy_cleanup(curl);
					return -4;
				}
				num_entries = HTTP_BING_NUM_RESULTS;
				continue;
			} else {
				LOGGING_QUICK_ERROR("kraken.http_scan", "the HTTP request failed")
				free(webpage_b);
				curl_easy_cleanup(curl);
				return -2;
			}
		}
		num_timeouts = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code != 200) {
			free(webpage_b);
			curl_easy_cleanup(curl);
			if (http_code == 401) {
				logging_log("kraken.http_scan", LOGGING_WARNING, "invalid Bing API Key");
				return -3;
			} else {
				logging_log("kraken.http_scan", LOGGING_DEBUG, "web server responded with: %lu", http_code);
			}
			return -2;
		}
		logging_log("kraken.http_scan", LOGGING_DEBUG, "%lu bytes were read from the http response", webpage_sz);
		num_queries++;
		num_entries = http_add_hosts_from_bing_xml(c_host_manager, target_domain, webpage_b);
		num_entries_total += num_entries;

		free(webpage_b);
		if (h_opts->progress_update != NULL) {
			h_opts->progress_update((((num_queries - 1) * HTTP_BING_NUM_RESULTS) + num_entries), HTTP_BING_MAX_RESULTS, h_opts->progress_update_data);
		}
	} while ((num_entries == HTTP_BING_NUM_RESULTS) && (num_entries_total < HTTP_BING_MAX_RESULTS) && !(HTTP_SHOULD_STOP(h_opts)));

	if (h_opts->progress_update != NULL) {
		h_opts->progress_update(HTTP_BING_MAX_RESULTS, HTTP_BING_MAX_RESULTS, h_opts->progress_update_data);
	}
	logging_log("kraken.http_scan", LOGGING_INFO, "bing enumeration complete, used %i queries and received %i results", num_queries, num_entries_total);
	return (((num_queries - 1) * HTTP_BING_NUM_RESULTS) + num_entries);
}
