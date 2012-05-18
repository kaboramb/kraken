#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <uriparser/Uri.h>
#include "hosts.h"
#include "http_scan.h"
#include "logging.h"

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
					/* if we wanted to continue to crawl additional pages on the same server, the
					 * code would go here before we run strncasecmp() on the scheme */
					if (strncasecmp((char *)value, "http", 4) == 0) { /* matches http and https */
						uri_state.uri = &uri;
						if (uriParseUriA(&uri_state, (char *)value) != URI_SUCCESS) {
							LOGGING_QUICK_ERROR("kraken.http_scan", "uriparser could not parse a URI extracted from the HTML")
							uriFreeUriMembersA(&uri);
							continue;
						}
						if (anchor_link != NULL) {
							for (current_link = anchor_link->next; current_link; current_link = current_link->next) {
								if (strncmp(current_link->scheme, uri.scheme.first, HTTP_SCHEME_SZ) == 0) {
									if (strncmp(current_link->hostname, uri.hostText.first, DNS_MAX_FQDN_LENGTH) == 0) {
										if ((strlen(uri.pathHead->text.first) > 1) && (strncmp(current_link->path, uri.pathHead->text.first, HTTP_RESOURCE_SZ) == 0)) {
											continue; /* got a duplicate link, ignore it */
										}
									}
								}
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
						if (strlen(uri.pathHead->text.first) > 1) {
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
	http_link *link_current = NULL;

	page = xmlReadMemory(tPage, strlen(tPage), "noname.xml", NULL, (XML_PARSE_RECOVER | XML_PARSE_NOERROR));
	if (page == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "libxml2 failed to parse provided data")
		return 1;
	}
	root_element = xmlDocGetRootElement(page);
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

int http_scrape_for_links(char *target_url, http_link **link_anchor) {
	char logStr[LOGGING_STR_LEN + 1];
	size_t webpage_sz;
	FILE *webpage_f = NULL;
	char *webpage_b = NULL;
	CURL *curl;
	CURLcode curl_res;
	long http_code;
	char *content_type;
	http_link *link_current = NULL;

	webpage_f = open_memstream(&webpage_b, &webpage_sz);
	if (webpage_f == NULL) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "could not open a memory stream")
		return 1;
	}

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, target_url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, webpage_f);
	curl_res = curl_easy_perform(curl);
	fclose(webpage_f);
	if (curl_res != 0) {
		LOGGING_QUICK_ERROR("kraken.http_scan", "the HTTP request failed")
		free(webpage_b);
		curl_easy_cleanup(curl);
		return 2;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	snprintf(logStr, sizeof(logStr), "web server responded with: %lu", http_code);
	LOGGING_QUICK_DEBUG("kraken.http_scan", logStr)

	snprintf(logStr, sizeof(logStr), "%lu bytes were read from the page", webpage_sz);
	LOGGING_QUICK_DEBUG("kraken.http_scan", logStr)

	curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
	if (content_type == NULL) {
		LOGGING_QUICK_WARNING("kraken.http_scan", "the content type was not provided in the servers response")
		free(webpage_b);
		return 3;
	}
	if (strstr(content_type, "text/html")) {
		http_get_links_from_html(webpage_b, &link_current);
		*link_anchor = link_current;
	}
	free(webpage_b);
	return 0;
}
