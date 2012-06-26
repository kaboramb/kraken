#include <stdlib.h>
#include <string.h>
#include "kraken_options.h"

void kraken_opts_init(kraken_opts *k_opts) {
	memset(k_opts, '\0', sizeof(struct kraken_opts));
	k_opts->dns_wordlist = NULL;
	k_opts->bing_api_key = NULL;
	return;
}

void kraken_opts_destroy(kraken_opts *k_opts) {
	if (k_opts->dns_wordlist != NULL) {
		free(k_opts->dns_wordlist);
		k_opts->dns_wordlist = NULL;
	}
	if (k_opts->bing_api_key != NULL) {
		free(k_opts->bing_api_key);
		k_opts->bing_api_key = NULL;
	}
	return;
}

int kraken_opts_set(kraken_opts *k_opts, int type, void *value) {
	void *new_value;
	switch (type) {
		case KRAKEN_OPT_DNS_WORDLIST:
			if (k_opts->dns_wordlist != NULL) {
				free(k_opts->dns_wordlist);
			}
			new_value = malloc(strlen(value) + 1);
			if (new_value == NULL) {
				return -2;
			}
			strncpy(new_value, value, strlen(value));
			k_opts->dns_wordlist = (char *)new_value;
			k_opts->dns_wordlist[strlen(value)] = '\0';
			break;
		case KRAKEN_OPT_BING_API_KEY:
			if (k_opts->bing_api_key != NULL) {
				free(k_opts->bing_api_key);
			}
			new_value = malloc(strlen(value) + 1);
			if (new_value == NULL) {
				return -2;
			}
			strncpy(new_value, value, strlen(value));
			k_opts->bing_api_key = (char *)new_value;
			k_opts->bing_api_key[strlen(value)] = '\0';
			break;
		default:
			return -1;
			break;
	}
	return 0;
}
