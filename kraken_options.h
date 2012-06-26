#ifndef _KRAKEN_SETTINGS_H
#define _KRAKEN_SETTINGS_H

#define KRAKEN_OPT_DNS_WORDLIST 1
#define KRAKEN_OPT_BING_API_KEY 2

typedef struct kraken_opts {
	char *dns_wordlist;
	char *bing_api_key;
} kraken_opts;

void kraken_opts_init(kraken_opts *k_opts);
void kraken_opts_destroy(kraken_opts *k_opts);
int kraken_opts_set(kraken_opts *k_opts, int type, void *value);

#endif
