#ifndef _KRAKEN_KRAKEN_OPTIONS_H
#define _KRAKEN_KRAKEN_OPTIONS_H

#define KRAKEN_OPT_DNS_WORDLIST 1
#define KRAKEN_OPT_BING_API_KEY 2

#define KRAKEN_CONF_DIR ".kraken"
#define KRAKEN_CONF_DIR_ENV_VAR "HOME"
#define KRAKEN_CONF_DIR_SEP "/"
#define KRAKEN_CONF_FILE "kraken.conf"

typedef struct kraken_opts {
	char *dns_wordlist;
	char *bing_api_key;
} kraken_opts;

void kraken_opts_init(kraken_opts *k_opts);
int kraken_opts_init_from_config(kraken_opts *k_opts);
void kraken_opts_destroy(kraken_opts *k_opts);
int kraken_opts_get(kraken_opts *k_opts, int type, void *value);
int kraken_opts_set(kraken_opts *k_opts, int type, void *value);

int kraken_conf_get_data_directory_path(char *path, size_t pathsz);
int kraken_conf_get_config_file_path(char *path, size_t pathsz);
int kraken_conf_load_config(const char *conf_path, kraken_opts *k_opts);
int kraken_conf_save_config(const char *conf_path, kraken_opts *k_opts);

#endif
