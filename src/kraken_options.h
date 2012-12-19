// kraken_options.h
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
