// kraken.c
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <argp.h>
#ifndef WITHOUT_LOG4C
#include <log4c.h>
#endif

#include "plugins.h"
#include "host_manager.h"
#include "export.h"
#include "gui_model.h"
#include "gui_main.h"
#include "whois_lookup.h"

char kraken_version_string[128];
const char *argp_program_version = kraken_version_string;
const char *argp_program_bug_address = "<smcintyre@securestate.net>";
static char doc[] = "Enumerate targets.";
static char args_doc[] = "";

static struct argp_option options[] = {
	{ "loglvl",	'L', "LOG_LEVEL", 0, "Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)" },
	{ "open",	'o', "OPEN_FILE", 0, "Restore information from a previous session" },
	{ 0 }
};

struct arguments {
	char *restore_file;
	int loglvl;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;

	switch (key) {
		case 'L':
			if (strncasecmp(arg, "FATAL", 5) == 0) {
				arguments->loglvl = LOGGING_FATAL;
			} else if (strncasecmp(arg, "ALERT", 5) == 0) {
				arguments->loglvl = LOGGING_ALERT;
			} else if (strncasecmp(arg, "CRITICAL", 8) == 0) {
				arguments->loglvl = LOGGING_CRITICAL;
			} else if (arg[0] == 'C') {
				arguments->loglvl = LOGGING_CRITICAL;
			} else if (strncasecmp(arg, "ERROR", 5) == 0) {
				arguments->loglvl = LOGGING_ERROR;
			} else if (arg[0] == 'E') {
				arguments->loglvl = LOGGING_ERROR;
			} else if (strncasecmp(arg, "WARNING", 7) == 0) {
				arguments->loglvl = LOGGING_WARNING;
			} else if (arg[0] == 'W') {
				arguments->loglvl = LOGGING_WARNING;
			} else if (strncasecmp(arg, "NOTICE", 6) == 0) {
				arguments->loglvl = LOGGING_NOTICE;
			} else if (strncasecmp(arg, "INFO", 4) == 0) {
				arguments->loglvl = LOGGING_INFO;
			} else if (arg[0] == 'I') {
				arguments->loglvl = LOGGING_INFO;
			} else if (strncasecmp(arg, "DEBUG", 5) == 0) {
				arguments->loglvl = LOGGING_DEBUG;
			} else if (arg[0] == 'D') {
				arguments->loglvl = LOGGING_DEBUG;
			} else if (strncasecmp(arg, "TRACE", 5) == 0) {
				arguments->loglvl = LOGGING_TRACE;
			} else {
				 argp_usage(state);
			}
			break;
		case 'o':
			arguments->restore_file = arg;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 1)
			/* Too many arguments. */
			argp_usage(state);
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv) {
	struct arguments arguments;
	curl_version_info_data *curl_info;
	kraken_opts k_opts;
	host_manager c_host_manager;
	main_gui_data m_data;
	host_iter host_i;
	single_host_info *c_host;
	whois_iter whois_i;
	whois_record *c_who_rcd;
	char ipstr[INET_ADDRSTRLEN];
#ifndef WITHOUT_LOG4C
	log4c_category_t* logcat = NULL;
#endif

	/* set argument defaults */
	arguments.restore_file = NULL;
#ifndef WITHOUT_LOG4C
	arguments.loglvl = LOG4C_PRIORITY_ERROR;
#else
	arguments.loglvl = 0;
#endif

	/* patch the version string from kraken.h */
	if (strlen(KRAKEN_REVISION_STRING)) {
		snprintf(kraken_version_string, sizeof(kraken_version_string), "kraken v:%u.%u rev:%s", KRAKEN_VERSION_MAJOR, KRAKEN_VERSION_MINOR, KRAKEN_REVISION_STRING);
	} else {
		snprintf(kraken_version_string, sizeof(kraken_version_string), "kraken v:%u.%u", KRAKEN_VERSION_MAJOR, KRAKEN_VERSION_MINOR);
	}
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	if (log4c_init()) {
		fprintf(stdout, "Could not initialize the logging subsystem.\n");
		return 1;
	}

#ifndef WITHOUT_LOG4C
	log4c_init();
	logcat = log4c_category_get("kraken");
	log4c_category_set_priority(logcat, arguments.loglvl);
	log4c_category_set_appender(logcat, log4c_appender_get("stdout"));
#endif

	curl_info = curl_version_info(CURLVERSION_NOW);
	if (!(curl_info->features & CURL_VERSION_ASYNCHDNS)) {
		LOGGING_QUICK_WARNING("kraken", "libcurl was not compiled with asynchronous dns support")
	}

	if (host_manager_init(&c_host_manager) != 0) {
		LOGGING_QUICK_FATAL("kraken", "could not initialize the host manager, it is likely that there is not enough memory")
		return 1;
	}

	if (kraken_opts_init_from_config(&k_opts) != 0) {
		LOGGING_QUICK_WARNING("kraken", "an error occured while loading the config file, using default options")
		kraken_opts_init(&k_opts);
	}

	if (arguments.restore_file != NULL) {
		if (access(arguments.restore_file, R_OK) == -1) {
			logging_log("kraken", LOGGING_ERROR, "could not read file: %s", arguments.restore_file);
		} else {
			if (import_host_manager_from_xml(&c_host_manager, arguments.restore_file) != 0) {
				logging_log("kraken", LOGGING_ERROR, "could not import file: %s", arguments.restore_file);
			} else if (access(arguments.restore_file, W_OK) == 0) {
				c_host_manager.save_file_path = malloc(strlen(arguments.restore_file) + 1);
				if (c_host_manager.save_file_path != NULL) {
					strncpy(c_host_manager.save_file_path, arguments.restore_file, sizeof(c_host_manager.save_file_path));
				}
			}
		}
	}

	gui_main_data_init(&m_data, &k_opts, &c_host_manager);

	if (plugins_init(argv[0], &k_opts, &c_host_manager, &m_data) < 0) {
		kraken_opts_destroy(&k_opts);
		host_manager_destroy(&c_host_manager);
#ifndef WITHOUT_LOG4C
		log4c_fini();
#endif
		return 1;
	}
	LOGGING_QUICK_WARNING("kraken", "releasing the kraken")

	gui_show_main_window(&m_data);
	m_data.gui_is_active = 0;
	kraken_thread_mutex_lock(&m_data.plugin_mutex);

	if (c_host_manager.known_hosts) {
		printf("\n");
		printf("Summary: %u hosts found on %u networks\n", c_host_manager.known_hosts, c_host_manager.known_whois_records);
		printf("Hosts found:\n");
		host_manager_iter_host_init(&c_host_manager, &host_i);
		while (host_manager_iter_host_next(&c_host_manager, &host_i, &c_host)) {
			inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
			printf("\t%s\n", ipstr);
		}
		printf("\n");
		printf("Networks found:\n");
		host_manager_iter_whois_init(&c_host_manager, &whois_i);
		while (host_manager_iter_whois_next(&c_host_manager, &whois_i, &c_who_rcd)) {
			printf("\t%s\n", (char *)&c_who_rcd->cidr_s);
		}
	}

	LOGGING_QUICK_WARNING("kraken", "good luck and good hunting")
	plugins_destroy();
	kraken_thread_mutex_unlock(&m_data.plugin_mutex);
	gui_main_data_destroy(&m_data);
	kraken_opts_destroy(&k_opts);
	host_manager_destroy(&c_host_manager);
#ifndef WITHOUT_LOG4C
	log4c_fini();
#endif
	return 0;
}
