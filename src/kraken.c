// kraken.c
//
// Copyright 2012 Spencer McIntyre <smcintyre@securestate.net>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.
//
//

#include "kraken.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>
#include <argp.h>
#ifndef WITHOUT_LOG4C
#include <log4c.h>
#endif

#include "plugins.h"
#include "host_manager.h"
#include "export.h"
#include "gui_main.h"
#include "whois_lookup.h"

const char *argp_program_version = "kraken 0.1";
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
	host_manager c_host_manager;
	kraken_opts k_opts;
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

	if (plugins_init(argv[0], &k_opts, &c_host_manager) < 0) {
		kraken_opts_destroy(&k_opts);
		host_manager_destroy(&c_host_manager);
#ifndef WITHOUT_LOG4C
		log4c_fini();
#endif
		return 1;
	}
	LOGGING_QUICK_WARNING("kraken", "releasing the kraken")

	gui_show_main_window(&k_opts, &c_host_manager);

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
			printf("\t%s\n", &c_who_rcd->cidr_s);
		}
	}

	LOGGING_QUICK_WARNING("kraken", "good luck and good hunting")
	plugins_destroy();
	kraken_opts_destroy(&k_opts);
	host_manager_destroy(&c_host_manager);
#ifndef WITHOUT_LOG4C
	log4c_fini();
#endif
	return 0;
}
