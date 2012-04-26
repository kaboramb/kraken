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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ares.h>
#include <argp.h>
#include "hosts.h"
#include "host_manager.h"
#include "dns_enum.h"
#include "whois_lookup.h"

const char *argp_program_version = "kraken 0.1";
const char *argp_program_bug_address = "<smcintyre@securestate.net>";
static char doc[] = "Enumerate targets.";
static char args_doc[] = "TARGET_DOMAIN";

static struct argp_option options[] = {
	{ 0 }
};

struct arguments {
	char *target_domains[1];
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	
	switch (key) {
		case ARGP_KEY_ARG:
			if (state->arg_num >= 1)
			/* Too many arguments. */
			argp_usage (state);
			arguments->target_domains[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 1) {
				/* Not enough arguments. */
				argp_usage (state);
			}
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
	unsigned int current_host_i;
	unsigned int current_who_i;
	single_host_info current_host;
	whois_record current_who_rec;
	char ipstr[INET_ADDRSTRLEN];
	
	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	if (init_host_manager(&c_host_manager) != 0) {
		printf("ERROR: could not initialize the host manager, it is likely that there is not enough memory\n");
		return 0;
	}
	dns_enumerate_domain(arguments.target_domains[0], &c_host_manager);
	
	printf("\n");
	for (current_host_i = 0; current_host_i < c_host_manager.known_hosts; current_host_i++) {
		current_host = c_host_manager.hosts[current_host_i];
		inet_ntop(AF_INET, &current_host.ipv4_addr, ipstr, sizeof(ipstr));
		printf("%s %s\n", current_host.hostname, ipstr);
	}
	printf("\n");
	whois_fill_host_manager(&c_host_manager);
	
	printf("\n");
	printf("Summary: %u hosts found on %u networks\n", c_host_manager.known_hosts, c_host_manager.known_whois_records);
	printf("Networks found:\n");
	for (current_who_i = 0; current_who_i < c_host_manager.known_whois_records; current_who_i++) {
		current_who_rec = c_host_manager.whois_records[current_who_i];
		printf("\t%s\n", current_who_rec.cidr_s);
	}
	
	destroy_host_manager(&c_host_manager);
	return 0;
}
