#ifndef _KRAKEN_EXPORT_H
#define _KRAKEN_EXPORT_H

#include "kraken.h"

typedef struct export_csv_opts {
	/* everything except delimiter is boolean */
	char primary_delimiter[4];
	char secondary_delimiter[4];
	char new_line[4];
	char show_fields;

	char filter_host_is_up;

	char host_ipv4_addr;
	char host_names;

	char whois_cidr;
	char whois_netname;
	char whois_orgname;
} export_csv_opts;

void export_csv_opts_init(export_csv_opts *e_opts);
void export_csv_opts_destroy(export_csv_opts *e_opts);

int export_host_manager_to_csv_ex(host_manager *c_host_manager, const char *dest_file, export_csv_opts *e_opts);
int export_host_manager_to_xml(host_manager *c_host_manager, const char *dest_file);
int import_host_manager_from_xml(host_manager *c_host_manager, const char *source_file);

#endif
