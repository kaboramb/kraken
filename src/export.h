// export.h
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
