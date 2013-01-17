// kraken.h
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

#ifndef _KRAKEN_KRAKEN_H
#define _KRAKEN_KRAKEN_H

#include <Python.h>
#include <arpa/inet.h>
#include <assert.h>

#ifndef _KRAKEN_WHOIS_LOOKUP_H					/* if it hasn't been included yet, include it */
#define _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS	/* but skil the function definitions at the end */
#include "whois_lookup.h"
#undef _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS		/* don't skip the function definitions next time */
#undef _KRAKEN_WHOIS_LOOKUP_H 					/* next time do include it again because we'll need the function definitions */

#include "network_addr.h"

#include "kraken_thread.h"
#include "kraken_options.h"
#include "logging.h"

extern char kraken_version_string[128];
#define KRAKEN_VERSION_MAJOR 0
#define KRAKEN_VERSION_MINOR 1

#ifndef KRAKEN_REVISION_STRING
#define KRAKEN_REVISION_STRING ""
#endif

#define MAX_LINE 512

#define DNS_MAX_FQDN_LENGTH 255 /* also defined in dns_enum.h */
#define KRAKEN_HOST_STATUS_UP 1
#define KRAKEN_HOST_STATUS_UNKNOWN 0
#define KRAKEN_HOST_STATUS_DOWN -1
#define KRAKEN_HOST_STATUS_IS_VALID(i) ((-2 < i) && (i < 2))

#define KRAKEN_ACTION_PAUSE -1
#define KRAKEN_ACTION_STOP 0
#define KRAKEN_ACTION_RUN 1

#define KRAKEN_ITER_STATUS_NEW 1
#define KRAKEN_ITER_STATUS_USED 0

typedef struct kraken_basic_iter {
	int status;
	unsigned int position;
} kraken_basic_iter;

typedef struct single_host_info {
	struct in_addr ipv4_addr;
	struct whois_record *whois_data;
	char (*names)[DNS_MAX_FQDN_LENGTH + 1];
	unsigned int n_names;
	char status;
	char os;
} single_host_info;

typedef struct host_manager {
	kraken_thread_mutex k_mutex;
	char lw_domain[DNS_MAX_FQDN_LENGTH + 1];	/* last working domain, so we can keep track in the GUI if we want */
	char *save_file_path;
	unsigned int known_hosts;
	unsigned int current_capacity;
	unsigned int known_whois_records;
	unsigned int current_whois_record_capacity;
	single_host_info *hosts;
	whois_record *whois_records;
} host_manager;

#endif

#endif
