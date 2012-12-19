// whois_lookup.h
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

#ifndef _KRAKEN_WHOIS_LOOKUP_H
#define _KRAKEN_WHOIS_LOOKUP_H

#define WHOIS_PORT 43
#define WHOIS_SZ_DATA 63
#define WHOIS_SZ_DATA_S 31
#define WHOIS_SZ_REQ 128
#define WHOIS_SZ_RESP 4096
#define WHOIS_TIMEOUT_SEC 0
#define WHOIS_TIMEOUT_USEC 500000	/* half second is 500,000 usec */

#define WHOIS_REQ_TYPE_IP 1
#define WHOIS_REQ_TYPE_HOST 2

#define WHOIS_SRV_ARIN 1
#define WHOIS_SRV_RIPE 2

#define WHOIS_SRV_HOST_ARIN "whois.arin.net"
#define WHOIS_SRV_HOST_RIPE "whois.ripe.net"

/* this is a duplicate */
#define DNS_MAX_FQDN_LENGTH 255

#ifndef _KRAKEN_WHOIS_LOOKUP_H_SKIP_TYPEDEFS
#define _KRAKEN_WHOIS_LOOKUP_H_SKIP_TYPEDEFS
typedef struct whois_record {
	char cidr_s[WHOIS_SZ_DATA_S + 1];
	char netname[WHOIS_SZ_DATA + 1];
	char description[WHOIS_SZ_DATA + 1];
	
	char orgname[WHOIS_SZ_DATA + 1];
	char regdate_s[WHOIS_SZ_DATA_S + 1];
	char updated_s[WHOIS_SZ_DATA_S + 1];
} whois_record;
typedef struct whois_record whois_response;
#endif

#ifndef _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS
#define _KRAKEN_WHOIS_LOOKUP_H_SKIP_FUNCDEFS
int whois_lookup_ip(struct in_addr *ip, whois_response *who_resp);
int whois_raw_lookup(int req_type, int target_server, char *request, char *response);
int whois_fill_host_manager(host_manager *c_host_manager);
char *whois_get_best_name(whois_record *who_data);

#endif

#endif
