// network_addr.h
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

#ifndef _KRAKEN_NETWORK_ADDR_H
#define _KRAKEN_NETWORK_ADDR_H

#include <arpa/inet.h>

#define NETADDR_CIDR_ADDRSTRLEN 24

typedef struct network_addr {
	struct in_addr network;
	struct in_addr subnetmask;
} network_addr;

int netaddr_cidr_str_to_nwk(struct network_addr *network, char *netstr);
int netaddr_ip_in_nwk(struct network_addr *network, struct in_addr *ip);
int netaddr_range_str_to_nwk(struct network_addr *network, char *iplow, char *iphigh);
int netaddr_nwk_to_cidr_str(struct network_addr *network, char *netstr, size_t sz_netstr);
unsigned int netaddr_ips_in_nwk(struct network_addr *network);
int netaddr_ip_is_rfc1918(struct in_addr *ip);
int netaddr_ip_is_rfc3330(struct in_addr *ip);

#endif
