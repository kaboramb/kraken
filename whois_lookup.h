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

#define WHOIS_SRV_IP "199.212.0.48" /* TODO: make this the name whois.arin.net not the IP */
#define WHOIS_SRV_HOST "199.212.0.48" /*TODO: fix this to a working server */

/* this is a duplicate */
#define DNS_MAX_FQDN_LENGTH 255

typedef struct whois_response {
	char cidr_s[WHOIS_SZ_DATA_S + 1];
	char netname[WHOIS_SZ_DATA + 1];
	char comment[WHOIS_SZ_DATA + 1];
	
	char orgname[WHOIS_SZ_DATA + 1];
	char regdate_s[WHOIS_SZ_DATA_S + 1];
	char updated_s[WHOIS_SZ_DATA_S + 1];
} whois_response;

int whois_lookup_ip(struct in_addr *ip, struct whois_response *who_resp);
int whois_raw_lookup(int req_type, char *request, char *response);

#endif
