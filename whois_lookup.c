#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "hosts.h"
#include "whois_lookup.h"
#include "host_manager.h"
#include "network_addr.h"

int whois_lookup_ip(struct in_addr *ip, whois_response *who_resp) {
	char raw_resp[WHOIS_SZ_RESP];
	int szResp = 0;
	char ipstr[INET6_ADDRSTRLEN];
	int retVal = 0;
	char *pCur = NULL;
	int szData = 0;
	
	inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr));
	
	memset(who_resp, '\0', sizeof(whois_response));
	retVal = whois_raw_lookup(WHOIS_REQ_TYPE_IP, ipstr, raw_resp);
	if (retVal != 0) {
		return retVal;
	}
	
	szResp = strlen(raw_resp);
	pCur = raw_resp;
	while (pCur < (raw_resp + szResp)) {
		szData = 0;
		pCur += 1;		/* advance the cursor once to skip the newline */
		if ((*pCur == '#') || (*pCur == '\n')) {
			continue;	/* skip comments */
		}
		if (strncasecmp(pCur, "cidr: ", 6) == 0) {
			pCur += 6;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->cidr_s, pCur, szData);
			pCur += szData;
		} else if (strncasecmp(pCur, "netname: ", 9) == 0) {
			pCur += 9;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->netname, pCur, szData);
			pCur += szData;
		} else if (strncasecmp(pCur, "comment: ", 9) == 0) {
			pCur += 9;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->comment, pCur, szData);
			pCur += szData;
		} else if (strncasecmp(pCur, "orgname: ", 9) == 0) {
			pCur += 9;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->orgname, pCur, szData);
			pCur += szData;
		} else if (strncasecmp(pCur, "regdate: ", 9) == 0) {
			pCur += 9;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->regdate_s, pCur, szData);
			pCur += szData;
		} else if (strncasecmp(pCur, "updated: ", 9) == 0) {
			pCur += 9;
			while ((*pCur == ' ') && (pCur < (raw_resp + szResp))) {
				pCur += 1;
			}
			while ((*(pCur + szData) != '\n') && (pCur < (raw_resp + szResp))) {
				szData += 1;
			}
			strncpy(who_resp->updated_s, pCur, szData);
			pCur += szData;
		} else {
			pCur = strchr(pCur, '\n');
			if (pCur == NULL) {
				break;
			}
		}
	}
	return 0;
}

int whois_raw_lookup(int req_type, char *request, char *response) {
	/*
	 * Returns 0 on Success
	 * Returns 1 on Error
	 */
	int sock;
	int szReq = 0;
	int szResp = 0;
	int tmpSzResp = 0;
	char reqBuffer[WHOIS_SZ_REQ];
	struct sockaddr_in dest_addr;
	fd_set fdRead;
	struct timeval timeout;
	
	
	memset(reqBuffer,  '\0', sizeof(WHOIS_SZ_REQ));
	memset(response,   '\0', sizeof(WHOIS_SZ_RESP));
	memset(&dest_addr, '\0', sizeof(dest_addr));
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		printf("ERROR: could not allocate a socket\n");
		return 1;
	}
	
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(WHOIS_PORT);

	if (req_type == WHOIS_REQ_TYPE_IP) {
		inet_pton(AF_INET, WHOIS_SRV_IP, &(dest_addr.sin_addr));
		snprintf(reqBuffer, sizeof(reqBuffer), "n + %s\r\n", request);
	} else if (req_type == WHOIS_REQ_TYPE_HOST) {
		inet_pton(AF_INET, WHOIS_SRV_HOST, &(dest_addr.sin_addr));
		snprintf(reqBuffer, sizeof(reqBuffer), "%s\r\n", request);
	} else {
		printf("ERROR: could not determine WHOIS request type\n");
		return 2;
	}
	szReq = strlen(reqBuffer);
	
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
		printf("ERROR: could not connect to WHOIS server\n");
		return 3;
	}
	
	if (send(sock, reqBuffer, szReq, 0) != szReq) {
		printf("ERROR: failed to send the expected amount of data");
		return 4;
	}
	
	FD_ZERO(&fdRead);
	FD_SET(sock, &fdRead);
	timeout.tv_sec = WHOIS_TIMEOUT_SEC;
	timeout.tv_usec = WHOIS_TIMEOUT_USEC;
	
	while (szResp < WHOIS_SZ_RESP) {
		select(sock + 1, &fdRead, NULL, NULL, &timeout);
		if (FD_ISSET(sock, &fdRead) == 0) {
			if (szResp > 0) {
				return 0;
			} else {
				return 5;
			}
		}
		tmpSzResp = recv(sock, &response[szResp], (WHOIS_SZ_RESP - szResp), 0);
		szResp += tmpSzResp;
		if ((tmpSzResp == 0) && (szResp > 0)) {
			break;
		} else if ((tmpSzResp == 0) && (szResp == 0)) {
			return 5;
		}
	}
	return 0;
}

int whois_fill_host_manager(host_manager *c_host_manager) {
	/* TODO: this function needs to be written and used */
	unsigned int current_host_i;
	unsigned int current_who_i;
	int host_has_whois;
	single_host_info *current_host;
	whois_record tmp_who_resp;
	whois_record *cur_who_resp;
	network_info network;
	int ret_val = 0;
	char ipstr[INET6_ADDRSTRLEN];
	
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		current_host = &c_host_manager->hosts[current_host_i];
		inet_ntop(AF_INET, &current_host->ipv4_addr, ipstr, sizeof(ipstr));
		host_has_whois = 0;
		for (current_who_i = 0; current_who_i < c_host_manager->known_whois_records; current_who_i ++) {
			cur_who_resp = &c_host_manager->whois_records[current_who_i];
			ret_val = netaddr_cidr_str_to_nwk(cur_who_resp->cidr_s, &network);
			if (ret_val == 0) {
				if (netaddr_ip_in_nwk(&current_host->ipv4_addr, &network) == 1) {
					host_has_whois = 1;
					break;
				}
			} else {
				printf("ERROR: could not parse cidr address: %s\n", (char *)&cur_who_resp->cidr_s);
			}
			
		}
		if (host_has_whois == 1) {
#ifdef DEBUG
			printf("DEBUG: skipping host %s because whois record is already present\n", ipstr);
#endif
			continue;
		}
		ret_val = whois_lookup_ip(&current_host->ipv4_addr, &tmp_who_resp);
		if (ret_val == 0) {
			printf("INFO: got whois record for %s\n", ipstr);
			host_manager_add_whois(c_host_manager, &tmp_who_resp);
		}
	}
	return 0;
}
