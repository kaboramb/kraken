#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_addr.h"

int netaddr_ip_in_nwk(struct network_addr *network, struct in_addr *ip) {
	/*
	 * Returns 0 on "No the network described by in_addr is not in network"
	 * Returns 1 on "Yes the network described by in_addr is in network"
	 */
	if ((ip->s_addr & network->subnetmask.s_addr) == (network->network.s_addr)) {
		 return 1;
	}
	return 0;
}

int netaddr_cidr_str_to_nwk(struct network_addr *network, char *o_netstr) {
	/*
	 * Returns 1 on success
	 * Returns 0 on failure (due to unparseable address)
	 *
	 * netstr is a cidr range such as "192.168.1.1/25" network is a pointer to a network_addr structure
	 * In the event that the IP is not a member of the network such as above, the network (in this case 192.168.1.0)
	 * is placed into the network member of the network_addr structure
	 */
	char *pCur = NULL;
	int bits = 0;
	char netstr[NETADDR_CIDR_ADDRSTRLEN]; /* nice round number, leaves extra space */

	memset(netstr, '\0', NETADDR_CIDR_ADDRSTRLEN);
	if (strlen(o_netstr) >= NETADDR_CIDR_ADDRSTRLEN) {
		return 0;
	}
	strncpy(netstr, o_netstr, (NETADDR_CIDR_ADDRSTRLEN - 1));
	memset(network, '\0', sizeof(struct network_addr));

	pCur = strchr(netstr, '/');
	if (pCur == NULL) {
		return 0;
	}
	*pCur = '\0';
	pCur += 1;
	if (strlen(pCur) > 2) {
		return 0;
	}

	if (inet_pton(AF_INET, netstr, &network->network) != 1) {
		return 0;
	}
	bits = atoi(pCur);
	if (bits > 32) {
		return 0;
	}

	switch (bits) {
		case 0:  { network->subnetmask.s_addr = 0x00000000; break; }
		case 1:  { network->subnetmask.s_addr = 0x00000080; break; }
		case 2:  { network->subnetmask.s_addr = 0x000000c0; break; }
		case 3:  { network->subnetmask.s_addr = 0x000000e0; break; }
		case 4:  { network->subnetmask.s_addr = 0x000000f0; break; }
		case 5:  { network->subnetmask.s_addr = 0x000000f8; break; }
		case 6:  { network->subnetmask.s_addr = 0x000000fc; break; }
		case 7:  { network->subnetmask.s_addr = 0x000000fe; break; }
		case 8:  { network->subnetmask.s_addr = 0x000000ff; break; }
		case 9:  { network->subnetmask.s_addr = 0x000080ff; break; }
		case 10: { network->subnetmask.s_addr = 0x0000c0ff; break; }
		case 11: { network->subnetmask.s_addr = 0x0000e0ff; break; }
		case 12: { network->subnetmask.s_addr = 0x0000f0ff; break; }
		case 13: { network->subnetmask.s_addr = 0x0000f8ff; break; }
		case 14: { network->subnetmask.s_addr = 0x0000fcff; break; }
		case 15: { network->subnetmask.s_addr = 0x0000feff; break; }
		case 16: { network->subnetmask.s_addr = 0x0000ffff; break; }
		case 17: { network->subnetmask.s_addr = 0x0080ffff; break; }
		case 18: { network->subnetmask.s_addr = 0x00c0ffff; break; }
		case 19: { network->subnetmask.s_addr = 0x00e0ffff; break; }
		case 20: { network->subnetmask.s_addr = 0x00f0ffff; break; }
		case 21: { network->subnetmask.s_addr = 0x00f8ffff; break; }
		case 22: { network->subnetmask.s_addr = 0x00fcffff; break; }
		case 23: { network->subnetmask.s_addr = 0x00feffff; break; }
		case 24: { network->subnetmask.s_addr = 0x00ffffff; break; }
		case 25: { network->subnetmask.s_addr = 0x80ffffff; break; }
		case 26: { network->subnetmask.s_addr = 0xc0ffffff; break; }
		case 27: { network->subnetmask.s_addr = 0xe0ffffff; break; }
		case 28: { network->subnetmask.s_addr = 0xf0ffffff; break; }
		case 29: { network->subnetmask.s_addr = 0xf8ffffff; break; }
		case 30: { network->subnetmask.s_addr = 0xfcffffff; break; }
		case 31: { network->subnetmask.s_addr = 0xfeffffff; break; }
		case 32: { network->subnetmask.s_addr = 0xffffffff; break; }
	}
	network->network.s_addr = (network->network.s_addr & network->subnetmask.s_addr);
	return 1;
}

int netaddr_range_str_to_nwk(struct network_addr *network, char *iplow, char *iphigh) {
	/*
	 * Returns 1 on success
	 * Returns 0 on failure (due to unparseable address)
	 */
	struct in_addr iplow_s;
	struct in_addr iphigh_s;

	memset(network, '\0', sizeof(struct network_addr));

	if (inet_pton(AF_INET, iplow, &iplow_s) != 1) {
		return 0;
	}
	if (inet_pton(AF_INET, iphigh, &iphigh_s) != 1) {
		return 0;
	}

	network->network.s_addr = (iplow_s.s_addr & iphigh_s.s_addr);
	network->subnetmask.s_addr = (0xffffffff ^ (iphigh_s.s_addr ^ (network->network.s_addr)));
	return 1;
}

int netaddr_nwk_to_cidr_str(struct network_addr *network, char *netstr, size_t sz_netstr) {
	char mask[4];

	memset(mask, '\0', sizeof(mask));
	memset(netstr, '\0', sz_netstr);
	inet_ntop(AF_INET, &network->network, netstr, sz_netstr);

	switch (network->subnetmask.s_addr) {
		case 0x00000000: { strcpy(mask, "0" ); break; }
		case 0x00000080: { strcpy(mask, "1" ); break; }
		case 0x000000c0: { strcpy(mask, "2" ); break; }
		case 0x000000e0: { strcpy(mask, "3" ); break; }
		case 0x000000f0: { strcpy(mask, "4" ); break; }
		case 0x000000f8: { strcpy(mask, "5" ); break; }
		case 0x000000fc: { strcpy(mask, "6" ); break; }
		case 0x000000fe: { strcpy(mask, "7" ); break; }
		case 0x000000ff: { strcpy(mask, "8" ); break; }
		case 0x000080ff: { strcpy(mask, "9" ); break; }
		case 0x0000c0ff: { strcpy(mask, "10"); break; }
		case 0x0000e0ff: { strcpy(mask, "11"); break; }
		case 0x0000f0ff: { strcpy(mask, "12"); break; }
		case 0x0000f8ff: { strcpy(mask, "13"); break; }
		case 0x0000fcff: { strcpy(mask, "14"); break; }
		case 0x0000feff: { strcpy(mask, "15"); break; }
		case 0x0000ffff: { strcpy(mask, "16"); break; }
		case 0x0080ffff: { strcpy(mask, "17"); break; }
		case 0x00c0ffff: { strcpy(mask, "18"); break; }
		case 0x00e0ffff: { strcpy(mask, "19"); break; }
		case 0x00f0ffff: { strcpy(mask, "20"); break; }
		case 0x00f8ffff: { strcpy(mask, "21"); break; }
		case 0x00fcffff: { strcpy(mask, "22"); break; }
		case 0x00feffff: { strcpy(mask, "23"); break; }
		case 0x00ffffff: { strcpy(mask, "24"); break; }
		case 0x80ffffff: { strcpy(mask, "25"); break; }
		case 0xc0ffffff: { strcpy(mask, "26"); break; }
		case 0xe0ffffff: { strcpy(mask, "27"); break; }
		case 0xf0ffffff: { strcpy(mask, "28"); break; }
		case 0xf8ffffff: { strcpy(mask, "29"); break; }
		case 0xfcffffff: { strcpy(mask, "30"); break; }
		case 0xfeffffff: { strcpy(mask, "31"); break; }
		case 0xffffffff: { strcpy(mask, "32"); break; }
	}
	if ((strlen(netstr) + 2 + strlen(mask)) > sz_netstr) {
		memset(netstr, '\0', sz_netstr);
		return 0;
	}
	strcat(netstr, "/");
	strcat(netstr, mask);
	return 1;
}
