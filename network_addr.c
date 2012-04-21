#include "network_addr.h"

int netaddr_ip_in_nwk(struct *in_addr, struct network_info* network) {
	/*
	 * Returns 0 on "No the network described by in_addr is not in network"
	 * Returns 1 on "Yes the network described by in_addr is in network"
	 */
	if ((in_addr->s_addr & network->subnetmask.s_addr) == (network->network.s_addr)) {
		 return 1;
	}
	return 0;
}

int netaddr_cidr_str_to_nwk(char *netstr, struct network_info* network) {
	/*
	 * Returns 0 on success
	 * Returns 1 on failure (due to unparseable address)
	 * 
	 * netstr is a cidr range such as "192.168.1.1/25" network is a pointer to a network_info structure
	 * In the event that the IP is not a member of the network such as above, the network (in this case 192.168.1.0)
	 * is placed into the network member of the network_info structure
	 */
	char *pCur = NULL;
	int bits = 0;
	unsigned short *dbls;
	
	memset(network, '\0', sizeof(struct network_info));
	pCur = strchr(netstr, '/');
	if (pCur == NULL) {
		return 1;
	}
	*pCur = '\0';
	pCur += 1;
	if (strlen(pCur) > 2) {
		return 1;
	}
	
	inet_pton(AF_INET, netstr, &network->network);
	bits = atoi(pCur);
	if (bits > 32) {
		return 1;
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
	return 0;
}
