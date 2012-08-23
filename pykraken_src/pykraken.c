#include <Python.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "kraken.h"
#include "host_manager.h"
#include "dns_enum.h"
#include "http_scan.h"
#include "network_addr.h"
#include "whois_lookup.h"

#define MODULE_DOC ""
#define MODULE_VERSION "0.1"

static PyObject *pykraken_whois_lookup_ip(PyObject *self, PyObject *args) {
	struct in_addr target_ip;
	char *ipstr;
	whois_response who_resp;
	PyObject *pyWhoResp = PyDict_New();
	PyObject *pyTmpStr = NULL;

	if (pyWhoResp == NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a dictionary to store the results");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		Py_DECREF(pyWhoResp);
		return NULL;
	}
	if (inet_pton(AF_INET, ipstr, &target_ip) == 0) {
		PyErr_SetString(PyExc_ValueError, "invalid IP address");
		Py_DECREF(pyWhoResp);
		return NULL;
	}
	if (whois_lookup_ip(&target_ip, &who_resp) != 0) {
		PyErr_SetString(PyExc_ValueError, "whois lookup failed");
		Py_DECREF(pyWhoResp);
		return NULL;
	}
	if (who_resp.cidr_s[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.cidr_s);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "cidr", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	if (who_resp.netname[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.netname);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "netname", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	if (who_resp.description[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.description);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "description", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	if (who_resp.orgname[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.orgname);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "orgname", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	if (who_resp.regdate_s[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.regdate_s);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "regdate", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	if (who_resp.updated_s[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.updated_s);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "updated", pyTmpStr);
			Py_DECREF(pyTmpStr);
		}
	}
	return pyWhoResp;
}

static PyObject *pykraken_get_nameservers(PyObject *self, PyObject *args) {
	domain_ns_list nameservers;
	char ipstr[INET_ADDRSTRLEN];
	int i;
	char *pTargetDomain;
	PyObject *nsList = PyDict_New();
	PyObject *nsIpaddr;

	if (nsList == NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a dictionary to store the results");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s", &pTargetDomain)) {
		Py_DECREF(nsList);
		return NULL;
	}
	memset(&nameservers, '\0', sizeof(nameservers));

	dns_get_nameservers_for_domain(pTargetDomain, &nameservers);
	for (i = 0; (nameservers.servers[i][0] != '\0' && i < DNS_MAX_NS_HOSTS); i++) {
		inet_ntop(AF_INET, &nameservers.ipv4_addrs[i], ipstr, sizeof(ipstr));
		nsIpaddr = PyString_FromString(ipstr);
		if (nsIpaddr) {
			PyDict_SetItemString(nsList, nameservers.servers[i], nsIpaddr);
			Py_DECREF(nsIpaddr);
		}
	}
	return nsList;
}

static PyObject *pykraken_enumerate_domain(PyObject *self, PyObject *args) {
	host_manager c_host_manager;
	host_iter host_i;
	single_host_info *c_host;
	hostname_iter hostname_i;
	char *hostname;
	char *pTargetDomain;
	char *pHostFileList;
	char ipstr[INET_ADDRSTRLEN];
	PyObject *pyTmpStr = NULL;
	PyObject *pyHostDict = PyDict_New();
	PyObject *pyAddrList = NULL;

	if (pyHostDict == NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a dictionary to store the results");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "ss", &pTargetDomain, &pHostFileList)) {
		Py_DECREF(pyHostDict);
		return NULL;
	}

	if (host_manager_init(&c_host_manager) != 0) {
		PyErr_SetString(PyExc_MemoryError, "could not initialize the host manager, it is likely that there is not enough memory");
		return NULL;
	}

	dns_enum_domain(&c_host_manager, pTargetDomain, pHostFileList);

	host_manager_iter_host_init(&c_host_manager, &host_i);
	while (host_manager_iter_host_next(&c_host_manager, &host_i, &c_host)) {
		single_host_iter_hostname_init(c_host, &hostname_i);
		while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
			pyTmpStr = PyString_FromString(hostname);
			pyAddrList = PyDict_GetItem(pyHostDict, pyTmpStr);
			if (pyAddrList == NULL) {
				pyAddrList = PyList_New(0);
				if (pyAddrList == NULL) {
					PyErr_SetString(PyExc_MemoryError, "could not create a list to store the results");
					return NULL;
				}
			}
			inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
			PyList_Append(pyAddrList, PyString_FromString(ipstr));
			PyDict_SetItem(pyHostDict, pyTmpStr, pyAddrList);
		}
	}
	host_manager_destroy(&c_host_manager);
	return pyHostDict;
}

static PyObject *pykraken_enumerate_network(PyObject *self, PyObject *args) {
	host_manager c_host_manager;
	host_iter host_i;
	single_host_info *c_host;
	network_addr network;
	hostname_iter hostname_i;
	char *hostname;
	char *pTargetDomain;
	char *pTargetNetwork;
	char ipstr[INET_ADDRSTRLEN];
	PyObject *pyTmpStr = NULL;
	PyObject *pyHostDict = PyDict_New();
	PyObject *pyAddrList = NULL;

	if (pyHostDict == NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a dictionary to store the results");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "ss", &pTargetDomain, &pTargetNetwork)) {
		Py_DECREF(pyHostDict);
		return NULL;
	}

	if (netaddr_cidr_str_to_nwk(&network, pTargetNetwork) != 0) {
		PyErr_SetString(PyExc_ValueError, "invalid CIDR network");
		Py_DECREF(pyHostDict);
		return NULL;
	}

	if (host_manager_init(&c_host_manager) != 0) {
		PyErr_SetString(PyExc_MemoryError, "could not initialize the host manager, it is likely that there is not enough memory");
		return NULL;
	}

	dns_enum_network_ex(&c_host_manager, pTargetDomain, &network, NULL);

	host_manager_iter_host_init(&c_host_manager, &host_i);
	while (host_manager_iter_host_next(&c_host_manager, &host_i, &c_host)) {
		single_host_iter_hostname_init(c_host, &hostname_i);
		while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
			pyTmpStr = PyString_FromString(hostname);
			pyAddrList = PyDict_GetItem(pyHostDict, pyTmpStr);
			if (pyAddrList == NULL) {
				pyAddrList = PyList_New(0);
				if (pyAddrList == NULL) {
					PyErr_SetString(PyExc_MemoryError, "could not create a list to store the results");
					return NULL;
				}
			}
			inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
			PyList_Append(pyAddrList, PyString_FromString(ipstr));
			PyDict_SetItem(pyHostDict, pyTmpStr, pyAddrList);
		}
	}
	host_manager_destroy(&c_host_manager);
	return pyHostDict;
}

static PyObject *pykraken_ip_in_cidr(PyObject *self, PyObject *args) {
	char *pIpAddr;
	char *pCidrNetwork;
	network_addr network;
	struct in_addr packedIp;

	if (!PyArg_ParseTuple(args, "ss", &pIpAddr, &pCidrNetwork)) {
		return NULL;
	}

	if (netaddr_cidr_str_to_nwk(&network, pCidrNetwork) != 0) {
		PyErr_SetString(PyExc_ValueError, "invalid CIDR network");
		return NULL;
	}

	if (inet_pton(AF_INET, pIpAddr, &packedIp) == 0) {
		PyErr_SetString(PyExc_ValueError, "invalid IP address");
		return NULL;
	}

	if (netaddr_ip_in_nwk(&network, &packedIp) == 1) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *pykraken_scrape_for_links(PyObject *self, PyObject *args) {
	char *pServer;
	char linkStr[HTTP_SCHEME_SZ + DNS_MAX_FQDN_LENGTH + HTTP_RESOURCE_SZ + 5]; /* len(":///") + 1 */
	http_link *link_anchor = NULL;
	http_link *link_current = NULL;
	unsigned int link_position = 0;
	unsigned int link_counter = 1;
	int ret_val = 0;
	PyObject *pyTmpStr = NULL;
	PyObject *pyLinkList = NULL;

	if (!PyArg_ParseTuple(args, "s", &pServer)) {
		return NULL;
	}
	ret_val = http_scrape_url_for_links(pServer, &link_anchor);
	if (ret_val != 0) {
		switch (ret_val) {
			case 1: PyErr_SetString(PyExc_MemoryError, "could not allocate memory to process the request");
			case 2: PyErr_SetString(PyExc_Exception, "the HTTP request failed");
			case 3: PyErr_SetString(PyExc_Exception, "the web server attempted to redirect to a different server");
			case 4: PyErr_SetString(PyExc_Exception, "the content type was not provided in the web servers response");
			default: PyErr_SetString(PyExc_Exception, "an unknown error occured");
		}
		http_free_link(link_anchor);
		return NULL;
	}
	if (link_anchor == NULL) {
		return PyTuple_New(0);
	}
	for (link_current = link_anchor->next; link_current; link_current = link_current->next) {
		link_counter++;
	}
	pyLinkList = PyTuple_New(link_counter);
	if (pyLinkList == NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a tuple to store the results");
		http_free_link(link_anchor);
		return NULL;
	}
	for (link_current = link_anchor; link_current; link_current = link_current->next) {
		memset(linkStr, '\0', sizeof(linkStr));
		strncat(linkStr, link_current->scheme, HTTP_SCHEME_SZ);
		strcat(linkStr, "://");
		strncat(linkStr, link_current->hostname, DNS_MAX_FQDN_LENGTH);
		strcat(linkStr, "/");
		strncat(linkStr, link_current->path, HTTP_RESOURCE_SZ);
		pyTmpStr = PyString_FromString(linkStr);
		if (pyTmpStr == NULL) {
			PyErr_SetString(PyExc_SystemError, "could not convert a C string to a Python string");
			Py_DECREF(pyLinkList);
			http_free_link(link_anchor);
			return NULL;
		}
		PyTuple_SetItem(pyLinkList, link_position, pyTmpStr);
		link_position++;
	}
	http_free_link(link_anchor);
	return pyLinkList;
}

static PyObject *pykraken_redirect_on_same_server(PyObject *self, PyObject *args) {
	char *original_url;
	char *redirect_url;
	int ret_val = 0;

	if (!PyArg_ParseTuple(args, "ss", &original_url, &redirect_url)) {
		return NULL;
	}
	ret_val = http_redirect_on_same_server(original_url, redirect_url);
	if (ret_val == -1) {
		PyErr_SetString(PyExc_ValueError, "a problem occured while parsing the URLs");
		return NULL;
	}
	if (ret_val == 1) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *pykraken_enumerate_bing(PyObject *self, PyObject *args) {
	char *target_domain;
	char *bing_api_key;
	host_manager c_host_manager;
	host_iter host_i;
	single_host_info *c_host;
	hostname_iter hostname_i;
	char *hostname;
	char ipstr[INET_ADDRSTRLEN];
	http_enum_opts h_opts;
	PyObject *pyTmpStr = NULL;
	PyObject *pyHostDict = PyDict_New();
	PyObject *pyAddrList = NULL;

	if (pyHostDict== NULL) {
		PyErr_SetString(PyExc_MemoryError, "could not create a dictionary to store the results");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "ss", &target_domain, &bing_api_key)) {
		return NULL;
	}

	host_manager_init(&c_host_manager);
	http_enum_opts_init(&h_opts);
	http_enum_opts_set_bing_api_key(&h_opts, bing_api_key);

	http_search_engine_bing_ex(&c_host_manager, target_domain, &h_opts);

	host_manager_iter_host_init(&c_host_manager, &host_i);
	while (host_manager_iter_host_next(&c_host_manager, &host_i, &c_host)) {
		single_host_iter_hostname_init(c_host, &hostname_i);
		while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
			pyTmpStr = PyString_FromString(hostname);
			pyAddrList = PyDict_GetItem(pyHostDict, pyTmpStr);
			if (pyAddrList == NULL) {
				pyAddrList = PyList_New(0);
				if (pyAddrList == NULL) {
					PyErr_SetString(PyExc_MemoryError, "could not create a list to store the results");
					return NULL;
				}
			}
			inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
			PyList_Append(pyAddrList, PyString_FromString(ipstr));
			PyDict_SetItem(pyHostDict, pyTmpStr, pyAddrList);
		}
	}
	http_enum_opts_destroy(&h_opts);
	host_manager_destroy(&c_host_manager);
	return pyHostDict;
}

static PyMethodDef PyKrakenMethods[] = {
	{"whois_lookup_ip", pykraken_whois_lookup_ip, METH_VARARGS, "whois_lookup_ip(target_ip)\nRetrieve the whois record pretaining to an IP address\n\n@type target_ip: String\n@param target_ip: ip address to retreive whois information for"},
	{"get_nameservers", pykraken_get_nameservers, METH_VARARGS, "get_nameservers(target_domain)\nEnumerate nameservers for a domain\n\n@type target_domain: String\n@param target_domain: the domain to retreive the list of name servers for"},
	{"enumerate_domain", pykraken_enumerate_domain, METH_VARARGS, "enumerate_domain(target_domain, host_list)\nEnumerate hostnames for a domain\n\n@type target_domain: String\n@param target_domain: the domain to enumerate hostnames for\n@type host_list: String\n@param host_list: path to a file containing a list of host names to bruteforce"},
	{"enumerate_network", pykraken_enumerate_network, METH_VARARGS, "enumerate_network(target_domain, target_network)\nEnumerate hostnames for a network\n\n@type target_domain: String\n@param target_domain: the domain who's name servers to use\n@type target_network: String\n@param target_network: the network in CIDR notation to bruteforce records for"},
	{"ip_in_cidr", pykraken_ip_in_cidr, METH_VARARGS, "ip_in_cidr(target_ip, target_network)\nCheck if an IP address is in a CIDR network\n\n@type target_ip: String\n@param target_ip: the ip to check\n@type target_network: String\n@param target_network: the network to check"},
	{"scrape_for_links", pykraken_scrape_for_links, METH_VARARGS, ""},
	{"redirect_on_same_server", pykraken_redirect_on_same_server, METH_VARARGS, ""},
	{"enumerate_bing", pykraken_enumerate_bing, METH_VARARGS, ""},
	{NULL, NULL, 0, NULL}
};

void initpykraken(void) {
   	PyObject *mod;
	mod = Py_InitModule3("pykraken", PyKrakenMethods, MODULE_DOC);
	PyModule_AddStringConstant(mod, "version", MODULE_VERSION);
	return;
}

int main(int argc, char *argv[]) {
	Py_SetProgramName(argv[0]);
	Py_Initialize();
	initpykraken();
	return 0;
}
