#include <Python.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "hosts.h"
#include "host_manager.h"
#include "dns_enum.h"
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
		PyErr_SetString(PyExc_Exception, "could not create a dictionary to store the results");
		return NULL;
	}
	
	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		Py_DECREF(pyWhoResp);
		return NULL;
	}
	if (inet_pton(AF_INET, ipstr, &target_ip) == 0) {
		PyErr_SetString(PyExc_Exception, "invalid IP address");
		Py_DECREF(pyWhoResp);
		return NULL;
	}
	if (whois_lookup_ip(&target_ip, &who_resp) != 0) {
		PyErr_SetString(PyExc_Exception, "whois lookup failed");
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
	if (who_resp.comment[0] != '\0') {
		pyTmpStr = PyString_FromString(who_resp.comment);
		if (pyTmpStr) {
			PyDict_SetItemString(pyWhoResp, "comment", pyTmpStr);
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
		PyErr_SetString(PyExc_Exception, "could not create a dictionary to store the results");
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

static PyMethodDef PyKrakenMethods[] = {
	{"whois_lookup_ip", pykraken_whois_lookup_ip, METH_VARARGS, "Retrieve the whois record pretaining to an IP address"},
	{"get_nameservers", pykraken_get_nameservers, METH_VARARGS, "Enumerate nameservers for a domain"},
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
