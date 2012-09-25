#include "kraken.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "plugins.h"
#include "host_manager.h"
#include "logging.h"
#include "utilities.h"

#define PYMOD_KRAKEN_DOC ""
#define PYMOD_KRAKEN_VERSION "0.1"

#define PLUGINS_PYTHON_ERROR_CREATION() PyErr_SetString(PyExc_MemoryError, "creation of a necessary Python type failed")
#define PLUGINS_PYTHON_ERROR_CONVERSION() PyErr_SetString(PyExc_ValueError, "could not convert a value to a Python type")
#define PLUGINS_PYTHON_ERROR_INVALID_IP() PyErr_SetString(PyExc_ValueError, "invalid IP Address")

static plugin_manager *c_plugin_manager = NULL;

PyObject *plugins_utils_host_get_hostnames_list(single_host_info *c_host) {
	char *hostname;
	hostname_iter hostname_i;
	PyObject *py_hostname_list;
	PyObject *py_hostname;

	py_hostname_list = PyList_New(0);
	if (py_hostname_list == NULL) {
		PLUGINS_PYTHON_ERROR_CREATION();
		return NULL;
	}
	single_host_iter_hostname_init(c_host, &hostname_i);
	while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
		py_hostname = PyString_FromString(hostname);
		if (py_hostname == NULL) {
			Py_DECREF(py_hostname_list);
			PyErr_SetString(PyExc_ValueError, "invalid hostname");
			return NULL;
		}
		if (PyList_Append(py_hostname_list, py_hostname) < 0) {
			Py_DECREF(py_hostname);
			Py_DECREF(py_hostname_list);
			PyErr_SetString(PyExc_StandardError, "could not insert the hostname into the list");
			return NULL;
		}
		Py_DECREF(py_hostname);
	}
	return py_hostname_list;
}

PyObject *plugins_utils_host_get_host_dict(single_host_info *c_host) {
	char ipstr[INET_ADDRSTRLEN];
	PyObject *py_host_dict;
	PyObject *py_tmp_obj;

	py_host_dict = PyDict_New();
	if (py_host_dict == NULL) {
		PLUGINS_PYTHON_ERROR_CREATION();
		return NULL;
	}

	inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
	py_tmp_obj = PyString_FromString(ipstr);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_host_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_host_dict, "ipv4_addr", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	if (c_host->whois_data == NULL) {
		Py_INCREF(Py_None);
		PyDict_SetItemString(py_host_dict, "network", Py_None);
	} else {
		py_tmp_obj = PyString_FromString(c_host->whois_data->cidr_s);
		if (py_tmp_obj == NULL) {
			Py_DECREF(py_host_dict);
			PLUGINS_PYTHON_ERROR_CONVERSION();
			return NULL;
		}
		PyDict_SetItemString(py_host_dict, "network", py_tmp_obj);
		Py_DECREF(py_tmp_obj);
	}

	py_tmp_obj = plugins_utils_host_get_hostnames_list(c_host);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_host_dict);
		return NULL;
	}
	PyDict_SetItemString(py_host_dict, "names", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyInt_FromLong(c_host->status);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_host_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_host_dict, "status", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	return py_host_dict;
}

PyObject *plugins_utils_host_get_network_dict(whois_record *w_rcd) {
	PyObject *py_net_dict;
	PyObject *py_tmp_obj;

	py_net_dict = PyDict_New();
	if (py_net_dict == NULL) {
		PLUGINS_PYTHON_ERROR_CREATION();
		return NULL;
	}

	py_tmp_obj = PyString_FromString(w_rcd->cidr_s);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "cidr", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyString_FromString(w_rcd->netname);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "netname", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyString_FromString(w_rcd->description);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "description", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyString_FromString(w_rcd->orgname);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "orgname", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyString_FromString(w_rcd->regdate_s);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "regdate", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	py_tmp_obj = PyString_FromString(w_rcd->updated_s);
	if (py_tmp_obj == NULL) {
		Py_DECREF(py_net_dict);
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	PyDict_SetItemString(py_net_dict, "updated", py_tmp_obj);
	Py_DECREF(py_tmp_obj);

	return py_net_dict;
}

static PyObject *pymod_kraken_api_callback_register(PyObject *self, PyObject *args) {
	static char *callback_id_original;
	char callback_id[32];
	PyObject *callback_function;
	plugin_callback **stored_callback_function = NULL;

	if (!PyArg_ParseTuple(args, "sO", &callback_id_original, &callback_function)) {
		return NULL;
	}
	if (!PyCallable_Check(callback_function)) {
		PyErr_SetString(PyExc_TypeError, "the callback function must be callable");
		return NULL;
	}
	if (c_plugin_manager->current_plugin == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "the callback api is currently locked");
		return NULL;
	}
	if (kraken_thread_mutex_trylock(&c_plugin_manager->callback_mutex) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "the callback api is currently locked");
		return NULL;
	}

	strncpy(callback_id, callback_id_original, (sizeof(callback_id) - 1));
	util_str_to_lower(callback_id);

	if (strcmp(callback_id, "host_on_add") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_add;
	} else if (strcmp(callback_id, "host_on_demand") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_demand;
	} else if (strcmp(callback_id, "host_on_status_up") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_status_up;
	} else if (strcmp(callback_id, "network_on_add") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_network_on_add;
	} else {
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		PyErr_SetString(PyExc_ValueError, "invalid callback identifier");
		return NULL;
	}
	if (*stored_callback_function != NULL) {
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		PyErr_SetString(PyExc_RuntimeError, "only one function can be registered to a callback event at a time");
		return NULL;
	}
	Py_INCREF(callback_function);
	*stored_callback_function = callback_function;

	kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
	logging_log("kraken.plugins", LOGGING_NOTICE, "plugin %s registered a callback for event: %s", c_plugin_manager->current_plugin->name, callback_id);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *pymod_kraken_api_callback_unregister(PyObject *self, PyObject *args) {
	char *callback_id;
	plugin_callback **stored_callback_function = NULL;

	if (!PyArg_ParseTuple(args, "s", &callback_id)) {
		return NULL;
	}
	if (c_plugin_manager->current_plugin == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "the callback api is currently locked");
		return NULL;
	}
	if (kraken_thread_mutex_trylock(&c_plugin_manager->callback_mutex) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "the callback api is currently locked");
		return NULL;
	}

	if (strcasecmp(callback_id, "host_on_add") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_add;
	} else if (strcasecmp(callback_id, "host_on_demand") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_demand;
	} else if (strcasecmp(callback_id, "host_on_status_up") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_host_on_status_up;
	} else if (strcasecmp(callback_id, "network_on_add") == 0) {
		stored_callback_function = &c_plugin_manager->current_plugin->callback_network_on_add;
	} else {
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		PyErr_SetString(PyExc_ValueError, "invalid callback identifier");
		return NULL;
	}
	if (*stored_callback_function == NULL) {
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		PyErr_SetString(PyExc_RuntimeError, "no callback is registered to that event");
		return NULL;
	}
	Py_XDECREF(*stored_callback_function);
	*stored_callback_function = NULL;

	kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *pymod_kraken_api_log(PyObject *self, PyObject *args) {
	char *message;
	int logLvl;

	if (!PyArg_ParseTuple(args, "is", &logLvl, &message)) {
		return NULL;
	}

	logging_log("kraken.plugins", logLvl, "%s", message);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef pymod_kraken_methods[] = {
	{"callback_register", pymod_kraken_api_callback_register, METH_VARARGS, ""},
	{"callback_unregister", pymod_kraken_api_callback_unregister, METH_VARARGS, ""},
	{"log", pymod_kraken_api_log, METH_VARARGS, ""},
	{NULL, NULL, 0, NULL}
};

static PyObject *pymod_kraken_host_manager_get_host_count(PyObject *self, PyObject *args) {
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	return Py_BuildValue("I", c_plugin_manager->c_host_manager->known_hosts);
}

static PyObject *pymod_kraken_host_manager_get_host_by_id(PyObject *self, PyObject *args) {
	unsigned int id;
	char ipstr[INET_ADDRSTRLEN];
	single_host_info *c_host;

	if (!PyArg_ParseTuple(args, "I", &id)) {
		return NULL;
	}
	if (!host_manager_get_host_by_id(c_plugin_manager->c_host_manager, id, &c_host)) {
		PyErr_SetString(PyExc_ValueError, "invalid host id");
		return NULL;
	}
	inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));

	return Py_BuildValue("s", ipstr);
}

static PyObject *pymod_kraken_host_manager_get_host_details(PyObject *self, PyObject *args) {
	char *ipstr;
	single_host_info *c_host;
	struct in_addr ip;

	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		return NULL;
	}
	inet_pton(AF_INET, ipstr, &ip);
	if (!host_manager_get_host_by_addr(c_plugin_manager->c_host_manager, &ip, &c_host)) {
		PLUGINS_PYTHON_ERROR_INVALID_IP();
		return NULL;
	}

	return plugins_utils_host_get_host_dict(c_host);
}

static PyObject *pymod_kraken_host_manager_set_host_details(PyObject *self, PyObject *args) {
	char *tmphostname;
	char *ipstr;
	single_host_info *c_host;
	single_host_info new_host;
	struct in_addr ip;
	PyObject *py_host_dict;
	PyObject *py_tmp_obj;

	if (!PyArg_ParseTuple(args, "O!", &PyDict_Type, &py_host_dict)) {
		return NULL;
	}

	py_tmp_obj = PyDict_GetItemString(py_host_dict, "ipv4_addr");
	if (py_tmp_obj == NULL) {
		PyErr_SetString(PyExc_KeyError, "missing ipv4_addr key");
		return NULL;
	}
	if (!PyString_Check(py_tmp_obj)) {
		PyErr_SetString(PyExc_TypeError, "ipv4_addr must be specified as a string");
		return NULL;
	}
	ipstr = PyString_AsString(py_tmp_obj);
	if (ipstr == NULL) {
		return NULL; /* PyString_AsString rasies a TypeError if necessary */
	}

	if (!inet_pton(AF_INET, ipstr, &ip)) {
		PLUGINS_PYTHON_ERROR_INVALID_IP();
		return NULL;
	}

	single_host_init(&new_host);
	new_host.status = KRAKEN_HOST_STATUS_UNKNOWN;
	if (!host_manager_get_host_by_addr(c_plugin_manager->c_host_manager, &ip, &c_host)) {
		memcpy(&new_host.ipv4_addr, &ip, sizeof(struct in_addr));
		c_host = &new_host;
	}

	py_tmp_obj = PyDict_GetItemString(py_host_dict, "status");
	if (py_tmp_obj != NULL) {
		if (!PyInt_Check(py_tmp_obj)) {
			single_host_destroy(&new_host);
			PyErr_SetString(PyExc_TypeError, "status must be specified as an integer");
			return NULL;
		}
		if (!KRAKEN_HOST_STATUS_IS_VALID(PyInt_AsLong(py_tmp_obj))) {
			single_host_destroy(&new_host);
			PyErr_SetString(PyExc_ValueError, "the status is not within a valid range");
			return NULL;
		}
		c_host->status = PyInt_AsLong(py_tmp_obj);
	}

	py_tmp_obj = PyDict_GetItemString(py_host_dict, "names");
	if (py_tmp_obj != NULL) {
		if (PyString_Check(py_tmp_obj)) {
			tmphostname = PyString_AsString(py_tmp_obj);
			if (tmphostname == NULL) {
				single_host_destroy(&new_host);
				return NULL; /* PyString_AsString rasies a TypeError if necessary */
			}
			single_host_add_hostname(c_host, tmphostname);
		} else if (PyList_Check(py_tmp_obj)) {
			PyObject *py_hostname_list = py_tmp_obj;
			Py_ssize_t list_sz = 0;
			Py_ssize_t list_pos = 0;
			list_sz = PyList_Size(py_hostname_list);
			for (list_pos = 0; list_pos < list_sz; list_pos++) {
				py_tmp_obj = PyList_GetItem(py_hostname_list, list_pos);
				if (!PyString_Check(py_tmp_obj)) {
					single_host_destroy(&new_host);
					PyErr_SetString(PyExc_TypeError, "the name must be specified as a string");
					return NULL;
				}
				tmphostname = PyString_AsString(py_tmp_obj);
				if (tmphostname == NULL) {
					single_host_destroy(&new_host);
					return NULL;
				}
				single_host_add_hostname(c_host, tmphostname);
			}
		} else {
			single_host_destroy(&new_host);
			PyErr_SetString(PyExc_TypeError, "the names field must be specified as a string or a list of strings");
			return NULL;
		}
	}
	host_manager_add_host(c_plugin_manager->c_host_manager, c_host);
	single_host_destroy(&new_host);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *pymod_kraken_host_manager_get_hosts(PyObject *self, PyObject *args) {
	host_iter host_i;
	single_host_info *c_host;
	PyObject *py_ip_list;
	PyObject *py_ipstr;
	char ipstr[INET_ADDRSTRLEN];

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	py_ip_list = PyList_New(0);
	if (py_ip_list == NULL) {
		PLUGINS_PYTHON_ERROR_CREATION();
		return NULL;
	}
	host_manager_iter_host_init(c_plugin_manager->c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_plugin_manager->c_host_manager, &host_i, &c_host)) {
		inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
		py_ipstr = PyString_FromString(ipstr);
		if (py_ipstr == NULL) {
			Py_DECREF(py_ip_list);
			PLUGINS_PYTHON_ERROR_INVALID_IP();
			return NULL;
		}
		if (PyList_Append(py_ip_list, py_ipstr) < 0) {
			Py_DECREF(py_ipstr);
			Py_DECREF(py_ip_list);
			PyErr_SetString(PyExc_StandardError, "could not insert the ip address into the list");
			return NULL;
		}
		Py_DECREF(py_ipstr);
	}
	return py_ip_list;
}

static PyObject *pymod_kraken_host_manager_get_hostnames(PyObject *self, PyObject *args) {
	char *ipstr;
	single_host_info *c_host;
	struct in_addr ip;

	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		return NULL;
	}
	inet_pton(AF_INET, ipstr, &ip);
	if (!host_manager_get_host_by_addr(c_plugin_manager->c_host_manager, &ip, &c_host)) {
		PLUGINS_PYTHON_ERROR_INVALID_IP();
		return NULL;
	}

	return plugins_utils_host_get_hostnames_list(c_host);
}

static PyObject *pymod_kraken_host_manager_add_hostname(PyObject *self, PyObject *args) {
	char *ipstr;
	char *hostname;
	single_host_info *c_host;
	struct in_addr ip;

	if (!PyArg_ParseTuple(args, "ss", &ipstr, &hostname)) {
		return NULL;
	}
	inet_pton(AF_INET, ipstr, &ip);
	if (!host_manager_get_host_by_addr(c_plugin_manager->c_host_manager, &ip, &c_host)) {
		PLUGINS_PYTHON_ERROR_INVALID_IP();
		return NULL;
	}
	single_host_add_hostname(c_host, hostname);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *pymod_kraken_host_manager_get_network_count(PyObject *self, PyObject *args) {
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	return Py_BuildValue("I", c_plugin_manager->c_host_manager->known_whois_records);
}

static PyObject *pymod_kraken_host_manager_get_network_by_id(PyObject *self, PyObject *args) {
	unsigned int id;
	char ipstr[INET_ADDRSTRLEN];
	whois_record *w_rcd;

	if (!PyArg_ParseTuple(args, "I", &id)) {
		return NULL;
	}
	if (!host_manager_get_whois_by_id(c_plugin_manager->c_host_manager, id, &w_rcd)) {
		PyErr_SetString(PyExc_ValueError, "invalid network id");
		return NULL;
	}

	return Py_BuildValue("s", w_rcd->cidr_s);
}

static PyObject *pymod_kraken_host_manager_get_network_details(PyObject *self, PyObject *args) {
	char *ipstr;
	whois_record *w_rcd;
	network_addr network;
	struct in_addr ip;

	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		return NULL;
	}
	if (inet_pton(AF_INET, ipstr, &ip)) {
		if (!host_manager_get_whois_by_addr(c_plugin_manager->c_host_manager, &ip, &w_rcd)) {
			PyErr_SetString(PyExc_ValueError, "no network information available");
			return NULL;
		}
	} else if (netaddr_cidr_str_to_nwk(&network, ipstr)) {
		if (!host_manager_get_whois(c_plugin_manager->c_host_manager, &network, &w_rcd)) {
			PyErr_SetString(PyExc_ValueError, "no network information available");
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_ValueError, "invalid host\network specification");
		return NULL;
	}

	return plugins_utils_host_get_network_dict(w_rcd);
}

static PyObject *pymod_kraken_host_manager_get_network_by_addr(PyObject *self, PyObject *args) {
	char *ipstr;
	whois_record *w_rcd;
	struct in_addr ip;
	PyObject *py_cidr;

	if (!PyArg_ParseTuple(args, "s", &ipstr)) {
		return NULL;
	}
	if (!inet_pton(AF_INET, ipstr, &ip)) {
		PLUGINS_PYTHON_ERROR_INVALID_IP();
		return NULL;
	}
	if (!host_manager_get_whois_by_addr(c_plugin_manager->c_host_manager, &ip, &w_rcd)) {
		PyErr_SetString(PyExc_ValueError, "no network information available");
		return NULL;
	}
	py_cidr = PyString_FromString(w_rcd->cidr_s);
	if (py_cidr == NULL) {
		PLUGINS_PYTHON_ERROR_CONVERSION();
		return NULL;
	}
	return py_cidr;
}

static PyObject *pymod_kraken_host_manager_get_networks(PyObject *self, PyObject *args) {
	whois_iter whois_i;
	whois_record *w_rcd;
	PyObject *py_cidr_list;
	PyObject *py_tmp_str;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	py_cidr_list = PyList_New(0);
	if (py_cidr_list == NULL) {
		PLUGINS_PYTHON_ERROR_CREATION();
		return NULL;
	}
	host_manager_iter_whois_init(c_plugin_manager->c_host_manager, &whois_i);
	while (host_manager_iter_whois_next(c_plugin_manager->c_host_manager, &whois_i, &w_rcd)) {
		if (strlen(w_rcd->cidr_s) == 0) {
			continue;
		}
		py_tmp_str = PyString_FromString(w_rcd->cidr_s);
		if (py_tmp_str == NULL) {
			Py_DECREF(py_cidr_list);
			PLUGINS_PYTHON_ERROR_CONVERSION();
			return NULL;
		}
		if (PyList_Append(py_cidr_list, py_tmp_str) < 0) {
			Py_DECREF(py_tmp_str);
			Py_DECREF(py_cidr_list);
			PyErr_SetString(PyExc_StandardError, "could not insert the network into the list");
			return NULL;
		}
		Py_DECREF(py_tmp_str);
	}

	return py_cidr_list;
}

static PyObject *pymod_kraken_host_manager_quick_add_by_name(PyObject *self, PyObject *args) {
	char *hostname;
	int ret_val;

	if (!PyArg_ParseTuple(args, "s", &hostname)) {
		return NULL;
	}
	ret_val = host_manager_quick_add_by_name(c_plugin_manager->c_host_manager, hostname);
	if (ret_val == -1) {
		PyErr_SetString(PyExc_ValueError, "could not resolve the hostname");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef pymod_kraken_host_manager_methods[] = {
	{"get_host_count", pymod_kraken_host_manager_get_host_count, METH_VARARGS, ""},
	{"get_host_by_id", pymod_kraken_host_manager_get_host_by_id, METH_VARARGS, ""},
	{"get_host_details", pymod_kraken_host_manager_get_host_details, METH_VARARGS, ""},
	{"set_host_details", pymod_kraken_host_manager_set_host_details, METH_VARARGS, ""},
	{"get_hosts", pymod_kraken_host_manager_get_hosts, METH_VARARGS, ""},
	{"get_hostnames", pymod_kraken_host_manager_get_hostnames, METH_VARARGS, ""},
	{"add_hostname", pymod_kraken_host_manager_add_hostname, METH_VARARGS, ""},
	{"get_network_count", pymod_kraken_host_manager_get_network_count, METH_VARARGS, ""},
	{"get_network_by_id", pymod_kraken_host_manager_get_network_by_id, METH_VARARGS, ""},
	{"get_network_details", pymod_kraken_host_manager_get_network_details, METH_VARARGS, ""},
	{"get_network_by_addr", pymod_kraken_host_manager_get_network_by_addr, METH_VARARGS, ""},
	{"get_networks", pymod_kraken_host_manager_get_networks, METH_VARARGS, ""},
	{"quick_add_by_name", pymod_kraken_host_manager_quick_add_by_name, METH_VARARGS, ""},
	{NULL, NULL, 0, NULL}
};

PyObject *plugins_pymod_kraken_init(void) {
   	PyObject *pymod_kraken;
   	PyObject *pymod_kraken_host_manager;

	pymod_kraken = Py_InitModule3("kraken", pymod_kraken_methods, PYMOD_KRAKEN_DOC);
	PyModule_AddStringConstant(pymod_kraken, "version", PYMOD_KRAKEN_VERSION);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_FATAL", LOGGING_FATAL);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_ALERT", LOGGING_ALERT);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_CRITICAL", LOGGING_CRITICAL);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_ERROR", LOGGING_ERROR);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_WARNING", LOGGING_WARNING);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_NOTICE", LOGGING_NOTICE);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_INFO", LOGGING_INFO);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_DEBUG", LOGGING_DEBUG);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_TRACE", LOGGING_TRACE);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_NOTSET", LOGGING_NOTSET);
	PyModule_AddIntConstant(pymod_kraken, "LOG_LVL_UNKNOWN", LOGGING_UNKNOWN);

	pymod_kraken_host_manager = Py_InitModule3("kraken.host_manager", pymod_kraken_host_manager_methods, PYMOD_KRAKEN_DOC);
	PyModule_AddIntConstant(pymod_kraken_host_manager, "HOST_STATUS_UP", KRAKEN_HOST_STATUS_UP);
	PyModule_AddIntConstant(pymod_kraken_host_manager, "HOST_STATUS_UNKNOWN", KRAKEN_HOST_STATUS_UNKNOWN);
	PyModule_AddIntConstant(pymod_kraken_host_manager, "HOST_STATUS_DOWN", KRAKEN_HOST_STATUS_DOWN);

	PyModule_AddObject(pymod_kraken, "error", PyErr_NewException("kraken.error", NULL, NULL));
	PyModule_AddObject(pymod_kraken, "host_manager", pymod_kraken_host_manager);
	return pymod_kraken;
}

void plugins_python_sys_path_append(char *path) {
	char tmppath[512];
	if (snprintf(tmppath, sizeof(tmppath), "%s:%s", Py_GetPath(), path) >= sizeof(tmppath)) {
		logging_log("kraken.plugins", LOGGING_ERROR, "the Python path is to large for the buffer and could not be set");
		return;
	}
	PySys_SetPath(tmppath);
	return;
}

void plugins_python_sys_path_prepend(char *path) {
	char tmppath[512];
	if (snprintf(tmppath, sizeof(tmppath), "%s:%s", path, Py_GetPath()) >= sizeof(tmppath)) {
		logging_log("kraken.plugins", LOGGING_ERROR, "the Python path is to large for the buffer and could not be set");
		return;
	}
	PySys_SetPath(tmppath);
	return;
}

int plugins_init(char *name, kraken_opts *k_opts, host_manager *c_host_manager) {
	DIR *dp;
	struct dirent *ep;
	unsigned int c_plugin = 0;
	unsigned int n_plugins = 0;
	plugin_iter plugin_i;
	plugin_object *plugin_obj;
	size_t name_sz;
	PyObject *pymod_kraken;
	PyObject *pName;
	PyObject *pPluginObj;
	PyObject *pInitFunc;
	PyObject *pReturnValue;
	char plugin_path[128];
	char plugin_name[PLUGIN_SZ_NAME + 1];

	if (c_plugin_manager != NULL) {
		logging_log("kraken.plugins", LOGGING_ERROR, "the plugin engine has already been initialized");
		return;
	}
	logging_log("kraken.plugins", LOGGING_DEBUG, "initializing the python plugin engine");

	memset(plugin_path, '\0', sizeof(plugin_path));
	snprintf(plugin_path, sizeof(plugin_path), "%s/kraken/plugins", DATAROOTDIR);
	if (!util_dir_exists(plugin_path)) {
		logging_log("kraken.plugins", LOGGING_CRITICAL, "could not find the data directory");
		return -1;
	}

	Py_SetProgramName(name);
	Py_Initialize();
	PyEval_InitThreads();
	pymod_kraken = plugins_pymod_kraken_init();
	plugins_python_sys_path_prepend(plugin_path);

	dp = opendir(plugin_path);
	if (dp == NULL) {
		Py_Finalize();
		return -1;
	}
	while (ep = readdir(dp)) {
		if (ep->d_type != DT_REG) {
			continue;
		}
		name_sz = strlen(ep->d_name) - 3;
		if (strncmp(&ep->d_name[name_sz], ".py", 3) != 0) {
			continue;
		}
		if (name_sz > PLUGIN_SZ_NAME) {
			continue;
		}
		n_plugins++;
	}
	closedir(dp);

	c_plugin_manager = calloc(sizeof(plugin_manager) + (sizeof(plugin_object) * n_plugins), 1);
	if (c_plugin_manager == NULL) {
		logging_log("kraken.plugins", LOGGING_CRITICAL, "could not allocate enough memory for the plugin engine");
		return -2;
	}
	c_plugin_manager->k_opts = k_opts;
	c_plugin_manager->c_host_manager = c_host_manager;
	c_plugin_manager->current_plugin = NULL;
	c_plugin_manager->pymod_kraken = pymod_kraken;
	kraken_thread_mutex_init(&c_plugin_manager->callback_mutex);
	kraken_thread_mutex_lock(&c_plugin_manager->callback_mutex);
	c_plugin_manager->n_plugins = n_plugins;
	n_plugins = 0;

	plugins_iter_init(&plugin_i);
	dp = opendir(plugin_path);
	while (ep = readdir(dp)) {
		if (ep->d_type != DT_REG) {
			continue;
		}
		name_sz = strlen(ep->d_name) - 3;
		if (strncmp(&ep->d_name[name_sz], ".py", 3) != 0) {
			continue;
		}
		if (name_sz > PLUGIN_SZ_NAME) {
			continue;
		}
		memset(plugin_name, '\0', sizeof(plugin_name));
		strncpy(plugin_name, ep->d_name, name_sz);
		logging_log("kraken.plugins", LOGGING_TRACE, "loading plugin %s", plugin_name);
		pName = PyString_FromString(plugin_name);
		pPluginObj = PyImport_Import(pName);
		Py_DECREF(pName);
		if (pPluginObj == NULL) {
			logging_log("kraken.plugins", LOGGING_WARNING, "could not load plugin %s", plugin_name);
			continue;
		}
		plugins_iter_next(&plugin_i, &plugin_obj);
		strncpy(plugin_obj->name, plugin_name, name_sz);
		plugin_obj->python_object = pPluginObj;
		plugin_obj->callback_host_on_add = NULL;
		plugin_obj->callback_host_on_demand = NULL;
		plugin_obj->callback_host_on_status_up = NULL;
		plugin_obj->callback_network_on_add = NULL;
		n_plugins++;

		/* run the initialize method if it is defined */
		pInitFunc = PyObject_GetAttrString(plugin_obj->python_object, PLUGIN_METHOD_INITIALIZE);
		if (pInitFunc == NULL) {
			PyErr_Clear();
			continue;
		}
		if (!PyCallable_Check(pInitFunc)) {
			logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin_name, PLUGIN_METHOD_INITIALIZE);
			Py_XDECREF(pInitFunc);
			continue;
		}
		c_plugin_manager->current_plugin = plugin_obj;
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		pReturnValue = PyObject_CallObject(pInitFunc, NULL);
		kraken_thread_mutex_lock(&c_plugin_manager->callback_mutex);
		Py_XDECREF(pInitFunc);
		if (pReturnValue == NULL) {
			logging_log("kraken.plugins", LOGGING_ERROR, "the call to function %s.%s failed", plugin_name, PLUGIN_METHOD_INITIALIZE);
			continue;
		}
		if (PyErr_Occurred()) {
			logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin_name, PLUGIN_METHOD_INITIALIZE);
			PyErr_Clear();
		}
		Py_XDECREF(pReturnValue);
	}
	closedir(dp);
	c_plugin_manager->current_plugin = NULL;
	c_plugin_manager->n_plugins = n_plugins;
	logging_log("kraken.plugins", LOGGING_INFO, "successfully loaded %u plugins", c_plugin_manager->n_plugins);
	return;
}

void plugins_destroy(void) {
	plugin_iter plugin_i;
	plugin_object *plugin_obj;
	PyObject *pFiniFunc;
	PyObject *pReturnValue;

	logging_log("kraken.plugins", LOGGING_DEBUG, "finalizing the python plugin engine");

	PyErr_CheckSignals();
	if (PyErr_Occurred()) {
		if (!PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
			logging_log("kraken.plugins", LOGGING_WARNING, "an error has occurred prior to finalizing any plugin");
		}
		PyErr_Clear();
	}

	/* run the finalize method if it is defined */
	plugins_iter_init(&plugin_i);
	while (plugins_iter_next(&plugin_i, &plugin_obj)) {
		pFiniFunc = PyObject_GetAttrString(plugin_obj->python_object, PLUGIN_METHOD_FINALIZE);
		if (pFiniFunc == NULL) {
			PyErr_Clear();
			continue;
		}
		if (!PyCallable_Check(pFiniFunc)) {
			logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
			Py_XDECREF(pFiniFunc);
			continue;
		}
		c_plugin_manager->current_plugin = plugin_obj;
		kraken_thread_mutex_unlock(&c_plugin_manager->callback_mutex);
		pReturnValue = PyObject_CallObject(pFiniFunc, NULL);
		kraken_thread_mutex_lock(&c_plugin_manager->callback_mutex);
		Py_XDECREF(pFiniFunc);
		if (pReturnValue == NULL) {
			logging_log("kraken.plugins", LOGGING_ERROR, "the call to function %s.%s failed", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
			continue;
		}
		if (PyErr_Occurred()) {
			logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
			PyErr_Clear();
		}
		Py_XDECREF(pReturnValue);
	}

	plugins_iter_init(&plugin_i);
	while (plugins_iter_next(&plugin_i, &plugin_obj)) {
		Py_XDECREF(plugin_obj->python_object);
		if (plugin_obj->callback_host_on_add != NULL) {
			Py_XDECREF(plugin_obj->callback_host_on_add);
		}
		if (plugin_obj->callback_host_on_demand != NULL) {
			Py_XDECREF(plugin_obj->callback_host_on_demand);
		}
		if (plugin_obj->callback_host_on_status_up != NULL) {
			Py_XDECREF(plugin_obj->callback_host_on_status_up);
		}
		if (plugin_obj->callback_network_on_add != NULL) {
			Py_XDECREF(plugin_obj->callback_network_on_add);
		}
	}
	c_plugin_manager->current_plugin = NULL;
	Py_Finalize();
	return;
}

void plugins_iter_init(plugin_iter *iter) {
	assert(c_plugin_manager != NULL);
	iter->status = KRAKEN_ITER_STATUS_NEW;
	iter->position = 0;
	return;
}

int plugins_iter_next(plugin_iter *iter, plugin_object **plugin) {
	if (iter->status == KRAKEN_ITER_STATUS_NEW) {
		iter->status = KRAKEN_ITER_STATUS_USED;
	} else {
		iter->position += 1;
	}
	if (iter->position >= c_plugin_manager->n_plugins) {
		*plugin = NULL;
		return 0;
	}
	*plugin = &c_plugin_manager->plugins[iter->position];
	return 1;
}

int plugins_get_plugin_by_name(char *name, plugin_object **plugin) {
	plugin_iter plugin_i;
	plugin_object *c_plugin;

	*plugin = NULL;
	plugins_iter_init(&plugin_i);
	while (plugins_iter_next(&plugin_i, &c_plugin)) {
		if (strlen(c_plugin->name) != strlen(name)) {
			continue;
		}
		if (strcasecmp(c_plugin->name, name) != 0) {
			continue;
		}
		*plugin = c_plugin;
		return 1;
	}
	return 0;
}

kstatus_plugin plugins_run_plugin_method_arg_str(plugin_object *plugin, char *plugin_method, char *plugin_args, char *error_msg, size_t error_msg_sz) {
	PyObject *arg;
	PyObject *args_container;
	int ret_val = 0;

	assert(c_plugin_manager != NULL);
	args_container = PyTuple_New(1);
	arg = PyString_FromString(plugin_args);
	if ((args_container == NULL) || (arg == NULL)) {
		return KSTATUS_PLUGIN_ERROR_PYOBJCREATE;
	}
	PyTuple_SetItem(args_container, 0, arg);
	ret_val = plugins_run_plugin_method(plugin, plugin_method, args_container, error_msg, error_msg_sz);

	Py_XDECREF(args_container);
	return ret_val;
}

kstatus_plugin plugins_run_plugin_method(plugin_object *plugin, char *plugin_method, PyObject *args_container, char *error_msg, size_t error_msg_sz) {
	PyObject *pFunc;
	PyObject *py_ret_val = NULL;

	assert(c_plugin_manager != NULL);
	if (error_msg != NULL) {
		memset(error_msg, '\0', error_msg_sz);
	}
	pFunc = PyObject_GetAttrString(plugin->python_object, plugin_method);
	if (pFunc == NULL) {
		logging_log("kraken.plugins", LOGGING_ERROR, "could not find plugin attribute %s.%s", plugin->name, plugin_method);
		return KSTATUS_PLUGIN_ERROR_NO_PYATTRIBUTE;
	}
	if (!PyCallable_Check(pFunc)) {
		Py_XDECREF(pFunc);
		logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin->name, plugin_method);
		return KSTATUS_PLUGIN_ERROR_PYFUNCTION;
	}

	py_ret_val = PyObject_CallObject(pFunc, args_container);
	Py_XDECREF(args_container);
	Py_XDECREF(py_ret_val);

	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyObject_GetAttrString(c_plugin_manager->pymod_kraken, "error"))) {
			PyObject *py_ret_val;
			PyObject *py_err_type;
			PyObject *py_err_value;
			PyObject *py_err_traceback;
			PyObject *py_message;
			char *message;

			PyErr_Fetch(&py_err_type, &py_err_value, &py_err_traceback);
			if (py_err_value != NULL) {
				py_message = PyObject_GetAttrString(py_err_value, "message");
				message = PyString_AsString(py_message);
				if (error_msg != NULL) {
					if (strlen(message) < error_msg_sz) {
						strncpy(error_msg, message, error_msg_sz);
					}
				}
				logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Kraken exception with message: %s", plugin->name, plugin_method, message);
			} else {
				logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Kraken exception, but the message could not be retrieved", plugin->name, plugin_method);
			}
		} else {
			logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin->name, plugin_method);
		}
		PyErr_Clear();
		return KSTATUS_PLUGIN_ERROR_PYEXC;
	}
	return KSTATUS_PLUGIN_OK;
}

int plugins_plugin_get_callback(plugin_object *c_plugin, int callback_id, plugin_callback **callback) {
	/*
	 * This can be used to both retrieve a callback as well as verify
	 * that an ID is valid
	 *
	 * returns -1 on invalid callback id
	 * returns 0 when the callback is not registered
	 * returns 1 when the callback is registered
	 */
	*callback = NULL;
	switch (callback_id) {
		case PLUGIN_CALLBACK_ID_HOST_ON_ADD:
			*callback = c_plugin->callback_host_on_add;
			break;
		case PLUGIN_CALLBACK_ID_HOST_ON_DEMAND:
			*callback = c_plugin->callback_host_on_demand;
			break;
		case PLUGIN_CALLBACK_ID_HOST_STATUS_UP:
			*callback = c_plugin->callback_host_on_status_up;
			break;
		case PLUGIN_CALLBACK_ID_NETWORK_ON_ADD:
			*callback = c_plugin->callback_network_on_add;
			break;
		default:
			return -1;
			break;
	}
	if (*callback == NULL) {
		return 0;
	}
	return 1;
}

kstatus_plugin plugins_all_run_callback(int callback_id, void *data, char *error_msg, size_t error_msg_sz) {
	plugin_iter plugin_i;
	plugin_object *c_plugin;
	plugin_callback *test_callback;

	/* check plugins have been initialized and the callback_id is valid before proceeding */
	if (c_plugin_manager == NULL) {
		return KSTATUS_PLUGIN_ERROR_NOT_INITIALIZED;
	}
	plugins_iter_init(&plugin_i);
	if (!plugins_iter_next(&plugin_i, &c_plugin)) {
		logging_log("kraken.plugins", LOGGING_INFO, "no plugins are loaded");
		return KSTATUS_PLUGIN_ERROR_NO_PLUGINS;
	}
	if (plugins_plugin_get_callback(c_plugin, callback_id, &test_callback) < 0) {
		logging_log("kraken.plugins", LOGGING_ERROR, "invalid callback ID specified");
		return KSTATUS_PLUGIN_ERROR_ARGUMENT;
	}

	/* validation complete, run 'em all */
	plugins_iter_init(&plugin_i);
	while (plugins_iter_next(&plugin_i, &c_plugin)) {
		plugins_plugin_run_callback(c_plugin, callback_id, data, error_msg, error_msg_sz);
	}

	return KSTATUS_PLUGIN_OK;
}

kstatus_plugin plugins_plugin_run_callback(plugin_object *c_plugin, int callback_id, void *data, char *error_msg, size_t error_msg_sz) {
	plugin_callback *callback;
	PyObject *arg;
	PyObject *args_container;
	PyObject *py_ret_val = NULL;

	if (c_plugin_manager == NULL) {
		return KSTATUS_PLUGIN_ERROR_NOT_INITIALIZED;
	}
	if (error_msg != NULL) {
		memset(error_msg, '\0', error_msg_sz);
	}
	if (!plugins_plugin_get_callback(c_plugin, callback_id, &callback)) {
		return KSTATUS_PLUGIN_ERROR_ARGUMENT;
	}

	args_container = PyTuple_New(1);
	if (args_container == NULL) {
		return KSTATUS_PLUGIN_ERROR_PYOBJCREATE;
	}
	if (PLUGIN_CALLBACK_DATA_HOST(callback_id)) {
		arg = plugins_utils_host_get_host_dict((single_host_info *)data);
	} else if (PLUGIN_CALLBACK_DATA_NETWORK(callback_id)) {
		arg = plugins_utils_host_get_network_dict((whois_record *)data);
	} else {
		Py_DECREF(args_container);
		return KSTATUS_PLUGIN_ERROR_ARGUMENT;
	}

	if (arg == NULL) {
		logging_log("kraken.plugins", LOGGING_ERROR, "the plugins_util function failed to convert the object to a python object");
		PyErr_Clear();
		Py_DECREF(args_container);
		return KSTATUS_PLUGIN_ERROR_PYOBJCREATE;
	}

	PyTuple_SetItem(args_container, 0, arg);

	py_ret_val = PyObject_CallObject((PyObject *)callback, args_container);
	Py_XDECREF(args_container);
	Py_XDECREF(py_ret_val);
	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyObject_GetAttrString(c_plugin_manager->pymod_kraken, "error"))) {
			PyObject *py_ret_val;
			PyObject *py_err_type;
			PyObject *py_err_value;
			PyObject *py_err_traceback;
			PyObject *py_message;
			char *message;

			PyErr_Fetch(&py_err_type, &py_err_value, &py_err_traceback);
			if (py_err_value != NULL) {
				py_message = PyObject_GetAttrString(py_err_value, "message");
				message = PyString_AsString(py_message);
				if (error_msg != NULL) {
					if (strlen(message) < error_msg_sz) {
						strncpy(error_msg, message, error_msg_sz);
					}
				}
				logging_log("kraken.plugins", LOGGING_WARNING, "the callback in plugin %s produced a Kraken exception with message: %s", c_plugin->name, message);
			} else {
				logging_log("kraken.plugins", LOGGING_WARNING, "the callback in plugin %s produced a Kraken exception, but the message could not be retrieved", c_plugin->name);
			}
		} else {
			logging_log("kraken.plugins", LOGGING_WARNING, "the callback in plugin %s produced a Python exception", c_plugin->name);
		}
		PyErr_Clear();
		return KSTATUS_PLUGIN_ERROR_PYEXC;
	}
	return KSTATUS_PLUGIN_OK;
}
