#include "kraken.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "plugins.h"
#include "logging.h"
#include "utilities.h"

#define PYMOD_KRAKEN_DOC ""
#define PYMOD_KRAKEN_VERSION "0.1"

static plugin_manager *c_plugin_manager = NULL;

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
	{"log", pymod_kraken_api_log, METH_VARARGS, ""},
	{NULL, NULL, 0, NULL}
};

void plugins_pymod_kraken_init(void) {
   	PyObject *mod;
	mod = Py_InitModule3("kraken", pymod_kraken_methods, PYMOD_KRAKEN_DOC);
	PyModule_AddStringConstant(mod, "version", PYMOD_KRAKEN_VERSION);

	PyModule_AddIntConstant(mod, "LOG_LVL_FATAL", LOGGING_FATAL);
	PyModule_AddIntConstant(mod, "LOG_LVL_ALERT", LOGGING_ALERT);
	PyModule_AddIntConstant(mod, "LOG_LVL_CRITICAL", LOGGING_CRITICAL);
	PyModule_AddIntConstant(mod, "LOG_LVL_ERROR", LOGGING_ERROR);
	PyModule_AddIntConstant(mod, "LOG_LVL_WARNING", LOGGING_WARNING);
	PyModule_AddIntConstant(mod, "LOG_LVL_NOTICE", LOGGING_NOTICE);
	PyModule_AddIntConstant(mod, "LOG_LVL_INFO", LOGGING_INFO);
	PyModule_AddIntConstant(mod, "LOG_LVL_DEBUG", LOGGING_DEBUG);
	PyModule_AddIntConstant(mod, "LOG_LVL_TRACE", LOGGING_TRACE);
	PyModule_AddIntConstant(mod, "LOG_LVL_NOTSET", LOGGING_NOTSET);
	PyModule_AddIntConstant(mod, "LOG_LVL_UNKNOWN", LOGGING_UNKNOWN);
	return;
}

void plugins_python_sys_path_append(char *path) {
	char command[256];

	snprintf(command, sizeof(command), "import sys\nsys.path.append('%s')\n", path);
	PyRun_SimpleString(command);
	return;
}

int plugins_init(char *name) {
	DIR *dp;
	struct dirent *ep;
	unsigned int c_plugin = 0;
	unsigned int n_plugins = 0;
	plugin_iter plugin_i;
	plugin_object *plugin_obj;
	size_t name_sz;
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
	plugins_pymod_kraken_init();
	plugins_python_sys_path_append(plugin_path);

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
	c_plugin_manager->n_plugins = n_plugins;
	c_plugin_manager->plugins = (plugin_object *)(c_plugin_manager + sizeof(plugin_manager));

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
		strncpy(plugin_name, ep->d_name, name_sz);
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

		/* run the initialize method if it is defined */
		pInitFunc = PyObject_GetAttrString(plugin_obj->python_object, PLUGIN_METHOD_INITIALIZE);
		if (pInitFunc == NULL) {
			continue;
		}
		if (!PyCallable_Check(pInitFunc)) {
			logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin_name, PLUGIN_METHOD_INITIALIZE);
			Py_XDECREF(pInitFunc);
			continue;
		}
		pReturnValue = PyObject_CallObject(pInitFunc, NULL);
		Py_XDECREF(pInitFunc);
		if (pReturnValue == NULL) {
			logging_log("kraken.plugins", LOGGING_ERROR, "the call to function %s.%s() failed", plugin_name, PLUGIN_METHOD_INITIALIZE);
			continue;
		}
		if (PyErr_Occurred()) {
			logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin_name, PLUGIN_METHOD_INITIALIZE);
		}
		Py_XDECREF(pReturnValue);
	}
	closedir(dp);

	logging_log("kraken.plugins", LOGGING_INFO, "successfully loaded %u plugins", c_plugin_manager->n_plugins);
	return;
}

void plugins_destroy(void) {
	plugin_iter plugin_i;
	plugin_object *plugin_obj;
	PyObject *pFiniFunc;
	PyObject *pReturnValue;

	logging_log("kraken.plugins", LOGGING_DEBUG, "finalizing the python plugin engine");

	/* run the finalize method if it is defined */
	plugins_iter_init(&plugin_i);
	while (plugins_iter_next(&plugin_i, &plugin_obj)) {
		pFiniFunc = PyObject_GetAttrString(plugin_obj->python_object, PLUGIN_METHOD_FINALIZE);
		if (pFiniFunc == NULL) {
			continue;
		}
		if (!PyCallable_Check(pFiniFunc)) {
			logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
			Py_XDECREF(pFiniFunc);
			continue;
		}
		pReturnValue = PyObject_CallObject(pFiniFunc, NULL);
		Py_XDECREF(pFiniFunc);
		if (pReturnValue == NULL) {
			logging_log("kraken.plugins", LOGGING_ERROR, "the call to function %s.%s() failed", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
			continue;
		}
		if (PyErr_Occurred()) {
			logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin_obj->name, PLUGIN_METHOD_FINALIZE);
		}
		Py_XDECREF(pReturnValue);
	}
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

int plugins_run_plugin_method(plugin_object *plugin, char *plugin_method, PyObject *plugin_args) {
	PyObject *pFunc;
	PyObject *pReturnValue;

	pFunc = PyObject_GetAttrString(plugin->python_object, plugin_method);
	if (pFunc == NULL) {
		logging_log("kraken.plugins", LOGGING_ERROR, "could not find plugin attribute %s.%s", plugin->name, plugin_method);
		return -2;
	}
	if (!PyCallable_Check(pFunc)) {
		logging_log("kraken.plugins", LOGGING_ERROR, "plugin attribute %s.%s is not callable", plugin->name, plugin_method);
		return -2;
	}

	pReturnValue = PyObject_CallObject(pFunc, plugin_args);
	if (pReturnValue == NULL) {
		Py_XDECREF(pFunc);
		logging_log("kraken.plugins", LOGGING_ERROR, "the call to function %s.%s() failed", plugin->name, plugin_method);
		return -3;
	}

	if (PyErr_Occurred()) {
		logging_log("kraken.plugins", LOGGING_WARNING, "the call to function %s.%s produced a Python exception", plugin->name, plugin_method);
	}
	Py_XDECREF(pFunc);
	Py_XDECREF(pReturnValue);
	return;
}
