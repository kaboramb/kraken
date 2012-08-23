#ifndef _KRAKEN_PLUGINS_H
#define _KRAKEN_PLUGINS_H

#include <Python.h>

#define PLUGIN_SZ_NAME 31
#define PLUGIN_METHOD_INITIALIZE "initialize"
#define PLUGIN_METHOD_MAIN "main"
#define PLUGIN_METHOD_FINALIZE "finalize"

typedef struct plugin_iter {
	int status;
	unsigned int position;
} plugin_iter;

typedef struct plugin_object {
	char name[PLUGIN_SZ_NAME + 1];
	PyObject *python_object;
} plugin_object;

typedef struct plugin_manager {
	unsigned int n_plugins;
	plugin_object *plugins;
} plugin_manager;

int plugins_init(char *name);
void plugins_destroy(void);
void plugins_iter_init(plugin_iter *iter);
int plugins_iter_next(plugin_iter *iter, plugin_object **plugin);
int plugins_run_plugin_method(plugin_object *plugin, char *plugin_method, PyObject *plugin_args);

#endif
