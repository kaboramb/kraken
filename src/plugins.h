#ifndef _KRAKEN_PLUGINS_H
#define _KRAKEN_PLUGINS_H

#include <Python.h>

#define PLUGIN_SZ_NAME 31
#define PLUGIN_SZ_LAST_ERROR_MSG 63
#define PLUGIN_METHOD_INITIALIZE "initialize"
#define PLUGIN_METHOD_MAIN "main"
#define PLUGIN_METHOD_FINALIZE "finalize"

#define PLUGIN_CALLBACK_ID_HOST_ON_ADD 1
#define PLUGIN_CALLBACK_ID_HOST_ON_DEMAND 2
#define PLUGIN_CALLBACK_ID_HOST_STATUS_UP 3
#define PLUGIN_CALLBACK_ID_NETWORK_ON_ADD 4
#define PLUGIN_CALLBACK_ID_IS_VALID(i) ((0 < i) && (i < 5))

typedef kraken_basic_iter plugin_iter;
typedef PyObject plugin_callback;

typedef struct plugin_object {
	char name[PLUGIN_SZ_NAME + 1];
	PyObject *python_object;
	plugin_callback *callback_host_on_add;
	plugin_callback *callback_host_on_demand;
	plugin_callback *callback_host_on_status_up;
	plugin_callback *callback_network_on_add;
} plugin_object;

typedef struct plugin_manager {
	kraken_opts *k_opts;
	host_manager *c_host_manager;
	PyObject *pymod_kraken;
	plugin_object *current_plugin;
	kraken_thread_mutex callback_mutex;
	unsigned int n_plugins;
	plugin_object plugins[];
} plugin_manager;

int plugins_init(char *name, kraken_opts *k_opts, host_manager *c_host_manager);
void plugins_destroy(void);
void plugins_iter_init(plugin_iter *iter);
int plugins_iter_next(plugin_iter *iter, plugin_object **plugin);
int plugins_get_plugin_by_name(char *name, plugin_object **plugin);
int plugins_run_plugin_method(plugin_object *plugin, char *plugin_method, PyObject *plugin_args);
int plugins_plugin_get_callback(plugin_object *c_plugin, int callback_id, plugin_callback **callback);
int plugins_plugin_run_callback_host_on_demand(plugin_object *c_plugin, struct in_addr *ip);

#endif
