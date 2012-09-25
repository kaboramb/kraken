#ifndef _KRAKEN_PLUGINS_H
#define _KRAKEN_PLUGINS_H

#include <Python.h>

#define PLUGIN_SZ_NAME 31
#define PLUGIN_METHOD_INITIALIZE "initialize"
#define PLUGIN_METHOD_MAIN "main"
#define PLUGIN_METHOD_FINALIZE "finalize"

#define PLUGIN_CALLBACK_ID_HOST_ON_ADD 10
#define PLUGIN_CALLBACK_ID_HOST_ON_DEMAND 11
#define PLUGIN_CALLBACK_ID_HOST_STATUS_UP 13
#define PLUGIN_CALLBACK_DATA_HOST(i) ((9 < i) && (i < 20))
#define PLUGIN_CALLBACK_ID_NETWORK_ON_ADD 20
#define PLUGIN_CALLBACK_DATA_NETWORK(i) ((19 < i) && (i < 30))

#define KSTATUS_PLUGIN_IS_ERROR(i) (i < 0)
#define KSTATUS_PLUGIN_IS_PYEXC(i) ((i < -1999) && (i > -3000))
#define KSTATUS_PLUGIN_OK 0
#define KSTATUS_PLUGIN_ERROR_ARGUMENT -2
#define KSTATUS_PLUGIN_ERROR_PYFUNCTION -3
#define KSTATUS_PLUGIN_ERROR_PYARGUMENT -4
#define KSTATUS_PLUGIN_ERROR_NO_PYATTRIBUTE -5
#define KSTATUS_PLUGIN_ERROR_PYOBJCREATE -6
#define KSTATUS_PLUGIN_ERROR_NOT_INITIALIZED -1000
#define KSTATUS_PLUGIN_ERROR_NO_PLUGINS -1001
#define KSTATUS_PLUGIN_ERROR_PYEXC -2000

typedef kraken_basic_iter plugin_iter;
typedef PyObject plugin_callback;
typedef int kstatus_plugin;

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
kstatus_plugin plugins_run_plugin_method_arg_str(plugin_object *plugin, char *plugin_method, char *plugin_args, char *error_msg, size_t error_msg_sz);
kstatus_plugin plugins_run_plugin_method(plugin_object *plugin, char *plugin_method, PyObject *args_container, char *error_msg, size_t error_msg_sz);
int plugins_plugin_get_callback(plugin_object *c_plugin, int callback_id, plugin_callback **callback);
kstatus_plugin plugins_all_run_callback(int callback_id, void *data, char *error_msg, size_t error_msg_sz);
kstatus_plugin plugins_plugin_run_callback(plugin_object *c_plugin, int callback_id, void *data, char *error_msg, size_t error_msg_sz);

#endif
