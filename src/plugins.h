// plugins.h
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of SecureState Consulting nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

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
