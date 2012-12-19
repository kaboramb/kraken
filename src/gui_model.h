// gui_model.h
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

#ifndef _KRAKEN_GUI_MODEL_H
#define _KRAKEN_GUI_MODEL_H

#include "kraken.h"
#include "plugins.h"

#define GUI_MODEL_MAX_MARQUEE_MSG_SIZE 32

typedef struct main_gui_data {
	int gui_is_active;
	GtkWidget *main_window;
	GtkWidget *tree_view;
	GtkWidget *main_marquee;

	GtkWidget *plugin_box;
	GtkWidget *plugin_entry;
	kraken_thread_mutex plugin_mutex;
	kraken_thread plugin_thread;

	kraken_opts *k_opts;
	host_manager *c_host_manager;
} main_gui_data;

typedef struct gui_data_menu_plugin {
	main_gui_data *m_data;
	plugin_object *c_plugin;
	int callback_id;
	void *plugin_data;
} gui_data_menu_plugin;

void gui_model_update_marquee(main_gui_data *m_data, const char *status);
int gui_model_update_tree_and_marquee(main_gui_data *m_data, const char *status);
GtkTreeModel *gui_refresh_tree_model(GtkTreeStore *store, main_gui_data *m_data);
GtkWidget *gui_model_create_view_and_model(host_manager *c_host_manager, main_gui_data *m_data);

#endif
