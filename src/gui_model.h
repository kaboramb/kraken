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
