#ifndef _KRAKEN_GUI_MODEL_H
#define _KRAKEN_GUI_MODEL_H

#include "hosts.h"

typedef struct main_gui_data {
	GtkWidget *tree_view;
	GtkWidget *main_marquee;
	host_manager *c_host_manager;
} main_gui_data;

int gui_model_update_tree_and_marquee(main_gui_data *m_data);
GtkTreeModel *gui_refresh_tree_model(GtkListStore *store, host_manager *c_host_manager);
GtkWidget *create_view_and_model(host_manager *c_host_manager);

#endif
