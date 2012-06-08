#ifndef _KRAKEN_GUI_MODEL_H
#define _KRAKEN_GUI_MODEL_H

#include "hosts.h"

#define GUI_MODEL_MAX_MARQUEE_SIZE 32

typedef struct main_gui_data {
	GtkWidget *tree_view;
	GtkWidget *main_marquee;
	host_manager *c_host_manager;
} main_gui_data;

void gui_model_update_marquee(main_gui_data *m_data, const char *status);
int gui_model_update_tree_and_marquee(main_gui_data *m_data, const char *status);
GtkTreeModel *gui_refresh_tree_model(GtkListStore *store, host_manager *c_host_manager);
GtkWidget *create_view_and_model(host_manager *c_host_manager, main_gui_data *m_data);

#endif
