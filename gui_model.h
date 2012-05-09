#ifndef _KRAKEN_GUI_MODEL_H
#define _KRAKEN_GUI_MODEL_H

#include "hosts.h"

GtkTreeModel *gui_refresh_tree_model(GtkListStore *store, host_manager *c_host_manager);
GtkWidget *create_view_and_model(host_manager *c_host_manager);

#endif
