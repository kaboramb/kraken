#ifndef _KRAKEN_GUI_POPUPS_H
#define _KRAKEN_GUI_POPUPS_H

#include "hosts.h"

typedef struct popup_data {
	GtkWidget *popup_window;
	GtkWidget *text_entry0;
	GtkWidget *text_entry1;
	GtkWidget *tree_view;
	host_manager *c_host_manager;
} popup_data;

gboolean gui_popup_bf_domain(GtkWidget *tree_view, host_manager *c_host_manager);
gboolean gui_popup_bf_network(GtkWidget *tree_view, host_manager *c_host_manager);

#endif
