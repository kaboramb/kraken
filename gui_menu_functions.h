#ifndef _KRAKEN_GUI_MENU_FUNCTIONS_H
#define _KRAKEN_GUI_MENU_FUNCTIONS_H

#include "hosts.h"

typedef struct menu_data {
	GtkWidget *tree_view;
	host_manager *c_host_manager;
} menu_data;

GtkWidget *get_main_menubar(GtkWidget  *window, gpointer userdata);
void gui_menu_edit_dns_forward_bf(menu_data *userdata, guint action, GtkWidget *widget);

#endif
