#ifndef _KRAKEN_GUI_MENU_FUNCTIONS_H
#define _KRAKEN_GUI_MENU_FUNCTIONS_H

#include "hosts.h"
#include "gui_model.h"

GtkWidget *get_main_menubar(GtkWidget  *window, gpointer userdata);
void gui_menu_edit_dns_forward_bf(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_dns_reverse_bf(main_gui_data *userdata, guint action, GtkWidget *widget);

#endif
