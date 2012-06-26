#ifndef _KRAKEN_GUI_MENU_FUNCTIONS_H
#define _KRAKEN_GUI_MENU_FUNCTIONS_H

#include "hosts.h"
#include "gui_model.h"

GtkWidget *get_main_menubar(GtkWidget  *window, gpointer userdata);
void gui_menu_file_export_csv(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_file_open(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_file_save(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_file_save_as(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_dns_forward_bf(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_dns_reverse_bf(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_http_scan_all_for_links(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_http_scan_host_for_links(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_http_search_bing(main_gui_data *userdata, guint action, GtkWidget *widget);
void gui_menu_edit_preferences(main_gui_data *m_data, guint action, GtkWidget *widget);

#endif
