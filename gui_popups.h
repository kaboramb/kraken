#ifndef _KRAKEN_GUI_POPUPS_H
#define _KRAKEN_GUI_POPUPS_H

#include "hosts.h"
#include "http_scan.h"
#include "gui_model.h"

typedef struct popup_data {
	GtkWidget *tree_view;
	GtkWidget *main_marquee;
	host_manager *c_host_manager;
	GtkWidget *popup_window;
	GtkWidget *text_entry0;
	GtkWidget *text_entry1;
	GtkWidget *misc_widget;
} popup_data;

gboolean gui_popup_bf_domain(main_gui_data *m_data);
gboolean gui_popup_bf_network(main_gui_data *m_data, char *cidr_str);
gboolean gui_popup_select_hosts_from_http_links(main_gui_data *m_data, http_link *link_anchor);

#endif
