#ifndef _KRAKEN_GUI_POPUPS_H
#define _KRAKEN_GUI_POPUPS_H

#include "hosts.h"
#include "gui_model.h"

typedef struct popup_data {
	GtkWidget *tree_view;
	GtkWidget *main_marquee;
	host_manager *c_host_manager;
	GtkWidget *popup_window;
	GtkWidget *text_entry0;
	GtkWidget *text_entry1;
} popup_data;

gboolean gui_popup_bf_domain(main_gui_data *m_data);
gboolean gui_popup_bf_network(main_gui_data *m_data, char *cidr_str);

#endif
