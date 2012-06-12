#ifndef _KRAKEN_GUI_POPUPS_H
#define _KRAKEN_GUI_POPUPS_H

#include "hosts.h"
#include "http_scan.h"
#include "gui_model.h"

#define GUI_POPUP_ERROR_EXPORT_FAILED(window) gui_popup_error_dialog(window, "Failed To Save Data", "Error: Failed To Save")
#define GUI_POPUP_ERROR_IMPORT_FAILED(window) gui_popup_error_dialog(window, "Failed To Import Data", "Error: Failed To Import")
#define GUI_POPUP_ERROR_INVALID_CIDR_NETWORK(window) gui_popup_error_dialog(window, "Invalid CIDR Network", "Error: Invalid Network")
#define GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(window) gui_popup_error_dialog(window, "Invalid Domain Name", "Error: Invalid Domain")
#define GUI_POPUP_ERROR_INVALID_HOST_NAME(window) gui_popup_error_dialog(window, "Invalid Host Name", "Error: Invalid Host")
#define GUI_POPUP_ERROR_INVALID_NO_HOSTS_FOUND_IN_LINKS(window) gui_popup_error_dialog(window, "No Links Were Found", "Error: No Links")

typedef struct popup_data {
	GtkWidget *tree_view;
	GtkWidget *main_marquee;
	host_manager *c_host_manager;
	GtkWidget *popup_window;
	GtkWidget *text_entry0;
	GtkWidget *text_entry1;
	GtkWidget *misc_widget;
} popup_data;

void gui_popup_error_dialog(gpointer window, const char *message, const char *title);
void gui_popup_info_dialog(gpointer window, const char *message, const char *title);
gint gui_popup_question_yes_no_dialog(gpointer window, const char *message, const char *title);
gboolean gui_popup_http_scan_links(main_gui_data *m_data, char *host_str);
gboolean gui_popup_dns_bf_domain(main_gui_data *m_data);
gboolean gui_popup_dns_bf_network(main_gui_data *m_data, char *cidr_str);
gboolean gui_popup_select_hosts_from_http_links(main_gui_data *m_data, http_link *link_anchor);

#endif
