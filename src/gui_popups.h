#ifndef _KRAKEN_GUI_POPUPS_H
#define _KRAKEN_GUI_POPUPS_H

#include "kraken.h"
#include "http_scan.h"
#include "gui_model.h"

#define GUI_POPUP_ERROR_EXPORT_FAILED(window) gui_popup_error_dialog(window, "Failed To Save Data", "Error: Failed To Save")
#define GUI_POPUP_ERROR_IMPORT_FAILED(window) gui_popup_error_dialog(window, "Failed To Import Data", "Error: Failed To Import")
#define GUI_POPUP_ERROR_GENERIC_ERROR(window) gui_popup_error_dialog(window, "An Error Occured", "An Error Occured")
#define GUI_POPUP_ERROR_INVALID_CIDR_NETWORK(window) gui_popup_error_dialog(window, "Invalid CIDR Network", "Error: Invalid Network")
#define GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(window) gui_popup_error_dialog(window, "Invalid Domain Name", "Error: Invalid Domain")
#define GUI_POPUP_ERROR_INVALID_HOST_NAME(window) gui_popup_error_dialog(window, "Invalid Host Name", "Error: Invalid Host")
#define GUI_POPUP_ERROR_INVALID_NO_HOSTS_FOUND_IN_LINKS(window) gui_popup_error_dialog(window, "No Links Were Found", "Error: No Links")
#define GUI_POPUP_QUESTION_SURE(window) gui_popup_question_yes_no_dialog(window, "Are You Sure?", "Confirm Action")

#define GUI_POPUP_BUTTON_TYPE_GENERIC 0
#define GUI_POPUP_BUTTON_TYPE_START 1
#define GUI_POPUP_BUTTON_TYPE_CANCEL 2
#define GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION 3
/* "BASIC" buttons have no call back assigned to them */
#define GUI_POPUP_BUTTON_TYPE_BASIC_APPLY 4
#define GUI_POPUP_BUTTON_TYPE_BASIC_START 5
#define GUI_POPUP_BUTTON_TYPE_BASIC_CANCEL 6

typedef struct popup_data {
	main_gui_data *m_data;
	void (*thread_function)(void *data);
	GtkWidget *popup_window;
	GtkWidget *text_entry0;
	GtkWidget *text_entry1;
	GtkWidget *misc_widget;
	GtkWidget *start_button;
	GtkWidget *cancel_button;
	GtkWidget *cancel_dialog;
	int action_status;
} popup_data;

void gui_popup_error_dialog(gpointer window, const char *message, const char *title);
void gui_popup_error_dialog_plugin(gpointer window, kstatus_plugin status, const char *message);
void gui_popup_info_dialog(gpointer window, const char *message, const char *title);
gint gui_popup_question_yes_no_dialog(gpointer window, const char *message, const char *title);
gboolean gui_popup_http_scrape_hosts_for_links(main_gui_data *m_data);
gboolean gui_popup_http_scrape_url_for_links(main_gui_data *m_data, char *host_str);
gboolean gui_popup_http_search_engine_bing(main_gui_data *m_data);
gboolean gui_popup_dns_enum_domain(main_gui_data *m_data);
gboolean gui_popup_dns_enum_network(main_gui_data *m_data, char *cidr_str);
gboolean gui_popup_select_hosts_from_http_links(main_gui_data *m_data, http_link *link_anchor);
gboolean gui_popup_manage_kraken_settings(main_gui_data *m_data);
gboolean gui_popup_help_about(main_gui_data *m_data);

#endif
