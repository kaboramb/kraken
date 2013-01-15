// gui_popups.h
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of SecureState Consulting nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

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
#define GUI_POPUP_ERROR_INVALID_IP_ADDRESS(window) gui_popup_error_dialog(window, "Invalid IP Address", "Error: Invalid IP")
#define GUI_POPUP_ERROR_INVALID_NO_HOSTS_FOUND_IN_LINKS(window) gui_popup_error_dialog(window, "No Links Were Found", "Error: No Links")
#define GUI_POPUP_ERROR_PLUGIN_RUNNING(window) gui_popup_error_dialog_plugin(window, KSTATUS_PLUGIN_OK, "A plugin is already running")
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
gint gui_popup_question_yes_no_cancel_dialog(gpointer window, const char *message, const char *title);
gboolean gui_popup_http_scrape_hosts_for_links(main_gui_data *m_data);
gboolean gui_popup_http_scrape_url_for_links(main_gui_data *m_data, char *host_str);
gboolean gui_popup_http_search_engine_bing_domain(main_gui_data *m_data);
gboolean gui_popup_http_search_engine_bing_ip(main_gui_data *m_data, char *ipstr);
gboolean gui_popup_dns_enum_domain(main_gui_data *m_data);
gboolean gui_popup_dns_enum_network(main_gui_data *m_data, char *cidr_str);
gboolean gui_popup_select_hosts_from_http_links(main_gui_data *m_data, http_link *link_anchor);
gboolean gui_popup_manage_kraken_settings(main_gui_data *m_data);
gboolean gui_popup_help_about(main_gui_data *m_data);

#endif
