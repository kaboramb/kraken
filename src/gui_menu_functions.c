// gui_menu_functions.c
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

#include "kraken.h"

#include <stdlib.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <string.h>

#include "export.h"
#include "gui_menu_functions.h"
#include "gui_model.h"
#include "plugins.h"
#include "gui_popups.h"
#include "host_manager.h"

static void suppress_log_function(G_GNUC_UNUSED const gchar *log_domain, G_GNUC_UNUSED GLogLevelFlags log_level, G_GNUC_UNUSED const gchar *message, G_GNUC_UNUSED gpointer user_data) {
	/* suppress the message */
	/* https://bugzilla.gnome.org/show_bug.cgi?id=662814 */
}

int gui_menu_file_save_as_ex(main_gui_data *m_data, guint action, GtkWidget *widget) {
	/* Returns -1 on error, 0 on failure didn't save and 1 on save */
	GtkWidget *dialog;
	guint log_handler;
	const char *domain = "Gtk";
	gint response;
	int ret_val = 0;

	if ((m_data->c_host_manager->known_hosts == 0) && (m_data->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(GTK_WINDOW(m_data->main_window), "There Is No Data To Save", "Error: No Data");
		return 0;
	}
	dialog = gtk_file_chooser_dialog_new("Save File", NULL, GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL),
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	if (m_data->c_host_manager->save_file_path == NULL) {
		gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");
		gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "kraken.xml");
	} else {
		gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), m_data->c_host_manager->save_file_path);
	}

	log_handler = g_log_set_handler(domain, G_LOG_LEVEL_WARNING, suppress_log_function, NULL);
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	g_log_remove_handler(domain, log_handler);

	if (response == GTK_RESPONSE_ACCEPT) {
		char *filename;
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		if (m_data->c_host_manager->save_file_path != NULL) {
			free(m_data->c_host_manager->save_file_path);
			m_data->c_host_manager->save_file_path = NULL;
		}
		m_data->c_host_manager->save_file_path = malloc(strlen(filename) + 1);
		strncpy(m_data->c_host_manager->save_file_path, filename, strlen(filename));
		m_data->c_host_manager->save_file_path[strlen(filename)] = '\0';
		response = export_host_manager_to_xml(m_data->c_host_manager, filename);
		if (response != 0) {
			GUI_POPUP_ERROR_EXPORT_FAILED(GTK_WINDOW(m_data->main_window));
			ret_val = -1;
		} else {
			ret_val = 1;
		}
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return ret_val;
}

void gui_menu_file_new_project(main_gui_data *m_data, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	gint response;

	if ((m_data->c_host_manager->known_hosts == 0) && (m_data->c_host_manager->known_whois_records == 0)) {
		return;
	}
	response = gui_popup_question_yes_no_cancel_dialog(GTK_WINDOW(m_data->main_window), "Save Current Project?", "Save Current Project?");
	if (response == GTK_RESPONSE_CANCEL) {
		return;
	} else if (response == GTK_RESPONSE_YES) {
		if (m_data->c_host_manager->save_file_path == NULL) {
			if (gui_menu_file_save_as_ex(m_data, action, widget) != 1) {
				return;
			}
		}
		response = export_host_manager_to_xml(m_data->c_host_manager, m_data->c_host_manager->save_file_path);
		if (response != 0) {
			GUI_POPUP_ERROR_EXPORT_FAILED(GTK_WINDOW(m_data->main_window));
		}
	}

	host_manager_destroy(m_data->c_host_manager); /* out with the old */
	host_manager_init(m_data->c_host_manager); /* in with the new */
	gui_model_update_tree_and_marquee(m_data, NULL);
	return;
}

void gui_export_csv(main_gui_data *m_data, guint action, GtkWidget *widget, const gchar *file_name, export_csv_opts *e_opts) {
	GtkWidget *dialog;
	guint log_handler;
	const char *domain = "Gtk";
	gint response;

	if ((m_data->c_host_manager->known_hosts == 0) && (m_data->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(GTK_WINDOW(m_data->main_window), "There Is No Data To Save", "Error: No Data");
		return;
	}
	dialog = gtk_file_chooser_dialog_new("Save File", NULL, GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL),
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), file_name);

	log_handler = g_log_set_handler(domain, G_LOG_LEVEL_WARNING, suppress_log_function, NULL);
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	g_log_remove_handler(domain, log_handler);

	if (response == GTK_RESPONSE_ACCEPT) {
		char *filename;

		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		response = export_host_manager_to_csv_ex(m_data->c_host_manager, filename, e_opts);
		g_free(filename);
		gtk_widget_destroy(dialog);
		if (response != 0) {
			GUI_POPUP_ERROR_EXPORT_FAILED(GTK_WINDOW(m_data->main_window));
		} else {
			gui_popup_info_dialog(GTK_WINDOW(m_data->main_window), "Successfully Exported Data", "Info: Export Successful");
		}
	} else {
		gtk_widget_destroy(dialog);
	}
	return;
}

void gui_menu_file_export_csv(main_gui_data *m_data, guint action, GtkWidget *widget) {
	export_csv_opts e_opts;

	export_csv_opts_init(&e_opts);
	gui_export_csv(m_data, action, widget, "kraken_export.csv", &e_opts);
	export_csv_opts_destroy(&e_opts);
	return;
}

void gui_menu_file_export_ips_list(main_gui_data *m_data, guint action, GtkWidget *widget) {
	export_csv_opts e_opts;

	export_csv_opts_init(&e_opts);
	strcpy((char *)&e_opts.secondary_delimiter, "\n");
	e_opts.show_fields = 0;
	e_opts.host_names = 0;
	e_opts.whois_cidr = 0;
	e_opts.whois_netname = 0;
	e_opts.whois_orgname = 0;
	gui_export_csv(m_data, action, widget, "kraken_export_ips.txt", &e_opts);
	export_csv_opts_destroy(&e_opts);
	return;
}

void gui_menu_file_export_hostnames_list(main_gui_data *m_data, guint action, GtkWidget *widget) {
	export_csv_opts e_opts;

	export_csv_opts_init(&e_opts);
	strcpy((char *)&e_opts.secondary_delimiter, "\n");
	e_opts.show_fields = 0;
	e_opts.host_ipv4_addr = 0;
	e_opts.whois_cidr = 0;
	e_opts.whois_netname = 0;
	e_opts.whois_orgname = 0;
	gui_export_csv(m_data, action, widget, "kraken_export_hostnames.txt", &e_opts);
	export_csv_opts_destroy(&e_opts);
	return;
}

void gui_menu_file_export_network_ranges(main_gui_data *m_data, guint action, GtkWidget *widget) {
	export_csv_opts e_opts;

	export_csv_opts_init(&e_opts);
	strcpy((char *)&e_opts.secondary_delimiter, "\n");
	e_opts.show_fields = 0;
	e_opts.host_names = 0;
	e_opts.host_ipv4_addr = 0;
	e_opts.whois_cidr = 1;
	e_opts.whois_netname = 0;
	e_opts.whois_orgname = 0;
	gui_export_csv(m_data, action, widget, "kraken_export_net_ranges.txt", &e_opts);
	export_csv_opts_destroy(&e_opts);
	return;
}

void gui_menu_file_open(main_gui_data *m_data, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	gint response;
	gboolean merge = FALSE;

	if ((m_data->c_host_manager->known_hosts > 0) || (m_data->c_host_manager->known_whois_records > 0)) {
		response = gui_popup_question_yes_no_dialog(GTK_WINDOW(m_data->main_window), "Merge With Existing Data?", "Merge?");
		if (response == GTK_RESPONSE_YES) {
			merge = TRUE;
		}
	}
	dialog = gtk_file_chooser_dialog_new("Open File", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		char *filename;
		if (merge == FALSE) {
			host_manager_destroy(m_data->c_host_manager); /* out with the old */
			host_manager_init(m_data->c_host_manager); /* in with the new */
		}
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		response = import_host_manager_from_xml(m_data->c_host_manager, filename);
		if (response != 0) {
			GUI_POPUP_ERROR_IMPORT_FAILED(GTK_WINDOW(m_data->main_window));
		}
		gui_model_update_tree_and_marquee(m_data, NULL);
		if (m_data->c_host_manager->save_file_path != NULL) {
			free(m_data->c_host_manager->save_file_path);
		}
		m_data->c_host_manager->save_file_path = malloc(strlen(filename) + 1);
		strncpy(m_data->c_host_manager->save_file_path, filename, strlen(filename));
		m_data->c_host_manager->save_file_path[strlen(filename)] = '\0';
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void gui_menu_file_save_as(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_menu_file_save_as_ex(m_data, action, widget);
	return;
}

void gui_menu_file_save(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gint response;

	if ((m_data->c_host_manager->known_hosts == 0) && (m_data->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(GTK_WINDOW(m_data->main_window), "There Is No Data To Save", "Error: No Data");
		return;
	}

	if (m_data->c_host_manager->save_file_path == NULL) {
		gui_menu_file_save_as_ex(m_data, action, widget);
		return;
	}
	response = export_host_manager_to_xml(m_data->c_host_manager, m_data->c_host_manager->save_file_path);
	if (response != 0) {
		GUI_POPUP_ERROR_EXPORT_FAILED(GTK_WINDOW(m_data->main_window));
	}
	return;
}

void gui_menu_edit_dns_enum_domain(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_dns_enum_domain(m_data);
	return;
}

void gui_menu_edit_dns_enum_network(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_dns_enum_network(m_data, NULL);
	return;
}

void gui_menu_edit_http_scan_all_for_links(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_scrape_hosts_for_links(m_data);
	return;
}

void gui_menu_edit_http_scrape_url_for_links(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_scrape_url_for_links(m_data, NULL);
	return;
}

void gui_menu_edit_http_search_bing_domain(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_search_engine_bing_domain(m_data);
}

void gui_menu_edit_http_search_bing_ip(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_search_engine_bing_ip(m_data, NULL);
}

void gui_menu_edit_http_search_bing_all_ips(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_search_engine_bing_all_ips(m_data, NULL);
}

void gui_menu_edit_preferences(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_manage_kraken_settings(m_data);
}

void gui_menu_view_console(main_gui_data *m_data, guint action, GtkWidget *widget) {
	if (GTK_CHECK_MENU_ITEM(widget)->active) {
		gtk_widget_show_all(m_data->plugin_box);
	} else {
		gtk_widget_hide_all(m_data->plugin_box);
	}
	return;
}

void gui_menu_view_expand_all(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gtk_tree_view_expand_all(GTK_TREE_VIEW(m_data->tree_view));
	return;
}

void gui_menu_view_collapse_all(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gtk_tree_view_collapse_all(GTK_TREE_VIEW(m_data->tree_view));
	return;
}

#ifdef KRAKEN_URI_WIKI
void gui_menu_help_wiki(main_gui_data *m_data, guint action, GtkWidget *widget) {
	GError *error = NULL;

	gtk_show_uri(NULL, KRAKEN_URI_WIKI, GDK_CURRENT_TIME, &error);
	return;
}
#endif

void gui_menu_help_about(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_help_about(m_data);
	return;
}

static GtkItemFactoryEntry main_menu_entries[] = {
	{ "/File",										NULL,			NULL,									0, 	"<Branch>"		},
	{ "/File/New Project",							NULL,			gui_menu_file_new_project,				0,	NULL			},
	{ "/File/",										NULL,			NULL,									0,	"<Separator>"	},
	{ "/File/Export",								NULL,			NULL,									0,	"<Branch>"		},
	{ "/File/Export/CSV",							NULL,			gui_menu_file_export_csv,				0,	NULL			},
	{ "/File/Export/IPs List",						NULL,			gui_menu_file_export_ips_list,			0,	NULL			},
	{ "/File/Export/Hostnames List",				NULL,			gui_menu_file_export_hostnames_list,	0,	NULL			},
	{ "/File/Export/Network Ranges",				NULL,			gui_menu_file_export_network_ranges,	0,	NULL			},
	{ "/File/",										NULL,			NULL,									0,	"<Separator>"	},
	{ "/File/Open",									"<CTRL>O",		gui_menu_file_open,						0,	NULL			},
	{ "/File/Save",									"<CTRL>S",		gui_menu_file_save,						0,	NULL			},
	{ "/File/Save As",								NULL,			gui_menu_file_save_as,					0,	NULL			},
	{ "/File/",										NULL,			NULL,									0,	"<Separator>"	},
	{ "/File/Quit",									"<CTRL>Q",		gtk_main_quit,							0, 	"<StockItem>",	GTK_STOCK_QUIT },
	{ "/Edit",										NULL,			NULL,									0,	"<Branch>"		},
	{ "/Edit/Add Hosts",							NULL,			NULL,									0,	"<Branch>"		},
	{ "/Edit/Add Hosts/DNS Forward Bruteforce",		NULL,			gui_menu_edit_dns_enum_domain, 			0,	NULL			},
	{ "/Edit/Add Hosts/DNS Reverse Bruteforce",		NULL,			gui_menu_edit_dns_enum_network, 		0,	NULL			},
	{ "/Edit/Add Hosts/HTTP Scan URL For Links",	NULL,			gui_menu_edit_http_scrape_url_for_links,	0,	NULL		},
	{ "/Edit/Add Hosts/HTTP Scan All For Links",	NULL,			gui_menu_edit_http_scan_all_for_links,	0,	NULL			},
	{ "/Edit/Add Hosts/HTTP Search Bing (Domain)",	NULL,			gui_menu_edit_http_search_bing_domain,	0,	NULL			},
	{ "/Edit/Add Hosts/HTTP Search Bing (Single IP Address)",	NULL,	gui_menu_edit_http_search_bing_ip,		0,	NULL		},
	{ "/Edit/Add Hosts/HTTP Search Bing (All IP Addresses)",	NULL,	gui_menu_edit_http_search_bing_all_ips,	0,	NULL		},
	{ "/Edit/",										NULL,			NULL,									0,	"<Separator>"	},
	{ "/Edit/Preferences",							NULL,			gui_menu_edit_preferences,				0,	NULL			},
	{ "/View",										NULL,			NULL,									0,	"<Branch>"		},
	{ "/View/Console",								NULL,			gui_menu_view_console,					0,	"<CheckItem>"	},
	{ "/View/",										NULL,			NULL,									0,	"<Separator>"	},
	{ "/View/Expand All",							NULL,			gui_menu_view_expand_all,				0,	NULL			},
	{ "/View/Collapse All",							NULL,			gui_menu_view_collapse_all,				0,	NULL			},
	{ "/Help",										NULL,			NULL,									0,	"<Branch>"		},
#ifdef KRAKEN_URI_WIKI
	{ "/Help/Wiki",									NULL,			gui_menu_help_wiki,						0,	NULL			},
#endif
	{ "/Help/About",								NULL,			gui_menu_help_about,					0, 	NULL			},
};

static gint nmain_menu_entries = sizeof(main_menu_entries) / sizeof(main_menu_entries[0]);

GtkWidget *gui_menu_get_main_menubar(GtkWidget  *window, gpointer userdata) {
	GtkItemFactory *item_factory;
	GtkAccelGroup *accel_group;
	GtkWidget *tmp_widget;

	/* Make an accelerator group (shortcut keys) */
	accel_group = gtk_accel_group_new();

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", accel_group);
	gtk_item_factory_create_items(item_factory, nmain_menu_entries, main_menu_entries, userdata);

	tmp_widget = gtk_item_factory_get_item(item_factory, "/View/Console");
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(tmp_widget), TRUE);

	gtk_window_add_accel_group(GTK_WINDOW(window), accel_group);

	return gtk_item_factory_get_widget(item_factory, "<main>");
}
