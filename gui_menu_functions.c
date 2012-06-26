#include <stdlib.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <string.h>
#include "export.h"
#include "gui_menu_functions.h"
#include "gui_model.h"
#include "gui_popups.h"
#include "hosts.h"
#include "host_manager.h"

static GtkItemFactoryEntry main_menu_entries[] = {
	{ "/File",									NULL,		NULL,							0, 	"<Branch>" },
	{ "/File/Export",							NULL,		NULL,							0,	"<Branch>" },
	{ "/File/Export/CSV",						NULL,		gui_menu_file_export_csv,		0,	NULL		},
	{ "/File/",									NULL,		NULL,							0,	"<Separator>"	},
	{ "/File/Open",								NULL,		gui_menu_file_open,				0,	NULL	},
	{ "/File/Save",								"<CTRL>S",	gui_menu_file_save,				0,	NULL	},
	{ "/File/Save As",							NULL,		gui_menu_file_save_as,			0,	NULL	},
	{ "/File/",									NULL,		NULL,							0,	"<Separator>"	},
	{ "/File/Quit",								"<CTRL>Q",	gtk_main_quit,					0, 	"<StockItem>",	GTK_STOCK_QUIT },
	{ "/Edit",									NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add Hosts",						NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add Hosts/DNS Forward Bruteforce",	NULL,		gui_menu_edit_dns_forward_bf, 	0,	NULL	},
	{ "/Edit/Add Hosts/DNS Reverse Bruteforce",	NULL,		gui_menu_edit_dns_reverse_bf, 	0,	NULL	},
	{ "/Edit/Add Hosts/HTTP Scan Host For Links",	NULL,	gui_menu_edit_http_scan_host_for_links,	0,	NULL	},
	{ "/Edit/Add Hosts/HTTP Scan All For Links",	NULL,	gui_menu_edit_http_scan_all_for_links,	0,	NULL	},
	{ "/Edit/Add Hosts/HTTP Search Bing",		NULL,		gui_menu_edit_http_search_bing,		0,	NULL	},
	{ "/Edit/",									NULL,		NULL,							0,	"<Separator>"	},
	{ "/Edit/Preferences",						NULL,		gui_menu_edit_preferences,		0,	NULL	},
};

static gint nmain_menu_entries = sizeof(main_menu_entries) / sizeof(main_menu_entries[0]);

static void suppress_log_function(G_GNUC_UNUSED const gchar *log_domain, G_GNUC_UNUSED GLogLevelFlags log_level, G_GNUC_UNUSED const gchar *message, G_GNUC_UNUSED gpointer user_data) {
	/* suppress the message */
	/* https://bugzilla.gnome.org/show_bug.cgi?id=662814 */
}

GtkWidget *get_main_menubar(GtkWidget  *window, gpointer userdata) {
	GtkItemFactory *item_factory;
	GtkAccelGroup *accel_group;

	/* Make an accelerator group (shortcut keys) */
	accel_group = gtk_accel_group_new();

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU_BAR, "<main>", accel_group);
	gtk_item_factory_create_items(item_factory, nmain_menu_entries, main_menu_entries, userdata);
	gtk_window_add_accel_group(GTK_WINDOW(window), accel_group);

	return gtk_item_factory_get_widget(item_factory, "<main>");
}

void gui_menu_file_export_csv(main_gui_data *userdata, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	guint log_handler;
	const char *domain = "Gtk";
	gint response;
	if ((userdata->c_host_manager->known_hosts == 0) && (userdata->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(NULL, "There Is No Data To Save", "Error: No Data");
		return;
	}
	dialog = gtk_file_chooser_dialog_new("Save File", NULL, GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL),
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "kraken_export.csv");
	
	log_handler = g_log_set_handler(domain, G_LOG_LEVEL_WARNING, suppress_log_function, NULL);
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	g_log_remove_handler(domain, log_handler);
	
	if (response == GTK_RESPONSE_ACCEPT) {
		char *filename;
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		response = export_host_manager_to_csv(userdata->c_host_manager, filename);
		if (response != 0) {
			GUI_POPUP_ERROR_EXPORT_FAILED(NULL);
		} else {
			gui_popup_info_dialog(NULL, "Successfully Exported Data", "Info: Export Successful");
		}
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void gui_menu_file_open(main_gui_data *userdata, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	gint response;
	gboolean merge = FALSE;
	if ((userdata->c_host_manager->known_hosts > 0) || (userdata->c_host_manager->known_whois_records > 0)) {
		response = gui_popup_question_yes_no_dialog(NULL, "Merge With Existing Data?", "Merge?");
		if (response == GTK_RESPONSE_NO) {
			merge = TRUE;
		}
	}
	dialog = gtk_file_chooser_dialog_new("Open File", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		char *filename;
		if (merge == TRUE) {
			destroy_host_manager(userdata->c_host_manager); /* out with the old */
			init_host_manager(userdata->c_host_manager); /* in with the new */
		}
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		response = import_host_manager_from_xml(userdata->c_host_manager, filename);
		if (response != 0) {
			GUI_POPUP_ERROR_IMPORT_FAILED(NULL);
		}
		gui_model_update_tree_and_marquee(userdata, NULL);
		if (userdata->c_host_manager->save_file_path != NULL) {
			free(userdata->c_host_manager->save_file_path);
		}
		userdata->c_host_manager->save_file_path = malloc(strlen(filename) + 1);
		userdata->c_host_manager->save_file_path[strlen(filename)] = '\0';
		strncpy(userdata->c_host_manager->save_file_path, filename, (strlen(filename) + 1));
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void gui_menu_file_save(main_gui_data *userdata, guint action, GtkWidget *widget) {
	gint response;
	if ((userdata->c_host_manager->known_hosts == 0) && (userdata->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(NULL, "There Is No Data To Save", "Error: No Data");
		return;
	}
	if (userdata->c_host_manager->save_file_path == NULL) {
		gui_menu_file_save_as(userdata, action, widget);
		return;
	}
	
	response = export_host_manager_to_xml(userdata->c_host_manager, userdata->c_host_manager->save_file_path);
	if (response != 0) {
		GUI_POPUP_ERROR_EXPORT_FAILED(NULL);
	}
	return;
}

void gui_menu_file_save_as(main_gui_data *userdata, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	guint log_handler;
	const char *domain = "Gtk";
	gint response;
	if ((userdata->c_host_manager->known_hosts == 0) && (userdata->c_host_manager->known_whois_records == 0)) {
		gui_popup_error_dialog(NULL, "There Is No Data To Save", "Error: No Data");
		return;
	}
	dialog = gtk_file_chooser_dialog_new("Save File", NULL, GTK_FILE_CHOOSER_ACTION_SAVE, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT, NULL),
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	if (userdata->c_host_manager->save_file_path == NULL) {
		gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");
		gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "kraken.xml");
	} else {
		gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(dialog), userdata->c_host_manager->save_file_path);
	}
	
	log_handler = g_log_set_handler(domain, G_LOG_LEVEL_WARNING, suppress_log_function, NULL);
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	g_log_remove_handler(domain, log_handler);
	
	if (response == GTK_RESPONSE_ACCEPT) {
		char *filename;
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		if (userdata->c_host_manager->save_file_path != NULL) {
			free(userdata->c_host_manager->save_file_path);
			userdata->c_host_manager->save_file_path = NULL;
		}
		userdata->c_host_manager->save_file_path = malloc(strlen(filename) + 1);
		strncpy(userdata->c_host_manager->save_file_path, filename, strlen(filename));
		userdata->c_host_manager->save_file_path[strlen(filename)] = '\0';
		response = export_host_manager_to_xml(userdata->c_host_manager, filename);
		if (response != 0) {
			GUI_POPUP_ERROR_EXPORT_FAILED(NULL);
		}
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void gui_menu_edit_dns_forward_bf(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_dns_bf_domain(m_data);
	return;
}

void gui_menu_edit_dns_reverse_bf(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_dns_bf_network(m_data, NULL);
	return;
}

void gui_menu_edit_http_scan_all_for_links(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_scan_all_for_links(m_data);
	return;
}

void gui_menu_edit_http_scan_host_for_links(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_http_scan_host_for_links(m_data, NULL);
	return;
}

void gui_menu_edit_http_search_bing(main_gui_data *m_data, guint action, GtkWidget *widget) {
	if (m_data->k_opts->bing_api_key == NULL) {
		gui_popup_error_dialog(NULL, "Bing API Key Not Set", "Error: Invalid API Key");
	} else {
		gui_popup_http_search_bing(m_data);
	}
}

void gui_menu_edit_preferences(main_gui_data *m_data, guint action, GtkWidget *widget) {
	gui_popup_manage_kraken_settings(m_data);
}
