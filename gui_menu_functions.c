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
	{ "/File/Save As",							NULL,		gui_menu_file_save_as,			0,	NULL	},
	{ "/File/Quit",								"<CTRL>Q",	gtk_main_quit,					0, 	"<StockItem>",	GTK_STOCK_QUIT },
	{ "/Edit",									NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add Hosts",						NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add Hosts/DNS Forward Bruteforce",	NULL,		gui_menu_edit_dns_forward_bf, 	0,	NULL	},
	{ "/Edit/Add Hosts/DNS Reverse Bruteforce",	NULL,		gui_menu_edit_dns_reverse_bf, 	0,	NULL	},
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

void gui_menu_file_save_as(main_gui_data *userdata, guint action, GtkWidget *widget) {
	GtkWidget *dialog;
	guint log_handler;
	const char *domain = "Gtk";
	gint response;
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
		strncpy(userdata->c_host_manager->save_file_path, filename, (strlen(filename) + 1));
		response = export_host_manager_to_xml(userdata->c_host_manager, filename);
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void gui_menu_edit_dns_forward_bf(main_gui_data *userdata, guint action, GtkWidget *widget) {
	gui_popup_bf_domain(userdata);
	return;
}

void gui_menu_edit_dns_reverse_bf(main_gui_data *userdata, guint action, GtkWidget *widget) {
	gui_popup_bf_network(userdata, NULL);
	return;
}
