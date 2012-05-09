#include <gtk/gtk.h>
#include <arpa/inet.h>
#include "gui_menu_functions.h"
#include "gui_model.h"
#include "gui_popups.h"
#include "hosts.h"
#include "host_manager.h"
#include "whois_lookup.h"
#include "dns_enum.h"

static GtkItemFactoryEntry main_menu_entries[] = {
	{ "/_File",								NULL,		NULL,							0, 	"<Branch>" },
	{ "/File/_Quit",						"<CTRL>Q",	gtk_main_quit,					0, 	"<StockItem>",	GTK_STOCK_QUIT },
	{ "/_Edit",								NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add",							NULL,		NULL,							0,	"<Branch>" },
	{ "/Edit/Add/DNS Forward Bruteforce",	NULL,		gui_menu_edit_dns_forward_bf, 	0,	NULL	},
	{ "/Edit/Add/DNS Reverse Bruteforce",	NULL,		gui_menu_edit_dns_reverse_bf, 	0,	NULL	},
};

static gint nmain_menu_entries = sizeof(main_menu_entries) / sizeof(main_menu_entries[0]);

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

void gui_menu_edit_dns_forward_bf(menu_data *userdata, guint action, GtkWidget *widget) {
	gui_popup_bf_domain(userdata->tree_view, userdata->c_host_manager);
	return;
}

void gui_menu_edit_dns_reverse_bf(menu_data *userdata, guint action, GtkWidget *widget) {
	gui_popup_bf_network(userdata->tree_view, userdata->c_host_manager);
	return;
}
