#include <gtk/gtk.h>
#include <arpa/inet.h>
#include "hosts.h"
#include "host_manager.h"
#include "whois_lookup.h"

enum {
	COL_HOSTNAME = 0,
	COL_IPADDR,
	COL_WHO_ORGNAME,
	NUM_COLS
};

enum {
	SORTID_HOSTNAME = 0,
	SORTID_IPADDR,
	SORTID_WHO_ORGNAME,
};

static GtkItemFactoryEntry main_menu_entries[] = {
	{ "/_File",			NULL,		NULL,			0, 	"<Branch>" },
	{ "/File/_Quit",	"<CTRL>Q",	gtk_main_quit,	0, 	"<StockItem>",	GTK_STOCK_QUIT }
};

static gint nmain_menu_entries = sizeof(main_menu_entries) / sizeof(main_menu_entries[0]);

void view_popup_menu_onDoSomething(GtkWidget *menuitem, gpointer userdata) {
	GtkTreeView *treeview = GTK_TREE_VIEW(userdata);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;

	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gchar *name;
		gtk_tree_model_get(model, &iter, COL_IPADDR, &name, -1);
		g_print("DEBUG: selected row is: %s\n", name);
		g_free(name);
	}
	/* else no row selected */
	return;
}

void view_popup_menu(GtkWidget *treeview, GdkEventButton *event, gpointer userdata) {
	GtkWidget *menu, *menuitem;
	menu = gtk_menu_new();
	menuitem = gtk_menu_item_new_with_label("Show WHOIS Data");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDoSomething, treeview);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);
	gtk_widget_show_all(menu);
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, (event != NULL) ? event->button : 0, gdk_event_get_time((GdkEvent*)event));
	return;
}

gboolean view_onButtonPressed(GtkWidget *treeview, GdkEventButton *event, gpointer userdata) {
	if (event->type == GDK_BUTTON_PRESS && event->button == 3) {
		if (1) {
			GtkTreeSelection *selection;
			selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
			if (gtk_tree_selection_count_selected_rows(selection) <= 1) {
				GtkTreePath *path;
				if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), (gint)event->x, (gint)event->y, &path, NULL, NULL, NULL)) {
					gtk_tree_selection_unselect_all(selection);
					gtk_tree_selection_select_path(selection, path);
					gtk_tree_path_free(path);
				}
			}
		}
		view_popup_menu(treeview, event, userdata);
		return TRUE;
	}
	return FALSE;
}

gboolean view_onPopupMenu(GtkWidget *treeview, gpointer userdata) {
	view_popup_menu(treeview, NULL, userdata);
	return TRUE;
}

static GtkTreeModel *create_and_fill_model(host_manager *c_host_manager) {
	GtkListStore *store;
	GtkTreeIter iter;
	unsigned int current_host_i;
	single_host_info *current_host;
	whois_record *who_data;
	char ipstr[INET_ADDRSTRLEN];
	
	store = gtk_list_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	
	/* append a row and fill data */
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		current_host = &c_host_manager->hosts[current_host_i];
		inet_ntop(AF_INET, &current_host->ipv4_addr, ipstr, sizeof(ipstr));
		gtk_list_store_append(store, &iter);
		if (current_host->whois_data != NULL) {
			who_data = current_host->whois_data;
			gtk_list_store_set(store, &iter, COL_HOSTNAME, current_host->hostname, COL_IPADDR, ipstr, COL_WHO_ORGNAME, who_data->orgname, -1);
		} else {
			gtk_list_store_set(store, &iter, COL_HOSTNAME, current_host->hostname, COL_IPADDR, ipstr, COL_WHO_ORGNAME, "", -1);
		}
	}
	
	return GTK_TREE_MODEL(store);
}

static GtkWidget *create_view_and_model(host_manager *c_host_manager) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkWidget *view;
	
	view = gtk_tree_view_new();
	g_signal_connect(view, "button-press-event", (GCallback)view_onButtonPressed, NULL);
	g_signal_connect(view, "popup-menu", (GCallback)view_onPopupMenu, NULL);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", COL_HOSTNAME);
	gtk_tree_view_column_set_title (col, "Hostname");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_HOSTNAME);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", COL_IPADDR);
	gtk_tree_view_column_set_title (col, "IP Address");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_IPADDR);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", COL_WHO_ORGNAME);
	gtk_tree_view_column_set_title (col, "WHOIS Organization");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_WHO_ORGNAME);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	model = create_and_fill_model(c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	g_object_unref(model);
	return view;
}

static GtkWidget *get_main_menubar(GtkWidget  *window) {
	GtkItemFactory *item_factory;
	GtkAccelGroup *accel_group;

	/* Make an accelerator group (shortcut keys) */
	accel_group = gtk_accel_group_new ();

	item_factory = gtk_item_factory_new (GTK_TYPE_MENU_BAR, "<main>", accel_group);
	gtk_item_factory_create_items (item_factory, nmain_menu_entries, main_menu_entries, NULL);

	gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);

	return gtk_item_factory_get_widget (item_factory, "<main>");
}

int gui_show_host_manager(host_manager *c_host_manager) {
	GtkWidget *window;
	GtkWidget *scroll_window;
	GtkWidget *main_vbox;
	GtkWidget *main_menu_bar;
	GtkWidget *view;
	
	gtk_init(NULL, NULL);
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);	
	g_signal_connect(window, "delete_event", gtk_main_quit, NULL); /* dirty */
	gtk_window_set_title(GTK_WINDOW(window), "Kraken");
	gtk_container_set_border_width(GTK_CONTAINER(window), 0);
	gtk_widget_set_size_request(window, 600, 850);
	
	main_vbox = gtk_vbox_new(FALSE, 1);
	gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
	gtk_container_add(GTK_CONTAINER(window), main_vbox);
	
	scroll_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll_window), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	
	main_menu_bar = get_main_menubar(window);
	
	view = create_view_and_model(c_host_manager);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll_window), view);
	
	gtk_box_pack_start(GTK_BOX (main_vbox), main_menu_bar, FALSE, TRUE, 0);
	gtk_box_pack_end(GTK_BOX(main_vbox), scroll_window, TRUE, TRUE, 0);
	
	gtk_widget_show_all(window);
	gtk_main();
	return 0;
}

