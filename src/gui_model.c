#include "kraken.h"

#include <stdlib.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <string.h>

#include "gui_model.h"
#include "gui_menu_functions.h"
#include "gui_popups.h"
#include "host_manager.h"
#include "http_scan.h"
#include "whois_lookup.h"

enum {
	COL_HOSTNAME = 0,
	COL_IPADDR,
	COL_WHO_BESTNAME,
	NUM_COLS
};

enum {
	SORTID_HOSTNAME = 0,
	SORTID_IPADDR,
	SORTID_WHO_ORGNAME,
};

void view_popup_menu_onDoDNSBruteforceDomain(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *name = NULL;
	char *domain = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	gtk_tree_model_get(model, &iter, COL_HOSTNAME, &name, -1);
	if (name != NULL) {
		domain = dns_get_domain(name);
		if (domain != NULL) {
			strncpy(m_data->c_host_manager->lw_domain, domain, DNS_MAX_FQDN_LENGTH);
		}
		g_free(name);
	}
	gui_popup_dns_enum_domain(m_data);
	return;
}

void view_popup_menu_onDoDNSBruteforceNetwork(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeIter piter;
	struct in_addr target_ip;
	single_host_info *c_host = NULL;
	gchar *ipstr = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (gtk_tree_model_iter_parent(model, &piter, &iter)) {
		gtk_tree_model_get(model, &piter, COL_IPADDR, &ipstr, -1);
	} else {
		gtk_tree_model_get(model, &iter, COL_IPADDR, &ipstr, -1);
	}
	inet_pton(AF_INET, (char *)ipstr, &target_ip);
	g_free(ipstr);
	host_manager_get_host_by_addr(m_data->c_host_manager, &target_ip, &c_host);
	if ((c_host == NULL) || (c_host->whois_data == NULL)) {
		return;
	}
	gui_popup_dns_enum_network(m_data, c_host->whois_data->cidr_s);
	return;
}

void view_popup_menu_onDoHttpScanLinks(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeIter piter;
	http_link *link_anchor = NULL;
	struct in_addr ip;
	int ret_val = 0;
	gchar *name = NULL;
	gchar *ipstr = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive selection from tree")
		return;
	}
	if (gtk_tree_model_iter_parent(model, &piter, &iter)) {
		gtk_tree_model_get(model, &piter, COL_IPADDR, &ipstr, -1);
		if (ipstr == NULL) {
			LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
			return;
		}
		gtk_tree_model_get(model, &iter, COL_HOSTNAME, &name, -1);
		if (name == NULL) {
			LOGGING_QUICK_WARNING("kraken.gui.model", "could not retreive host name");
			name = ipstr;
		}
		inet_pton(AF_INET, ipstr, &ip);
		ret_val = http_scrape_ip_for_links(name, &ip, "/", &link_anchor);
	} else {
		gtk_tree_model_get(model, &piter, COL_IPADDR, &ipstr, -1);
		if (ipstr == NULL) {
			LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
			return;
		}
		inet_pton(AF_INET, ipstr, &ip);
		ret_val = http_scrape_ip_for_links("", &ip, "/", &link_anchor);
	}
	inet_pton(AF_INET, ipstr, &ip);
	ret_val = http_scrape_ip_for_links(name, &ip, "/", &link_anchor);
	if ((name != NULL) && (name != ipstr)) {
		g_free(name);
	}
	g_free(ipstr);
	if (ret_val) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "there was an error requesting the page")
	} else {
		host_manager_set_host_status(m_data->c_host_manager, &ip, KRAKEN_HOST_UP);
	}
	gui_popup_select_hosts_from_http_links(m_data, link_anchor);
	http_free_link(link_anchor);
	return;
}

void view_popup_menu_onDelete(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeIter piter;
	struct in_addr ip;
	gint response;
	gchar *ipstr = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive selection from tree")
		return;
	}
	if (gtk_tree_model_iter_parent(model, &piter, &iter)) {
		gtk_tree_model_get(model, &piter, COL_IPADDR, &ipstr, -1);
	} else {
		gtk_tree_model_get(model, &iter, COL_IPADDR, &ipstr, -1);
	}
	if (ipstr == NULL) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
		return;
	}
	inet_pton(AF_INET, ipstr, &ip);
	response = GUI_POPUP_QUESTION_SURE(NULL);
	if (response) {
		host_manager_delete_host_by_ip(m_data->c_host_manager, &ip);
		gui_model_update_tree_and_marquee(m_data, NULL);
	}
	g_free(ipstr);
	return;
}

void view_popup_menu(GtkWidget *treeview, GdkEventButton *event, gpointer m_data) {
	GtkWidget *menu, *menuitem;
	menu = gtk_menu_new();

	menuitem = gtk_menu_item_new_with_label("DNS Bruteforce Domain");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDoDNSBruteforceDomain, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_menu_item_new_with_label("DNS Bruteforce Network");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDoDNSBruteforceNetwork, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_menu_item_new_with_label("HTTP Scan For Links");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDoHttpScanLinks, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_menu_item_new_with_label("Delete");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDelete, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	gtk_widget_show_all(menu);
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, (event != NULL) ? event->button : 0, gdk_event_get_time((GdkEvent*)event));
	return;
}

gboolean view_onButtonPressed(GtkWidget *treeview, GdkEventButton *event, gpointer userdata) {
	GtkTreeSelection *selection;
	if (event->type == GDK_BUTTON_PRESS && event->button == 3) {
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
		if (gtk_tree_selection_count_selected_rows(selection) != 0) {
			GtkTreePath *path;
			if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), (gint)event->x, (gint)event->y, &path, NULL, NULL, NULL)) {
				gtk_tree_selection_unselect_all(selection);
				gtk_tree_selection_select_path(selection, path);
				gtk_tree_path_free(path);
			}
			view_popup_menu(treeview, event, userdata);
		}
		return TRUE;
	}
	return FALSE;
}

void gui_model_update_marquee(main_gui_data *m_data, const char *status) {
	GtkWidget *label;
	char msg[GUI_MODEL_MAX_MARQUEE_MSG_SIZE + 1];

	gtk_container_foreach(GTK_CONTAINER(m_data->main_marquee), (GtkCallback)gtk_widget_destroy, NULL);

	if (status != NULL) {
		snprintf(msg, GUI_MODEL_MAX_MARQUEE_MSG_SIZE, "Status: %s", status);
	} else {
		strcpy(msg, "Status: Waiting");
	}
	label = gtk_label_new(msg);
	gtk_box_pack_start(GTK_BOX(m_data->main_marquee), label, FALSE, TRUE, 5);
	gtk_widget_show(label);

	snprintf(msg, GUI_MODEL_MAX_MARQUEE_MSG_SIZE, "Hosts: %u Networks: %u", m_data->c_host_manager->known_hosts, m_data->c_host_manager->known_whois_records);
	label = gtk_label_new(msg);
	gtk_box_pack_end(GTK_BOX(m_data->main_marquee), label, FALSE, TRUE, 5);
	gtk_widget_show(label);

	while (gtk_events_pending()) {
		gtk_main_iteration();
	}
	return;
}

int gui_model_update_tree_and_marquee(main_gui_data *m_data, const char *status) {
	GtkTreeModel *model;

	model = gui_refresh_tree_model(NULL, m_data->c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(m_data->tree_view), model);
	gui_model_update_marquee(m_data, status);
	while (gtk_events_pending()) {
		gtk_main_iteration();
	}
	return 0;
}

GtkTreeModel *gui_refresh_tree_model(GtkTreeStore *store, host_manager *c_host_manager) {
	GtkTreeIter ipiter;
	GtkTreeIter nameiter;
	GtkTreeModel *treemodel;
	host_iter host_i;
	single_host_info *c_host;
	char ipstr[INET_ADDRSTRLEN];
	hostname_iter hostname_i;
	char *hostname;
	char n_names_str[18];

	if (store == NULL) {
		store = gtk_tree_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	}

	treemodel = GTK_TREE_MODEL(store);
	gtk_tree_model_get_iter_first(treemodel, &ipiter);
	host_manager_iter_host_init(c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
		gtk_tree_store_append(store, &ipiter, NULL);
		gtk_tree_store_set(store, &ipiter, COL_IPADDR, ipstr, -1);
		if (c_host->n_names == 1) {
			gtk_tree_store_set(store, &ipiter, COL_HOSTNAME, c_host->names[0], -1);
		} else if (c_host->n_names > 1) {
			sprintf(n_names_str, "[ %u Hostnames ]", c_host->n_names);
			gtk_tree_store_set(store, &ipiter, COL_HOSTNAME, n_names_str, -1);
			single_host_iter_hostname_init(c_host, &hostname_i);
			while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
				gtk_tree_store_append(store, &nameiter, &ipiter);
				gtk_tree_store_set(store, &nameiter, COL_HOSTNAME, hostname, -1);
			}
		}
		if (c_host->whois_data != NULL) {
			gtk_tree_store_set(store, &ipiter, COL_WHO_BESTNAME, whois_get_best_name(c_host->whois_data), -1);
		} else {
			gtk_tree_store_set(store, &ipiter, COL_WHO_BESTNAME, "", -1);
		}
	}
	return GTK_TREE_MODEL(store);
}

GtkWidget *create_view_and_model(host_manager *c_host_manager, main_gui_data *m_data) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkWidget *view;
	GtkTreeStore *store;

	view = gtk_tree_view_new();
	store = gtk_tree_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	model = gui_refresh_tree_model(NULL, c_host_manager);
	g_signal_connect(view, "button-press-event", (GCallback)view_onButtonPressed, m_data);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_IPADDR);
	gtk_tree_view_column_set_title(col, "IP Address");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_IPADDR);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_HOSTNAME);
	gtk_tree_view_column_set_title(col, "Hostname");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_HOSTNAME);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_WHO_BESTNAME);
	gtk_tree_view_column_set_title(col, "WHOIS");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_WHO_ORGNAME);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	g_object_unref(model);
	return view;
}
