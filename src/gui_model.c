#include <stdlib.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <string.h>
#include "gui_model.h"
#include "gui_menu_functions.h"
#include "gui_popups.h"
#include "kraken.h"
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

	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gchar *name;
		char *domain = NULL;
		gtk_tree_model_get(model, &iter, COL_HOSTNAME, &name, -1);
		if (name != NULL) {
			domain = dns_get_domain(name);
			if (domain != NULL) {
				strncpy(m_data->c_host_manager->lw_domain, domain, DNS_MAX_FQDN_LENGTH);
			}
			g_free(name);
		}
	} else {
		return;
	}
	
	gui_popup_dns_enum_domain(m_data);
	return;
}

void view_popup_menu_onDoDNSBruteforceNetwork(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	struct in_addr target_ip;
	whois_record *who_r = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gchar *name;
		gtk_tree_model_get(model, &iter, COL_IPADDR, &name, -1);
		inet_pton(AF_INET, (char *)name, &target_ip);
		g_free(name);
		host_manager_get_whois(m_data->c_host_manager, &target_ip, &who_r);
	} else {
		return;
	}
	if (who_r == NULL) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retrieve the desired whois record")
		return;
	}
	
	gui_popup_dns_enum_network(m_data, who_r->cidr_s);
	return;
}

void view_popup_menu_onDoHttpScanLinks(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	http_link *link_anchor = NULL;
	struct in_addr ip;
	int ret_val = 0;

	selection = gtk_tree_view_get_selection(treeview);
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
		gchar *name;
		gchar *ipstr;
		gtk_tree_model_get(model, &iter, COL_IPADDR, &ipstr, -1);
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
		if (name != ipstr) {
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
	}
	return;
}

void view_popup_menu_onDelete(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	struct in_addr ip;
	gint response;
	
	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive selection from tree")
		return;
	}
	gchar *name;
	gchar *ipstr;
	gtk_tree_model_get(model, &iter, COL_IPADDR, &ipstr, COL_HOSTNAME, &name, -1);
	if (ipstr == NULL) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
		return;
	}
	if (name == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.model", "could not retreive host name");
		return;
	}
	inet_pton(AF_INET, ipstr, &ip);
	response = GUI_POPUP_QUESTION_SURE(NULL);
	if (response) {
		host_manager_delete_host(m_data->c_host_manager, name, &ip);
		gui_model_update_tree_and_marquee(m_data, NULL);
	}
	g_free(name);
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

GtkTreeModel *gui_refresh_tree_model(GtkListStore *store, host_manager *c_host_manager) {
	GtkTreeIter iter;
	unsigned int current_host_i;
	single_host_info *current_host;
	whois_record *who_data;
	char ipstr[INET_ADDRSTRLEN];
	
	if (store == NULL) {
		store = gtk_list_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	}
	
	/* append a row and fill data */
	for (current_host_i = 0; current_host_i < c_host_manager->known_hosts; current_host_i++) {
		current_host = &c_host_manager->hosts[current_host_i];
		inet_ntop(AF_INET, &current_host->ipv4_addr, ipstr, sizeof(ipstr));
		gtk_list_store_append(store, &iter);
		if (current_host->whois_data != NULL) {
			who_data = current_host->whois_data;
			gtk_list_store_set(store, &iter, COL_HOSTNAME, current_host->hostname, COL_IPADDR, ipstr, COL_WHO_BESTNAME, whois_get_best_name(who_data), -1);
		} else {
			host_manager_get_whois(c_host_manager, &current_host->ipv4_addr, &who_data); /* double check */
			if (who_data == NULL) {
				gtk_list_store_set(store, &iter, COL_HOSTNAME, current_host->hostname, COL_IPADDR, ipstr, COL_WHO_BESTNAME, "", -1);
			} else {
				current_host->whois_data = who_data;
				gtk_list_store_set(store, &iter, COL_HOSTNAME, current_host->hostname, COL_IPADDR, ipstr, COL_WHO_BESTNAME, whois_get_best_name(who_data), -1);
			}
		}
	}
	
	return GTK_TREE_MODEL(store);
}

GtkWidget *create_view_and_model(host_manager *c_host_manager, main_gui_data *m_data) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkWidget *view;
	
	view = gtk_tree_view_new();
	g_signal_connect(view, "button-press-event", (GCallback)view_onButtonPressed, m_data);
	
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
	gtk_tree_view_column_add_attribute (col, renderer, "text", COL_WHO_BESTNAME);
	gtk_tree_view_column_set_title (col, "WHOIS");
	gtk_tree_view_column_set_sort_column_id(col, SORTID_WHO_ORGNAME);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	model = gui_refresh_tree_model(NULL, c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	g_object_unref(model);
	return view;
}
