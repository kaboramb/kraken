// gui_model.c
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

#include "plugins.h"
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
	COL_IPADDR_BGCOLOR,
	COL_IPADDR_BGCOLOR_SET,
	NUM_COLS
};

enum {
	SORTID_HOSTNAME = 0,
	SORTID_IPADDR,
	SORTID_WHO_ORGNAME
};

void callback_thread_view_popup_menu_plugins(gui_data_menu_plugin *gp_data) {
	char error_msg[64];
	kstatus_plugin ret_val;

	gdk_threads_enter();
	gui_model_update_marquee(gp_data->m_data, "Running Plugin");
	gdk_threads_leave();

	ret_val = plugins_plugin_run_callback(gp_data->c_plugin, gp_data->callback_id, gp_data->plugin_data, error_msg, sizeof(error_msg));
	whois_fill_host_manager(gp_data->m_data->c_host_manager);

	gdk_threads_enter();
	if (KSTATUS_PLUGIN_IS_ERROR(ret_val)) {
		gui_popup_error_dialog_plugin(gp_data->m_data->main_window, ret_val, error_msg);
	}
	gui_model_update_tree_and_marquee(gp_data->m_data, NULL);
	gui_model_update_marquee(gp_data->m_data, NULL);
	gdk_threads_leave();

	kraken_thread_mutex_unlock(&gp_data->m_data->plugin_mutex);
	free(gp_data);
	return;
}

int gui_model_get_host_info_from_tree_iter(GtkTreeModel *model, GtkTreeIter *iter, main_gui_data *m_data, single_host_info **c_host, gchar **ipstr, gchar **name) {
	GtkTreeIter piter;
	gchar *lipstr = NULL;
	gchar *lname = NULL;
	single_host_info *lc_host = NULL;
	struct in_addr ip;

	if (gtk_tree_model_iter_parent(model, &piter, iter)) {
		gtk_tree_model_get(model, &piter, COL_IPADDR, &lipstr, -1);
		if (lipstr == NULL) {
			LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
			return 0;
		}
		gtk_tree_model_get(model, iter, COL_HOSTNAME, &lname, -1);
		if (lname == NULL) {
			LOGGING_QUICK_WARNING("kraken.gui.model", "could not retreive hostname");
			g_free(lipstr);
			return 0;
		}
	} else {
		gtk_tree_model_get(model, iter, COL_IPADDR, &lipstr, -1);
		if (lipstr == NULL) {
			LOGGING_QUICK_ERROR("kraken.gui.model", "could not retreive the IP address");
			return 0;
		}
		if (!gtk_tree_model_iter_has_child(model, iter)) {
			gtk_tree_model_get(model, iter, COL_HOSTNAME, &lname, -1);
		}
	}

	if (!inet_pton(AF_INET, lipstr, &ip)) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "the IP address was malformed from the GTK tree");
		if (lname != NULL) {
			g_free(lname);
		}
		g_free(lipstr);
		return 0;
	}
	if (!host_manager_get_host_by_addr(m_data->c_host_manager, &ip, &lc_host)) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "failed to retrieve the host information")
		if (lname != NULL) {
			g_free(lname);
		}
		g_free(lipstr);
		return 0;
	}

	if (c_host != NULL) {
		*c_host = lc_host;
	}
	if (name != NULL) {
		if (lname == NULL) {
			g_free(lipstr);
			return 0;
		}
		*name = lname;
	} else {
		if (lname != NULL) {
			g_free(lname);
		}
	}
	if (ipstr != NULL) {
		*ipstr = lipstr;
	} else {
		g_free(lipstr);
	}
	return 1;
}

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
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, NULL, NULL, &name)) {
		return;
	}
	domain = dns_get_domain(name);
	if (domain != NULL) {
		strncpy(m_data->c_host_manager->lw_domain, domain, DNS_MAX_FQDN_LENGTH);
	}
	g_free(name);
	gui_popup_dns_enum_domain(m_data);
	return;
}

void view_popup_menu_onDoDNSBruteforceNetwork(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	single_host_info *c_host = NULL;
	gchar *name = NULL;
	char *domain = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, NULL, &name)) {
		return;
	}
	if (c_host->whois_data == NULL) {
		return;
	}
	domain = dns_get_domain(name);
	if (domain != NULL) {
		strncpy(m_data->c_host_manager->lw_domain, domain, DNS_MAX_FQDN_LENGTH);
	}
	g_free(name);
	gui_popup_dns_enum_network(m_data, c_host->whois_data->cidr_s);
	return;
}

void view_popup_menu_onDoHttpScanLinks(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	http_link *link_anchor = NULL;
	int ret_val = 0;
	single_host_info *c_host = NULL;
	gchar *name = NULL;
	gchar *ipstr = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, &ipstr, &name)) {
		g_free(ipstr);
		if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, &ipstr, NULL)) {
			return;
		}
		ret_val = http_scrape_ip_for_links(ipstr, &c_host->ipv4_addr, "/", &link_anchor);
	} else {
		ret_val = http_scrape_ip_for_links(name, &c_host->ipv4_addr, "/", &link_anchor);
		g_free(name);
	}
	g_free(ipstr);
	if (ret_val) {
		LOGGING_QUICK_ERROR("kraken.gui.model", "there was an error requesting the page")
	} else {
		single_host_set_status(c_host, KRAKEN_HOST_STATUS_UP);
	}
	gui_popup_select_hosts_from_http_links(m_data, link_anchor);
	http_link_list_free(link_anchor);
	return;
}

void view_popup_menu_onDoHttpScanBingIP(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *gipstr = NULL;
	char ipstr[INET_ADDRSTRLEN + 1];

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, NULL, &gipstr, NULL)) {
		return;
	}

	strncpy(ipstr, gipstr, sizeof(ipstr));
	g_free(gipstr);
	gui_popup_http_search_engine_bing_ip(m_data, ipstr);
	return;
}

void view_popup_menu_onDelete(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint response;
	single_host_info *c_host = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, NULL, NULL)) {
		return;
	}

	response = GUI_POPUP_QUESTION_SURE(NULL);
	if (response == GTK_RESPONSE_YES) {
		host_manager_delete_host_by_ip(m_data->c_host_manager, &c_host->ipv4_addr);
		gui_model_update_tree_and_marquee(m_data, NULL);
	}
	return;
}

void view_popup_menu_onDeleteHostName(GtkWidget *menuitem, main_gui_data *m_data) {
	GtkTreeView *treeview = GTK_TREE_VIEW(m_data->tree_view);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint response;
	gchar *name = NULL;
	single_host_info *c_host = NULL;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, NULL, &name)) {
		return;
	}

	response = GUI_POPUP_QUESTION_SURE(NULL);
	if (response == GTK_RESPONSE_YES) {
		single_host_delete_hostname(c_host, name);
		gui_model_update_tree_and_marquee(m_data, NULL);
	}
	g_free(name);
	return;
}

void view_popup_menu_plugins_onHostDemand(GtkWidget *menuitem, gpointer data) {
	static main_gui_data *m_data;
	plugin_object *c_plugin;
	GtkTreeView *treeview;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	single_host_info *c_host;
	gui_data_menu_plugin *gp_data;

	if (menuitem == NULL) {
		m_data = data;
		return;
	}

	treeview = GTK_TREE_VIEW(m_data->tree_view);
	c_plugin = data;

	selection = gtk_tree_view_get_selection(treeview);
	if (!gtk_tree_selection_get_selected(selection, &model, &iter)) {
		return;
	}
	if (!gui_model_get_host_info_from_tree_iter(model, &iter, m_data, &c_host, NULL, NULL)) {
		return;
	}

	if (kraken_thread_mutex_trylock(&m_data->plugin_mutex) == 0) {
		gp_data = malloc(sizeof(gui_data_menu_plugin));
		gp_data->m_data = m_data;
		gp_data->c_plugin = c_plugin;
		gp_data->callback_id = PLUGIN_CALLBACK_ID_HOST_ON_DEMAND;
		gp_data->plugin_data = c_host;
		kraken_thread_create(&m_data->plugin_thread, callback_thread_view_popup_menu_plugins, gp_data);
	} else {
		GUI_POPUP_ERROR_PLUGIN_RUNNING(m_data->main_window);
	}
	return;
}

void view_popup_menu(GtkWidget *treeview, GdkEventButton *event, gpointer m_data) {
	GtkWidget *menu;
	GtkWidget *menuitem;
	GtkWidget *plugins_menu;
	plugin_object *c_plugin;
	plugin_callback *c_callback;
	plugin_iter plugin_i;

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

	menuitem = gtk_menu_item_new_with_label("HTTP Scan Bing IP");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDoHttpScanBingIP, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	/* build the plugins submenu */
	plugins_menu = gtk_menu_new();
	plugins_iter_init(&plugin_i);
	view_popup_menu_plugins_onHostDemand(NULL, m_data);
	while (plugins_iter_next(&plugin_i, &c_plugin)) {
		if (plugins_plugin_get_callback(c_plugin, PLUGIN_CALLBACK_ID_HOST_ON_DEMAND, &c_callback)) {
			menuitem = gtk_menu_item_new_with_label(c_plugin->name);
			g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_plugins_onHostDemand, c_plugin);
			gtk_menu_shell_append(GTK_MENU_SHELL(plugins_menu), menuitem);
		}
	}

	menuitem = gtk_menu_item_new_with_label("Plugins");
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(menuitem), plugins_menu);
	/* done with the plugins submenu */

	menuitem = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_menu_item_new_with_label("Delete");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDelete, m_data);
	gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

	menuitem = gtk_menu_item_new_with_label("Delete Hostname");
	g_signal_connect(menuitem, "activate", (GCallback)view_popup_menu_onDeleteHostName, m_data);
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

	model = gui_refresh_tree_model(NULL, m_data);
	gtk_tree_view_set_model(GTK_TREE_VIEW(m_data->tree_view), model);
	gui_model_update_marquee(m_data, status);
	while (gtk_events_pending()) {
		gtk_main_iteration();
	}
	return 0;
}

int gui_model_update_tree_and_marquee_thread(main_gui_data *m_data, const char *status) {
	int result;

	gdk_threads_enter();
	result = gui_model_update_tree_and_marquee(m_data, status);
	gdk_threads_leave();
	return result;
}

GtkTreeModel *gui_refresh_tree_model(GtkTreeStore *store, main_gui_data *m_data) {
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
		store = gtk_tree_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	}

	treemodel = GTK_TREE_MODEL(store);
	gtk_tree_model_get_iter_first(treemodel, &ipiter);
	host_manager_iter_host_init(m_data->c_host_manager, &host_i);
	while (host_manager_iter_host_next(m_data->c_host_manager, &host_i, &c_host)) {
		inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
		gtk_tree_store_append(store, &ipiter, NULL);
		gtk_tree_store_set(store, &ipiter, COL_IPADDR, ipstr, -1);
		if (netaddr_ip_is_rfc1918(&c_host->ipv4_addr) || netaddr_ip_is_rfc3330(&c_host->ipv4_addr)) {
			gtk_tree_store_set(store, &ipiter, COL_IPADDR_BGCOLOR, "Yellow", COL_IPADDR_BGCOLOR_SET, TRUE, -1);
		}
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

GtkWidget *gui_model_create_view_and_model(host_manager *c_host_manager, main_gui_data *m_data) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkWidget *view;
	GtkTreeStore *store;

	view = gtk_tree_view_new();
	store = gtk_tree_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	model = gui_refresh_tree_model(NULL, m_data);
	g_signal_connect(view, "button-press-event", (GCallback)view_onButtonPressed, m_data);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_set_attributes(col, renderer, "text", COL_IPADDR, "background", COL_IPADDR_BGCOLOR, "background-set", COL_IPADDR_BGCOLOR_SET, NULL);
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
