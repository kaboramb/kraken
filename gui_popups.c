#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "hosts.h"
#include "dns_enum.h"
#include "gui_popups.h"
#include "gui_model.h"
#include "host_manager.h"
#include "logging.h"
#include "network_addr.h"
#include "whois_lookup.h"

enum {
	COL_SELECT = 0,
	COL_DOMAIN,
	NUM_COLS
};

char *get_domain(char *originalname) {
	/* this returns a pointer to the second-to-top-level domain */
	char *pCur = originalname;
	int dotfound = 0;
	
	pCur += strlen(originalname);
	while (pCur != originalname) {
		if (*pCur == '.') {
			if (dotfound == 1) {
				return (pCur + 1);
			} else {
				dotfound = 1;
			}
		}
		pCur -= 1;
	}
	if (dotfound == 1) {
		return pCur;
	}
	return NULL;
}

int host_in_domain(char *hostname, char *domain) {
	char *hdomain;
	hdomain = get_domain(hostname);
	if (hdomain == NULL) {
		return 0;
	}
	if (strncasecmp(hdomain, domain, strlen(domain)) == 0) {
		return 1;
	}
	return 0;
}

void popup_error_invalid_domain_name(gpointer window) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Invalid Domain Name");
	gtk_window_set_title(GTK_WINDOW(dialog), "Error: Invalid Domain");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void popup_error_invalid_cidr_network(gpointer window) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Invalid CIDR Network");
	gtk_window_set_title(GTK_WINDOW(dialog), "Error: Invalid Network");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void popup_error_no_hosts_found_in_links(gpointer window) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "No Links Were Found");
	gtk_window_set_title(GTK_WINDOW(dialog), "Error: No Links");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void callback_bf_domain(GtkWidget *widget, popup_data *userdata) {
	const gchar *text_entry;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	
	memset(target_domain, '\0', sizeof(target_domain));
	text_entry = gtk_entry_get_text(GTK_ENTRY(userdata->text_entry0));
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
	
	if (strlen(target_domain) == 0) {
		popup_error_invalid_domain_name(userdata->popup_window);
		gtk_widget_destroy(userdata->popup_window);
		free(userdata);
		return;
	}
	
	gtk_widget_destroy(userdata->popup_window);
	
	dns_enumerate_domain(target_domain, userdata->c_host_manager);
	whois_fill_host_manager(userdata->c_host_manager);
	
	gui_model_update_tree_and_marquee((main_gui_data*)userdata);
	
	free(userdata);
	return;
}

gboolean gui_popup_bf_domain(main_gui_data *m_data) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *image;
	popup_data *p_data;
	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}
	
	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 115);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Forward Bruteforce");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);
	
	label = gtk_label_new("Target Domain: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);
	
	entry = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(entry), DNS_MAX_FQDN_LENGTH);
	if (strlen(m_data->c_host_manager->lw_domain) > 0) {
		gtk_entry_set_text(GTK_ENTRY(entry), m_data->c_host_manager->lw_domain);
	}
	
	p_data->popup_window = window;
	p_data->text_entry0 = entry;
	p_data->tree_view = m_data->tree_view;
	p_data->main_marquee = m_data->main_marquee;
	p_data->c_host_manager = m_data->c_host_manager;
	
	
	g_signal_connect(entry, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);
	
	/* get the button */
	button = gtk_button_new();
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_bf_domain), p_data);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(hbox);
	gtk_widget_show(button);
	
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	
	image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON);
	label = gtk_label_new("Start");
	
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 2);
	gtk_widget_show(image);
	gtk_box_pack_end(GTK_BOX(hbox), label, FALSE, FALSE, 2);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	
	gtk_widget_show(window);
	
	return TRUE;
}

void callback_bf_network(GtkWidget *widget, popup_data *userdata) {
	const gchar *text_entry;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	network_info target_network;
	
	memset(target_domain, '\0', sizeof(target_domain));
	text_entry = gtk_entry_get_text(GTK_ENTRY(userdata->text_entry0));
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
	
	if (strlen(target_domain) == 0) {
		popup_error_invalid_domain_name(userdata->popup_window);
		gtk_widget_destroy(userdata->popup_window);
		free(userdata);
		return;
	}
	
	text_entry = gtk_entry_get_text(GTK_ENTRY(userdata->text_entry1));
	if (netaddr_cidr_str_to_nwk((char *)text_entry, &target_network) != 0) {
		popup_error_invalid_cidr_network(userdata->popup_window);
		gtk_widget_destroy(userdata->popup_window);
		free(userdata);
		return;
	}
	gtk_widget_destroy(userdata->popup_window);
	
	dns_enumerate_network(target_domain, &target_network, userdata->c_host_manager);
	whois_fill_host_manager(userdata->c_host_manager);
	
	gui_model_update_tree_and_marquee((main_gui_data*)userdata);
	
	free(userdata);
	return;
}

gboolean gui_popup_bf_network(main_gui_data *m_data, char *cidr_str) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry0;
	GtkWidget *entry1;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *image;
	popup_data *p_data;
	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}
	
	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 165);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Reverse Bruteforce");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);
	
	label = gtk_label_new("Target Domain: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);
	
	entry0 = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(entry0), DNS_MAX_FQDN_LENGTH);
	if (strlen(m_data->c_host_manager->lw_domain) > 0) {
		gtk_entry_set_text(GTK_ENTRY(entry0), m_data->c_host_manager->lw_domain);
	}
	g_signal_connect(entry0, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry0, TRUE, TRUE, 0);
	gtk_widget_show(entry0);
	
	/* get another horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);
	
	label = gtk_label_new("Target Network: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);
	
	entry1 = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(entry1), 18);
	if (cidr_str != NULL) {
		gtk_entry_set_text(GTK_ENTRY(entry1), cidr_str);
	}
	g_signal_connect(entry1, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry1, TRUE, TRUE, 0);
	gtk_widget_show(entry1);
	
	p_data->popup_window = window;
	p_data->text_entry0 = entry0;
	p_data->text_entry1 = entry1;
	p_data->tree_view = m_data->tree_view;
	p_data->main_marquee = m_data->main_marquee;
	p_data->c_host_manager = m_data->c_host_manager;
	
	/* get the button */
	button = gtk_button_new();
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_bf_network), p_data);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(hbox);
	gtk_widget_show(button);
	
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	
	image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON);
	label = gtk_label_new("Start");
	
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 2);
	gtk_widget_show(image);
	gtk_box_pack_end(GTK_BOX(hbox), label, FALSE, FALSE, 2);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	
	gtk_widget_show(window);
	
	return TRUE;
}

GtkTreeModel *gui_refresh_http_link_domain_selection_model(GtkTreeStore *store, main_gui_data *m_data, http_link *link_anchor) {
	GtkTreeIter domainsearchiter, hostsearchiter;
	http_link *link_current;
	GtkTreeModel *treemodel = GTK_TREE_MODEL(store);
	gchar *domain;
	gchar *hostname;
	gboolean item_in_list = FALSE;
	
	if (store == NULL) {
		store = gtk_tree_store_new(NUM_COLS, G_TYPE_BOOLEAN, G_TYPE_STRING);
	}
	
	for (link_current = link_anchor; link_current; link_current = link_current->next) {
		if (gtk_tree_model_get_iter_first(treemodel, &domainsearchiter)) {
			item_in_list = FALSE;
			do {
				gtk_tree_model_get(treemodel, &domainsearchiter, COL_DOMAIN, &domain, -1);
				if (host_in_domain(link_current->hostname, domain) == 1) {
					gtk_tree_model_iter_children(treemodel, &hostsearchiter, &domainsearchiter);
					do {
						gtk_tree_model_get(treemodel, &hostsearchiter, COL_DOMAIN, &hostname, -1);
						if (strncasecmp(hostname, link_current->hostname, strlen(hostname)) == 0) {
							item_in_list = TRUE;
							break;
						}
					} while (gtk_tree_model_iter_next(treemodel, &hostsearchiter));
					if (!item_in_list) {
						gtk_tree_store_append(store, &hostsearchiter, &domainsearchiter);
						gtk_tree_store_set(store, &hostsearchiter, COL_SELECT, FALSE, COL_DOMAIN, link_current->hostname, -1);
						item_in_list = TRUE;
					}
					break;
				}
				g_free(domain);
			} while (gtk_tree_model_iter_next(treemodel, &domainsearchiter));
			if (item_in_list) {
				continue;
			}
		}
		domain = get_domain(link_current->hostname);
		if (domain == NULL) {
			LOGGING_QUICK_WARNING("kraken.gui.popups", "skipping an invalid domain name")
			continue;
		}
		gtk_tree_store_append(store, &domainsearchiter, NULL);
		gtk_tree_store_set(store, &domainsearchiter, COL_SELECT, FALSE, COL_DOMAIN, domain, -1);
		gtk_tree_store_append(store, &hostsearchiter, &domainsearchiter);
		gtk_tree_store_set(store, &hostsearchiter, COL_SELECT, FALSE, COL_DOMAIN, link_current->hostname, -1);
	}
	
	return GTK_TREE_MODEL(store);
}

void callback_toggle_cell(GtkCellRendererToggle *cell, gchar *path_string, GtkTreeStore *store) {
	GtkTreeIter piter, citer;
	gboolean selected;
	
	gtk_tree_model_get_iter_from_string(GTK_TREE_MODEL(store), &piter, path_string);
	gtk_tree_model_get(GTK_TREE_MODEL(store), &piter, COL_SELECT, &selected, -1);
	if (selected) {
		selected = FALSE;
	} else {
		selected = TRUE;
	}
	gtk_tree_store_set(store, &piter, COL_SELECT, selected, -1);
	if (gtk_tree_model_iter_children(GTK_TREE_MODEL(store), &citer, &piter)) {
		do {
			gtk_tree_store_set(store, &citer, COL_SELECT, selected, -1);
		} while (gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &citer));
	}
	return;
}

void callback_add_selected_hosts(GtkWidget *widget, popup_data *userdata) {
	GtkTreeModel *treemodel;
	GtkTreeIter piter, citer;
	gchar *hostname;
	gboolean selected;
	treemodel = gtk_tree_view_get_model((GtkTreeView *)userdata->misc_widget);

	if (gtk_tree_model_get_iter_first(treemodel, &piter) == FALSE) {
		return; /* tree is empty, nothing to process */
	}
	do {
		if (gtk_tree_model_iter_children(treemodel, &citer, &piter)) {
			do {
				gtk_tree_model_get(treemodel, &citer, COL_SELECT, &selected, COL_DOMAIN, &hostname, -1);
				if (selected) {
					host_manager_quick_add_by_name(userdata->c_host_manager, hostname);
				}
				g_free(hostname);
			} while (gtk_tree_model_iter_next(treemodel, &citer));
		}
	} while (gtk_tree_model_iter_next(treemodel, &piter));
	
	gtk_widget_destroy(userdata->popup_window);
	gui_model_update_tree_and_marquee((main_gui_data*)userdata);
	free(userdata);
	return;
}

GtkWidget *create_http_link_domain_selection_view_and_model(main_gui_data *m_data, http_link *link_anchor) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkWidget *view;
	GtkTreeStore *store;
	
	view = gtk_tree_view_new();
	store = gtk_tree_store_new(NUM_COLS, G_TYPE_BOOLEAN, G_TYPE_STRING);
	model = gui_refresh_http_link_domain_selection_model(store, m_data, link_anchor);
	
	renderer = gtk_cell_renderer_toggle_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "active", COL_SELECT);
	g_signal_connect(renderer, "toggled", (GCallback)callback_toggle_cell, store);
	gtk_tree_view_column_set_title(col, "Add");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_DOMAIN);
	gtk_tree_view_column_set_title(col, "Domain");
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);
	
	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);
	g_object_unref(model);
	return view;
}

gboolean gui_popup_select_hosts_from_http_links(main_gui_data *m_data, http_link *link_anchor) {
	GtkWidget *window;
	GtkWidget *scroll_window;
	GtkWidget *main_vbox, *hbox;
	GtkWidget *view;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *image;
	popup_data *p_data;
	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}
	
	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_size_request(window, 350, 400);
	gtk_window_set_title(GTK_WINDOW(window), "Select Domains");
	gtk_container_set_border_width(GTK_CONTAINER(window), 0);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect(window, "delete-event", G_CALLBACK(gtk_widget_destroy), NULL);
	
	main_vbox = gtk_vbox_new(FALSE, 1);
	gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
	gtk_container_add(GTK_CONTAINER(window), main_vbox);
	
	scroll_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll_window), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	
	view = create_http_link_domain_selection_view_and_model(m_data, link_anchor);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll_window), view);
	gtk_box_pack_start(GTK_BOX(main_vbox), scroll_window, TRUE, TRUE, 0);
	
	p_data->popup_window = window;
	p_data->tree_view = m_data->tree_view;
	p_data->main_marquee = m_data->main_marquee;
	p_data->c_host_manager = m_data->c_host_manager;
	p_data->misc_widget = view;
	
	/* get the buttons */
	button = gtk_button_new();
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 10);
	gtk_box_pack_end(GTK_BOX(main_vbox), hbox, FALSE, FALSE, 0);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_add_selected_hosts), p_data);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(hbox);
	gtk_widget_show(button);
	
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	
	image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON);
	label = gtk_label_new("Add Selected");
	
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 2);
	gtk_widget_show(image);
	gtk_box_pack_end(GTK_BOX(hbox), label, FALSE, FALSE, 2);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	
	gtk_widget_show_all(window);
	
	if (link_anchor == NULL) {
		popup_error_no_hosts_found_in_links(window);
		gtk_widget_destroy(window);
		free(p_data);
		return TRUE;
	}
	return TRUE;
}
