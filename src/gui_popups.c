#include "kraken.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "dns_enum.h"
#include "gui_popups.h"
#include "gui_popups_threads.h"
#include "gui_model.h"
#include "host_manager.h"
#include "http_scan.h"
#include "whois_lookup.h"

enum {
	COL_SELECT = 0,
	COL_DOMAIN,
	NUM_COLS
};

void gui_popup_data_init(popup_data *p_data, main_gui_data *m_data) {
	memset(p_data, '\0', sizeof(popup_data));
	p_data->m_data = m_data;
	p_data->thread_function = NULL;
	p_data->action_status = KRAKEN_ACTION_PAUSE;
	p_data->cancel_dialog = NULL;
	return;
}

void gui_popup_error_dialog(gpointer window, const char *message, const char *title) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, message);
	gtk_window_set_title(GTK_WINDOW(dialog), title);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

void gui_popup_info_dialog(gpointer window, const char *message, const char *title) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, message);
	gtk_window_set_title(GTK_WINDOW(dialog), title);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

gint gui_popup_question_yes_no_dialog(gpointer window, const char *message, const char *title) {
	GtkWidget *dialog;
	gint response;
	dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, message);
	gtk_window_set_title(GTK_WINDOW(dialog), title);
	response = gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	return response;
}

void callback_destroy(GtkWidget *widget, popup_data *p_data) {
	if (p_data != NULL) {
		free(p_data);
	}
	return;
}

void callback_cancel(GtkWidget *widget, popup_data *p_data) {
	if (p_data != NULL) {
		gtk_container_foreach(GTK_CONTAINER(p_data->popup_window), (GtkCallback)gtk_widget_destroy, NULL);
		gtk_widget_destroy(p_data->popup_window);
	}
	return;
}

GtkWidget *gui_popup_get_button(int type, popup_data *p_data, const char* text) {
	GtkWidget *button;
	GtkWidget *hbox;
	GtkWidget *image = NULL;
	GtkWidget *label = NULL;

	button = gtk_button_new();
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	switch (type) {
		case GUI_POPUP_BUTTON_TYPE_START:
			gtk_widget_set_can_default(button, TRUE);
			g_signal_connect(button, "clicked", G_CALLBACK(callback_thread_start), p_data);
			image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON);
			label = gtk_label_new("Start");
			break;
		case GUI_POPUP_BUTTON_TYPE_CANCEL:
			g_signal_connect(button, "clicked", G_CALLBACK(callback_cancel), p_data);
			image = gtk_image_new_from_stock(GTK_STOCK_CANCEL, GTK_ICON_SIZE_BUTTON);
			label = gtk_label_new("Cancel");
			break;
		case GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION:
			gtk_widget_set_sensitive(button, FALSE);
			g_signal_connect(button, "clicked", G_CALLBACK(callback_thread_cancel_action), p_data);
			image = gtk_image_new_from_stock(GTK_STOCK_CANCEL, GTK_ICON_SIZE_BUTTON);
			label = gtk_label_new("Cancel");
			break;
		case GUI_POPUP_BUTTON_TYPE_BASIC_APPLY:
			gtk_widget_set_can_default(button, TRUE);
			image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON);
			if (text == NULL) {
				label = gtk_label_new("Apply");
			} else {
				label = gtk_label_new(text);
			}
			break;
		case GUI_POPUP_BUTTON_TYPE_BASIC_CANCEL:
			image = gtk_image_new_from_stock(GTK_STOCK_CANCEL, GTK_ICON_SIZE_BUTTON);
			if (text == NULL) {
				label = gtk_label_new("Cancel");
			} else {
				label = gtk_label_new(text);
			}
	}
	if (image != NULL) {
		gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 0);
		gtk_widget_show(image);
	}
	gtk_box_pack_end(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	gtk_widget_show(button);
	return button;
}

gboolean gui_popup_http_scrape_url_for_links(main_gui_data *m_data, char *host_str) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry;
	GtkWidget *sbutton;
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
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 95);
	gtk_window_set_title(GTK_WINDOW(window), "HTTP Scan For Links");
	gtk_container_set_border_width(GTK_CONTAINER(window), 5);
	g_signal_connect(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);

	label = gtk_label_new("Target Host: http://");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(entry), DNS_MAX_FQDN_LENGTH);
	if (strlen(m_data->c_host_manager->lw_domain) > 0) {
		gtk_entry_set_text(GTK_ENTRY(entry), m_data->c_host_manager->lw_domain);
	}

	gui_popup_data_init(p_data, m_data);
	p_data->thread_function = (void *)&gui_popup_thread_http_scrape_url_for_links;
	p_data->popup_window = window;
	p_data->text_entry0 = entry;

	g_signal_connect(entry, "activate", G_CALLBACK(callback_thread_start), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	/* get the button */
	sbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_START, p_data, NULL);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_box_pack_end(GTK_BOX(hbox), sbutton, FALSE, FALSE, 0);
	gtk_widget_grab_default(sbutton);
	gtk_widget_show(hbox);
	gtk_widget_show(sbutton);
	p_data->start_button = sbutton;
	gtk_widget_show(window);
	return TRUE;
}

gboolean gui_popup_http_search_engine_bing(main_gui_data *m_data) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry;
	GtkWidget *sbutton, *cbutton;
	GtkWidget *label;
	popup_data *p_data;
	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}

	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 130);
	gtk_window_set_title(GTK_WINDOW(window), "HTTP Search Bing");
	gtk_container_set_border_width(GTK_CONTAINER(window), 3);
	g_signal_connect(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
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

	gui_popup_data_init(p_data, m_data);
	p_data->thread_function = (void *)&gui_popup_thread_http_search_engine_bing;
	p_data->popup_window = window;
	p_data->text_entry0 = entry;
	p_data->misc_widget = gtk_progress_bar_new();

	g_signal_connect(entry, "activate", G_CALLBACK(callback_thread_start), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	gtk_container_add(GTK_CONTAINER(vbox), p_data->misc_widget);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Waiting");
	gtk_widget_show(p_data->misc_widget);

	/* get the buttons */
	sbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_START, p_data, NULL);
	cbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION, p_data, NULL);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_box_pack_end(GTK_BOX(hbox), sbutton, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), cbutton, FALSE, FALSE, 0);
	gtk_widget_show(hbox);
	gtk_widget_grab_default(sbutton);

	p_data->start_button = sbutton;
	p_data->cancel_button = cbutton;

	gtk_widget_show(window);
	if (m_data->k_opts->bing_api_key == NULL) {
		gui_popup_error_dialog(window, "Bing API Key Not Set", "Error: Invalid API Key");
		gtk_widget_destroy(window);
	}
	return TRUE;
}

gboolean gui_popup_dns_enum_domain(main_gui_data *m_data) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry;
	GtkWidget *sbutton, *cbutton;
	GtkWidget *label;
	popup_data *p_data;

	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}

	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 130);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Forward Bruteforce");
	gtk_container_set_border_width(GTK_CONTAINER(window), 3);
	g_signal_connect_after(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
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

	gui_popup_data_init(p_data, m_data);
	p_data->thread_function = (void *)&gui_popup_thread_dns_enum_domain;
	p_data->popup_window = window;
	p_data->text_entry0 = entry;
	p_data->misc_widget = gtk_progress_bar_new();

	g_signal_connect(entry, "activate", G_CALLBACK(callback_thread_start), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	gtk_container_add(GTK_CONTAINER(vbox), p_data->misc_widget);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Waiting");
	gtk_widget_show(p_data->misc_widget);

	/* get the buttons */
	sbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_START, p_data, NULL);
	cbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION, p_data, NULL);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_box_pack_end(GTK_BOX(hbox), sbutton, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), cbutton, FALSE, FALSE, 0);
	gtk_widget_show(hbox);
	gtk_widget_grab_default(sbutton);

	p_data->start_button = sbutton;
	p_data->cancel_button = cbutton;

	gtk_widget_show(window);

	if (m_data->k_opts->dns_wordlist == NULL) {
		gui_popup_error_dialog(window, "Hostname Wordlist Not Set", "Error: Wordlist Not Set");
		gtk_widget_destroy(window);
	}
	return TRUE;
}

gboolean gui_popup_dns_enum_network(main_gui_data *m_data, char *cidr_str) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry0;
	GtkWidget *entry1;
	GtkWidget *sbutton, *cbutton;
	GtkWidget *label;
	popup_data *p_data;

	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}

	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 180);
	gtk_container_set_border_width(GTK_CONTAINER(window), 3);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Reverse Bruteforce");
	g_signal_connect_after(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	/* get a horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
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
	g_signal_connect(entry0, "activate", G_CALLBACK(callback_thread_start), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry0, TRUE, TRUE, 0);
	gtk_widget_show(entry0);

	/* get another horizontal box to place in the vertical box */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
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
	g_signal_connect(entry1, "activate", G_CALLBACK(callback_thread_start), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), entry1, TRUE, TRUE, 0);
	gtk_widget_show(entry1);


	gui_popup_data_init(p_data, m_data);
	p_data->thread_function = (void *)&gui_popup_thread_dns_enum_network;
	p_data->popup_window = window;
	p_data->text_entry0 = entry0;
	p_data->text_entry1 = entry1;
	p_data->misc_widget = gtk_progress_bar_new();

	gtk_container_add(GTK_CONTAINER(vbox), p_data->misc_widget);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Waiting");
	gtk_widget_show(p_data->misc_widget);

	/* get the buttons */
	sbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_START, p_data, NULL);
	cbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION, p_data, NULL);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_box_pack_end(GTK_BOX(hbox), sbutton, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), cbutton, FALSE, FALSE, 0);
	gtk_widget_show(hbox);
	gtk_widget_grab_default(sbutton);

	p_data->start_button = sbutton;
	p_data->cancel_button = cbutton;

	gtk_widget_show(window);
	return TRUE;
}

gboolean gui_popup_http_scrape_hosts_for_links(main_gui_data *m_data) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *sbutton, *cbutton;
	GtkWidget *label;
	popup_data *p_data;

	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}

	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 90);
	gtk_window_set_title(GTK_WINDOW(window), "HTTP Enumerate Hosts");
	gtk_container_set_border_width(GTK_CONTAINER(window), 5);
	g_signal_connect_after(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	gui_popup_data_init(p_data, m_data);
	p_data->thread_function = (void *)&gui_popup_thread_http_scrape_hosts_for_links;
	p_data->popup_window = window;
	p_data->misc_widget = gtk_progress_bar_new();

	gtk_container_add(GTK_CONTAINER(vbox), p_data->misc_widget);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Waiting");
	gtk_widget_show(p_data->misc_widget);

	/* get the buttons */
	sbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_START, p_data, NULL);
	cbutton = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_CANCEL_ACTION, p_data, NULL);
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_box_pack_end(GTK_BOX(hbox), sbutton, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(hbox), cbutton, FALSE, FALSE, 0);
	gtk_widget_show(hbox);
	gtk_widget_grab_default(sbutton);

	p_data->start_button = sbutton;
	p_data->cancel_button = cbutton;

	gtk_widget_show(window);
	return TRUE;
}

GtkTreeModel *gui_refresh_http_link_domain_selection_model(GtkTreeStore *store, main_gui_data *m_data, http_link *link_anchor) {
	GtkTreeIter domainsearchiter, hostsearchiter;
	GtkTreeModel *treemodel;
	http_link *link_current;
	gchar *domain;
	gchar *hostname;
	gboolean item_in_list = FALSE;

	if (store == NULL) {
		store = gtk_tree_store_new(NUM_COLS, G_TYPE_BOOLEAN, G_TYPE_STRING);
	}

	treemodel = GTK_TREE_MODEL(store);
	for (link_current = link_anchor; link_current; link_current = link_current->next) {
		if (gtk_tree_model_get_iter_first(treemodel, &domainsearchiter)) {
			item_in_list = FALSE;
			do {
				gtk_tree_model_get(treemodel, &domainsearchiter, COL_DOMAIN, &domain, -1);
				if (dns_host_in_domain(link_current->hostname, domain) == 1) {
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
		domain = dns_get_domain(link_current->hostname);
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

void callback_add_selected_hosts(GtkWidget *widget, popup_data *p_data) {
	GtkTreeModel *treemodel;
	GtkTreeIter piter, citer;
	gchar *hostname;
	gboolean selected;
	treemodel = gtk_tree_view_get_model((GtkTreeView *)p_data->misc_widget);

	if (gtk_tree_model_get_iter_first(treemodel, &piter) == FALSE) {
		return; /* tree is empty, nothing to process */
	}
	do {
		if (gtk_tree_model_iter_children(treemodel, &citer, &piter)) {
			do {
				gtk_tree_model_get(treemodel, &citer, COL_SELECT, &selected, COL_DOMAIN, &hostname, -1);
				if (selected) {
					host_manager_quick_add_by_name(p_data->m_data->c_host_manager, hostname);
				}
				g_free(hostname);
			} while (gtk_tree_model_iter_next(treemodel, &citer));
		}
	} while (gtk_tree_model_iter_next(treemodel, &piter));

	gui_model_update_tree_and_marquee((main_gui_data*)p_data, NULL);
	gtk_widget_destroy(p_data->popup_window);
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
	g_signal_connect_after(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	main_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), main_vbox);

	scroll_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll_window), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

	view = create_http_link_domain_selection_view_and_model(m_data, link_anchor);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll_window), view);
	gtk_box_pack_start(GTK_BOX(main_vbox), scroll_window, TRUE, TRUE, 0);

	gui_popup_data_init(p_data, m_data);
	p_data->popup_window = window;
	p_data->misc_widget = view;

	/* get the button */
	button = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_BASIC_APPLY, p_data, "Add Selected");
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_box_pack_end(GTK_BOX(main_vbox), hbox, FALSE, FALSE, 0);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_add_selected_hosts), p_data);
	gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_widget_grab_default(button);
	gtk_widget_show(hbox);

	gtk_widget_show_all(window);

	if (link_anchor == NULL) {
		GUI_POPUP_ERROR_INVALID_NO_HOSTS_FOUND_IN_LINKS(window);
		gtk_widget_destroy(window);
		return TRUE;
	}
	return TRUE;
}

void callback_manage_settings_select_dns_wordlist(GtkWidget *widget, popup_data *p_data) {
	GtkWidget *dialog;

	dialog = gtk_file_chooser_dialog_new("Select File", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		char *filename;

		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		gtk_entry_set_text(GTK_ENTRY(p_data->text_entry1), filename);
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
	return;
}

void callback_manage_settings(GtkWidget *widget, popup_data *p_data) {
	const gchar *option_text;
	int response;
	char conf_path[MAX_LINE];

	option_text = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry0));
	if ((option_text != NULL) && strlen(option_text)) {
		kraken_opts_set(p_data->m_data->k_opts, KRAKEN_OPT_BING_API_KEY, (char *)option_text);
	}

	option_text = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry1));
	if ((option_text != NULL) && strlen(option_text)) {
		kraken_opts_set(p_data->m_data->k_opts, KRAKEN_OPT_DNS_WORDLIST, (char *)option_text);
	}

	response = kraken_conf_get_config_file_path(conf_path, MAX_LINE);
	if (response == 0) {
		response = kraken_conf_save_config(conf_path, p_data->m_data->k_opts);
	}
	if (response != 0) {
		gui_popup_error_dialog(p_data->popup_window, "Could Not Save Options", "Error: Could Not Save Options");
	}
	gtk_widget_destroy(p_data->popup_window);
	return;
}

gboolean gui_popup_manage_kraken_settings(main_gui_data *m_data) {
	GtkWidget *window;
	GtkWidget *main_vbox, *vbox, *main_hbox, *hbox;
	GtkWidget *frame;
	GtkWidget *notebook;
	GtkWidget *bing_entry, *dns_wordlist_entry;
	GtkWidget *button;
	GtkWidget *label;
	popup_data *p_data;
	p_data = malloc(sizeof(popup_data));
	if (p_data == NULL) {
		LOGGING_QUICK_WARNING("kraken.gui.popup", "could not allcoate memory for p_data")
		return TRUE;
	}

	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_size_request(window, 350, 295);
	gtk_window_set_title(GTK_WINDOW(window), "Settings");
	gtk_container_set_border_width(GTK_CONTAINER(window), 3);
	g_signal_connect_after(window, "destroy", G_CALLBACK(callback_destroy), p_data);

	main_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(window), main_vbox);

	frame = gtk_frame_new("Basic Settings");
	gtk_container_set_border_width(GTK_CONTAINER(frame), 3);
	gtk_widget_show(frame);

	notebook = gtk_notebook_new();
	gtk_container_set_border_width(GTK_CONTAINER(notebook), 3);
	gtk_container_add(GTK_CONTAINER(main_vbox), notebook);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), frame, gtk_label_new("Basic"));

	/* get the main vertical box for the "basic" tab */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	gtk_widget_show(vbox);

	/* get a horizontal box for the bing api key dialog */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);

	label = gtk_label_new("Bing API Key: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);

	bing_entry = gtk_entry_new();
	gtk_entry_set_max_length(GTK_ENTRY(bing_entry), HTTP_BING_API_KEY_SZ);
	if (m_data->k_opts->bing_api_key != NULL) {
		gtk_entry_set_text(GTK_ENTRY(bing_entry), m_data->k_opts->bing_api_key);
	}
	gtk_box_pack_start(GTK_BOX(hbox), bing_entry, TRUE, TRUE, 0);
	gtk_widget_show(bing_entry);

	/* get a horizontal box for the dns wordlist dialog */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);

	label = gtk_label_new("DNS Hostname Wordlist: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 3);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);

	dns_wordlist_entry = gtk_entry_new();
	gtk_entry_set_editable(GTK_ENTRY(dns_wordlist_entry), FALSE);
	if (m_data->k_opts->dns_wordlist != NULL) {
		gtk_entry_set_text(GTK_ENTRY(dns_wordlist_entry), m_data->k_opts->dns_wordlist);
	}
	gtk_box_pack_start(GTK_BOX(hbox), dns_wordlist_entry, TRUE, TRUE, 0);
	gtk_widget_show(dns_wordlist_entry);

	button = gtk_button_new();
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_manage_settings_select_dns_wordlist), p_data);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(hbox);
	gtk_widget_show(button);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	label = gtk_label_new("Select File");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 2);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);

	/* end configuration of the "basic" tab */
	gui_popup_data_init(p_data, m_data);
	p_data->popup_window = window;
	p_data->text_entry0 = bing_entry;
	p_data->text_entry1 = dns_wordlist_entry;

	main_hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_set_border_width(GTK_CONTAINER(main_hbox), 2);
	gtk_container_add(GTK_CONTAINER(main_vbox), main_hbox);

	/* get the Apply button */
	button = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_BASIC_APPLY, p_data, NULL);
	g_signal_connect(button, "clicked", G_CALLBACK(callback_manage_settings), p_data);
	gtk_box_pack_end(GTK_BOX(main_hbox), button, FALSE, FALSE, 0);
	gtk_widget_grab_default(button);

	/* get the Cancel button */
	button = gui_popup_get_button(GUI_POPUP_BUTTON_TYPE_CANCEL, p_data, NULL);
	gtk_box_pack_end(GTK_BOX(main_hbox), button, FALSE, FALSE, 0);

	gtk_widget_show_all(window);
	return TRUE;
}
