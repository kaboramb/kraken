#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "hosts.h"
#include "dns_enum.h"
#include "gui_popups.h"
#include "gui_model.h"
#include "network_addr.h"
#include "whois_lookup.h"

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

void callback_bf_domain(GtkWidget *widget, popup_data *userdata) {
	GtkTreeModel *model;
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
	
	model = gui_refresh_tree_model(NULL, userdata->c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(userdata->tree_view), model);
	
	free(userdata);
	return;
}

gboolean gui_popup_bf_domain(GtkWidget *tree_view, host_manager *c_host_manager) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *image;
	popup_data *p_data;
	
	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 110);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Forward Bruteforce");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	p_data = malloc(sizeof(popup_data));
	
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
	if (strlen(c_host_manager->lw_domain) > 0) {
		gtk_entry_set_text(GTK_ENTRY(entry), c_host_manager->lw_domain);
	}
	
	p_data->popup_window = window;
	p_data->text_entry0 = entry;
	p_data->tree_view = tree_view;
	p_data->c_host_manager = c_host_manager;
	
	
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
	
	image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_SMALL_TOOLBAR);
	label = gtk_label_new("Start");
	
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 3);
	gtk_widget_show(image);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 3);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	
	gtk_widget_show(window);
	
	return TRUE;
}

void callback_bf_network(GtkWidget *widget, popup_data *userdata) {
	GtkTreeModel *model;
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
	
	model = gui_refresh_tree_model(NULL, userdata->c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(userdata->tree_view), model);
	
	free(userdata);
	return;
}

gboolean gui_popup_bf_network(GtkWidget *tree_view, host_manager *c_host_manager, char *cidr_str) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry0;
	GtkWidget *entry1;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *image;
	popup_data *p_data;
	
	/* get the main popup window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
	gtk_widget_set_size_request(GTK_WIDGET(window), 350, 150);
	gtk_window_set_title(GTK_WINDOW(window), "DNS Reverse Bruteforce");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	/* get the main vertical box for the window */
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	p_data = malloc(sizeof(popup_data));
	
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
	if (strlen(c_host_manager->lw_domain) > 0) {
		gtk_entry_set_text(GTK_ENTRY(entry0), c_host_manager->lw_domain);
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
	p_data->tree_view = tree_view;
	p_data->c_host_manager = c_host_manager;
	
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
	
	image = gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_SMALL_TOOLBAR);
	label = gtk_label_new("Start");
	
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 3);
	gtk_widget_show(image);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 3);
	gtk_widget_show(label);
	gtk_widget_show(hbox);
	gtk_container_add(GTK_CONTAINER(button), hbox);
	
	gtk_widget_show(window);
	
	return TRUE;
}
