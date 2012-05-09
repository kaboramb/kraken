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

void callback_bf_domain(GtkWidget *widget, popup_data *userdata) {
	GtkTreeModel *model;
	const gchar *text_entry;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	
	memset(target_domain, '\0', sizeof(target_domain));
	text_entry = gtk_entry_get_text(GTK_ENTRY(userdata->text_entry0));
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
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
	popup_data *p_data;
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	
	gtk_widget_set_size_request(GTK_WIDGET(window), 200, 150);
	gtk_window_set_title(GTK_WINDOW(window), "Enter Domain Name");
	
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	label = gtk_label_new("Target Domain: ");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);
	
	entry = gtk_entry_new();
	
	p_data = malloc(sizeof(popup_data));
	p_data->popup_window = window;
	p_data->text_entry0 = entry;
	p_data->tree_view = tree_view;
	p_data->c_host_manager = c_host_manager;
	
	gtk_entry_set_max_length(GTK_ENTRY(entry), DNS_MAX_FQDN_LENGTH);
	g_signal_connect(entry, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_entry_set_text(GTK_ENTRY(entry), "");
	gtk_box_pack_start(GTK_BOX(vbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);
	
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);
	
	button = gtk_button_new_with_label("Start");
	g_signal_connect(button, "clicked", G_CALLBACK(callback_bf_domain), p_data);
	gtk_box_pack_start(GTK_BOX(vbox), button, TRUE, TRUE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(button);
	
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
	text_entry = gtk_entry_get_text(GTK_ENTRY(userdata->text_entry1));
	netaddr_cidr_str_to_nwk(text_entry, &target_network);
	gtk_widget_destroy(userdata->popup_window);
	
	dns_enumerate_network(target_domain, &target_network, userdata->c_host_manager);
	whois_fill_host_manager(userdata->c_host_manager);
	
	model = gui_refresh_tree_model(NULL, userdata->c_host_manager);
	gtk_tree_view_set_model(GTK_TREE_VIEW(userdata->tree_view), model);
	
	free(userdata);
	return;
}

gboolean gui_popup_bf_network(GtkWidget *tree_view, host_manager *c_host_manager) {
	GtkWidget *window;
	GtkWidget *vbox, *hbox;
	GtkWidget *entry0;
	GtkWidget *entry1;
	GtkWidget *button;
	GtkWidget *label;
	popup_data *p_data;
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	
	gtk_widget_set_size_request(GTK_WIDGET(window), 200, 150);
	gtk_window_set_title(GTK_WINDOW(window), "Enter Domain Name");
	
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_widget_destroy), NULL);
	g_signal_connect_swapped(window, "delete-event", G_CALLBACK(gtk_widget_destroy), window);
	
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);
	
	label = gtk_label_new("Target Domain: ");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, TRUE, 0);
	gtk_widget_show(label);
	
	entry0 = gtk_entry_new();
	entry1 = gtk_entry_new();
	
	p_data = malloc(sizeof(popup_data));
	
	gtk_entry_set_max_length(GTK_ENTRY(entry0), DNS_MAX_FQDN_LENGTH);
	g_signal_connect(entry0, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_entry_set_text(GTK_ENTRY(entry0), "");
	gtk_box_pack_start(GTK_BOX(vbox), entry0, TRUE, TRUE, 0);
	gtk_widget_show(entry0);
	
	gtk_entry_set_max_length(GTK_ENTRY(entry1), DNS_MAX_FQDN_LENGTH);
	g_signal_connect(entry1, "activate", G_CALLBACK(callback_bf_domain), p_data);
	gtk_entry_set_text(GTK_ENTRY(entry1), "");
	gtk_box_pack_start(GTK_BOX(vbox), entry1, TRUE, TRUE, 0);
	gtk_widget_show(entry1);
	
	p_data->popup_window = window;
	p_data->text_entry0 = entry0;
	p_data->text_entry1 = entry1;
	p_data->tree_view = tree_view;
	p_data->c_host_manager = c_host_manager;
	
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(vbox), hbox);
	gtk_widget_show(hbox);
	
	button = gtk_button_new_with_label("Start");
	g_signal_connect(button, "clicked", G_CALLBACK(callback_bf_network), p_data);
	gtk_box_pack_start(GTK_BOX(vbox), button, TRUE, TRUE, 0);
	gtk_widget_set_can_default(button, TRUE);
	gtk_widget_grab_default(button);
	gtk_widget_show(button);
	
	gtk_widget_show(window);
	
	return TRUE;
}
