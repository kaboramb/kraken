#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "kraken.h"
#include "dns_enum.h"
#include "gui_popups.h"
#include "gui_popups_threads.h"
#include "gui_model.h"
#include "host_manager.h"
#include "http_scan.h"
#include "network_addr.h"
#include "whois_lookup.h"

void gui_popup_thread_dns_enumerate_domain(popup_data *p_data) {
	dns_enum_opts d_opts;
	const gchar *text_entry;
	int response;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	
	memset(target_domain, '\0', sizeof(target_domain));
	gdk_threads_enter();
	text_entry = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry0));
	if ((strlen(text_entry) > DNS_MAX_FQDN_LENGTH) || (strlen(text_entry) == 0)) {
		GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(p_data->popup_window);
		gtk_widget_destroy(p_data->popup_window);
		return;
	}
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
	
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Enumerating Domain");
	gui_model_update_marquee((main_gui_data *)p_data, "Enumerating Domain");
	gdk_threads_leave();
	
	dns_enum_opts_init(&d_opts);
	dns_enum_opts_set_wordlist(&d_opts, p_data->k_opts->dns_wordlist);
	d_opts.progress_update = (void *)&callback_update_progress;
	d_opts.progress_update_data = p_data;
	
	response = dns_enumerate_domain_ex(p_data->c_host_manager, target_domain, &d_opts);
	
	gdk_threads_enter();
	if (response == -1) {
		GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(p_data->popup_window);
		gui_model_update_marquee((main_gui_data *)p_data, NULL);
	} else {
		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Requesting WHOIS Records");
		gui_model_update_marquee((main_gui_data *)p_data, "Requesting WHOIS Records");
		gdk_threads_leave();
		whois_fill_host_manager(p_data->c_host_manager);
		gdk_threads_enter();
		gui_model_update_tree_and_marquee((main_gui_data *)p_data, NULL);
	}
	gtk_widget_destroy(p_data->popup_window);
	gdk_threads_leave();
	dns_enum_opts_destroy(&d_opts);
	return;
}

void gui_popup_thread_dns_enumerate_network(popup_data *p_data) {
	dns_enum_opts d_opts;
	const gchar *text_entry;
	int response;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	network_info target_network;
	
	memset(target_domain, '\0', sizeof(target_domain));
	gdk_threads_enter();
	text_entry = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry0));
	if ((strlen(text_entry) > DNS_MAX_FQDN_LENGTH) || (strlen(text_entry) == 0)) {
		GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(p_data->popup_window);
		gtk_widget_destroy(p_data->popup_window);
		gdk_threads_leave();
		return;
	}
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
	
	text_entry = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry1));
	if (netaddr_cidr_str_to_nwk((char *)text_entry, &target_network) != 0) {
		GUI_POPUP_ERROR_INVALID_CIDR_NETWORK(p_data->popup_window);
		gtk_widget_destroy(p_data->popup_window);
		gdk_threads_leave();
		return;
	}
	
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Enumerating Network");
	gui_model_update_marquee((main_gui_data *)p_data, "Enumerating Network");
	gdk_threads_leave();
	
	dns_enum_opts_init(&d_opts);
	d_opts.progress_update = (void *)&callback_update_progress;
	d_opts.progress_update_data = p_data;
	
	response = dns_enumerate_network_ex(p_data->c_host_manager, target_domain, &target_network, &d_opts);
	
	gdk_threads_enter();
	if (response == 0) {
		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Requesting WHOIS Records");
		gui_model_update_marquee((main_gui_data *)p_data, "Requesting WHOIS Records");
		gdk_threads_leave();
		whois_fill_host_manager(p_data->c_host_manager);
		gdk_threads_enter();
		gui_model_update_tree_and_marquee((main_gui_data*)p_data, NULL);
	}
	gtk_widget_destroy(p_data->popup_window);
	gdk_threads_leave();
	dns_enum_opts_destroy(&d_opts);
	return;
}

void gui_popup_thread_http_enumerate_hosts(popup_data *p_data) {
	http_link *link_anchor = NULL;
	kraken_thread k_thread;
	http_enum_opts h_opts;
	
	gdk_threads_enter();
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Scanning For Links");
	gui_model_update_marquee((main_gui_data *)p_data, "Scanning For Links");
	gdk_threads_leave();
	
	http_enum_opts_init(&h_opts);
	h_opts.progress_update = (void *)&callback_update_progress;
	h_opts.progress_update_data = p_data;
	
	http_enumerate_hosts_ex(p_data->c_host_manager, &link_anchor, &h_opts);
	
	gdk_threads_enter();
	gui_popup_select_hosts_from_http_links((main_gui_data *)p_data, link_anchor);
	gtk_widget_destroy(p_data->popup_window);
	gdk_threads_leave();
	http_enum_opts_destroy(&h_opts);
	return;
}

void gui_popup_thread_http_search_engine_bing(popup_data *p_data) {
	http_enum_opts h_opts;
	const gchar *text_entry;
	int response;
	char target_domain[DNS_MAX_FQDN_LENGTH + 1];
	
	memset(target_domain, '\0', sizeof(target_domain));
	gdk_threads_enter();
	text_entry = gtk_entry_get_text(GTK_ENTRY(p_data->text_entry0));
	gdk_threads_leave();
	if ((strlen(text_entry) > DNS_MAX_FQDN_LENGTH) || (strlen(text_entry) == 0)) {
		gdk_threads_enter();
		GUI_POPUP_ERROR_INVALID_DOMAIN_NAME(p_data->popup_window);
		gtk_widget_destroy(p_data->popup_window);
		gdk_threads_leave();
		return;
	}
	strncpy(target_domain, text_entry, DNS_MAX_FQDN_LENGTH);
	
	gdk_threads_enter();
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(p_data->misc_widget), "Searching Bing");
	gui_model_update_marquee((main_gui_data *)p_data, "Searching Bing");
	gdk_threads_leave();
	
	http_enum_opts_init(&h_opts);
	h_opts.progress_update = (void *)&callback_update_progress;
	h_opts.progress_update_data = p_data;
	if (p_data->k_opts->bing_api_key == NULL) {
		gdk_threads_enter();
		gui_popup_error_dialog(p_data->popup_window, "Bing API Key Not Set", "Error: Invalid API Key");
		gui_model_update_marquee((main_gui_data *)p_data, NULL);
		gdk_threads_leave();
	} else {
		http_enum_opts_set_bing_api_key(&h_opts, p_data->k_opts->bing_api_key);
		response = http_search_engine_bing_ex(p_data->c_host_manager, target_domain, &h_opts);
		gdk_threads_enter();
		if (response < 0) {
			if (response == -3) {
				gui_popup_error_dialog(p_data->popup_window, "Invalid Bing API Key", "Error: Invalid API Key");
			} else {
				GUI_POPUP_ERROR_GENERIC_ERROR(p_data->popup_window);
			}
			
		}
		gui_model_update_tree_and_marquee((main_gui_data *)p_data, NULL);
		gdk_threads_leave();
	}
	gdk_threads_enter();
	gtk_widget_destroy(p_data->popup_window);
	gdk_threads_leave();
	http_enum_opts_destroy(&h_opts);
	return;
}
