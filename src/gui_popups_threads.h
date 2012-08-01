#ifndef _KRAKEN_GUI_POPUPS_THREADS_H
#define _KRAKEN_GUI_POPUPS_THREADS_H

#include "kraken.h"
#include "dns_enum.h"
#include "gui_popups.h"
#include "http_scan.h"
#include "network_addr.h"

void callback_thread_start(GtkWidget *widget, popup_data *p_data);
void callback_thread_cancel_action(GtkWidget *widget, popup_data *p_data);
void callback_thread_update_progress(unsigned int current, unsigned int high, popup_data *p_data);

void gui_popup_thread_dns_enum_domain(popup_data *p_data);
void gui_popup_thread_dns_enum_network(popup_data *gpt_data);
void gui_popup_thread_http_scrape_url_for_links(popup_data *p_data);
void gui_popup_thread_http_scrape_hosts_for_links(popup_data *p_data);
void gui_popup_thread_http_search_engine_bing(popup_data *p_data);

#endif
