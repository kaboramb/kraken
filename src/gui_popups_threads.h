#ifndef _KRAKEN_GUI_POPUPS_THREADS_H
#define _KRAKEN_GUI_POPUPS_THREADS_H

#include "kraken.h"
#include "dns_enum.h"
#include "gui_popups.h"
#include "http_scan.h"
#include "network_addr.h"

void gui_popup_thread_dns_enumerate_domain(popup_data *p_data);
void gui_popup_thread_dns_enumerate_network(popup_data *gpt_data);
void gui_popup_thread_http_enumerate_hosts(popup_data *p_data);
void gui_popup_thread_http_search_engine_bing(popup_data *p_data);

#endif
