#ifndef _KRAKEN_GUI_MAIN_H
#define _KRAKEN_GUI_MAIN_H

#include "kraken.h"

void gui_main_data_init(main_gui_data *m_data, kraken_opts *k_opts, host_manager *c_host_manager);
int gui_show_main_window(main_gui_data *m_data);

#endif
