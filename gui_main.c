#include <gtk/gtk.h>
#include <arpa/inet.h>
#include "gui_menu_functions.h"
#include "gui_model.h"
#include "hosts.h"
#include "host_manager.h"
#include "whois_lookup.h"

int gui_show_main_window(host_manager *c_host_manager) {
	GtkWidget *window;
	GtkWidget *scroll_window;
	GtkWidget *main_vbox, *hbox;
	GtkWidget *main_menu_bar;
	GtkWidget *view;
	main_gui_data m_data;
	
	gtk_init(NULL, NULL);
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);	
	g_signal_connect(window, "delete_event", gtk_main_quit, NULL); /* dirty */
	gtk_window_set_title(GTK_WINDOW(window), "Kraken");
	gtk_container_set_border_width(GTK_CONTAINER(window), 0);
	gtk_widget_set_size_request(window, 550, 600);
	
	main_vbox = gtk_vbox_new(FALSE, 1);
	gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
	gtk_container_add(GTK_CONTAINER(window), main_vbox);
	
	scroll_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll_window), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	
	view = create_view_and_model(c_host_manager);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll_window), view);
	
	m_data.tree_view = view;
	m_data.c_host_manager = c_host_manager;
	main_menu_bar = get_main_menubar(window, &m_data);
	
	hbox = gtk_hbox_new(FALSE, 0);
	m_data.main_marquee = hbox;
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 2);
	gtk_widget_show(hbox);
	
	gtk_box_pack_start(GTK_BOX(main_vbox), main_menu_bar, FALSE, TRUE, 0);
	gtk_box_pack_start(GTK_BOX(main_vbox), scroll_window, TRUE, TRUE, 0);
	gtk_box_pack_end(GTK_BOX(main_vbox), hbox, FALSE, FALSE, 0);
	
	gtk_widget_show_all(window);
	gui_model_update_tree_and_marquee(&m_data);
	gtk_main();
	return 0;
}
