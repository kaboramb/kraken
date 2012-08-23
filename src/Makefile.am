AM_CFLAGS = -Wall -O2
AM_LDFLAGS =

bin_PROGRAMS = kraken
kraken_SOURCES = dns_enum.c export.c gui_main.c gui_menu_functions.c \
	gui_model.c gui_popups.c http_scan.c host_manager.c kraken.c \
	kraken_options.c logging.c network_addr.c whois_lookup.c dns_enum.h \
	export.h gui_main.h gui_menu_functions.h gui_model.h gui_popups.h \
	http_scan.h host_manager.h kraken.h kraken_options.h logging.h \
	network_addr.h whois_lookup.h kraken_thread.c kraken_thread.h \
	gui_popups_threads.c gui_popups_threads.h utilities.c utilities.h \
	xml_utilities.c xml_utilities.h plugins.c plugins.h
kraken_CFLAGS = $(GTK_CFLAGS) $(LIBXML_CFLAGS) $(PYTHON_INCLUDE) -DDATAROOTDIR='"$(datarootdir)"'
kraken_LDADD = $(GTK_LIBS) $(LIBXML_LIBS)
