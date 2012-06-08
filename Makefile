CC = gcc
PY = python
CFLAGS = -Wall -O0 -ggdb
GTKFLAGS = $(shell pkg-config --cflags --libs gtk+-2.0)
XMLFLAGS = $(shell pkg-config --cflags --libs xml2)

all: kraken remove_intermediates pykraken

kraken: dns_enum.o export.o gui_main.o gui_menu_functions.o gui_model.o gui_popups.o http_scan.o host_manager.o kraken.o logging.o network_addr.o whois_lookup.o
	$(CC) $(CFLAGS) $(GTKFLAGS) $(XMLFLAGS) -lcares -lcurl -llog4c -luriparser -o kraken dns_enum.o export.o gui_main.o gui_menu_functions.o gui_model.o gui_popups.o http_scan.o host_manager.o kraken.o logging.o network_addr.o whois_lookup.o

dns_enum.o:
	$(CC) $(CFLAGS) -c dns_enum.c

export.o:
	$(CC) $(CFLAGS) $(XMLFLAGS) -c export.c

gui_main.o:
	$(CC) $(CFLAGS) $(GTKFLAGS) -c gui_main.c

gui_menu_functions.o:
	$(CC) $(CFLAGS) $(GTKFLAGS) -c gui_menu_functions.c

gui_model.o:
	$(CC) $(CFLAGS) $(GTKFLAGS) -c gui_model.c

gui_popups.o:
	$(CC) $(CFLAGS) $(GTKFLAGS) -c gui_popups.c

http_scan.o:
	$(CC) $(CFLAGS) $(XMLFLAGS) -c http_scan.c

host_manager.o:
	$(CC) $(CFLAGS) -c host_manager.c

kraken.o:
	$(CC) $(CFLAGS) -c kraken.c

logging.o:
	$(CC) $(CFLAGS) -c logging.c

network_addr.o:
	$(CC) $(CFLAGS) -c network_addr.c

whois_lookup.o:
	$(CC) $(CFLAGS) -c whois_lookup.c

clean: remove_intermediates remove_pykraken_intermediates
	rm -rf kraken

remove_intermediates:
	rm -rf *.o

pykraken:
	$(PY) pykraken_src/setup.py build

remove_pykraken_intermediates:
	rm -rf pykraken_src/build
