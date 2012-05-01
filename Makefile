CC = gcc
PY = python
CFLAGS = -Wall -O0 -ggdb -D DEBUG
GTKFLAGS = $(shell pkg-config --cflags --libs gtk+-2.0)

all: kraken remove_intermediates pykraken

kraken: dns_enum.o  gui_main.o host_manager.o kraken.o network_addr.o whois_lookup.o
	$(CC) $(CFLAGS) $(GTKFLAGS) -lcares -o kraken dns_enum.o gui_main.o host_manager.o kraken.o network_addr.o whois_lookup.o

dns_enum.o:
	$(CC) $(CFLAGS) -c dns_enum.c

gui_main.o:
	$(CC) $(CFLAGS) $(GTKFLAGS) -c gui_main.c

host_manager.o:
	$(CC) $(CFLAGS) -c host_manager.c

kraken.o:
	$(CC) $(CFLAGS) -c kraken.c

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
