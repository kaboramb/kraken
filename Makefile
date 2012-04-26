CC = gcc
CFLAGS = -Wall -O0 -ggdb -D DEBUG

kraken: kraken.c dns_enum.c host_manager.c
	$(CC) $(CFLAGS) -lcares -o kraken kraken.c host_manager.c dns_enum.c whois_lookup.c network_addr.c

clean:
	rm kraken
