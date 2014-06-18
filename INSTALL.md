# Overview
The dependencies listed below for Ubuntu 14.04 should be compatible with newer versions of Ubuntu as well.

## Dependencies
### Required Packages
Ubuntu 14.04

 * libc-ares2
 * libc-ares-dev
 * python-dev
 * liburiparser1
 * liburiparser-dev
 * liblog4c3
 * liblog4c-dev
 * libgtk2.0-0
 * libgtk2.0-dev
 * libcurl4-openssl-dev
 * libxml2
 * libxml2-dev

<pre>
[user@localhost kraken]$ sudo apt-get install \
libc-ares2 libc-ares-dev \
python-dev python-dnspython \
liburiparser1 liburiparser-dev \
liblog4c3 liblog4c-dev \
libgtk2.0-0 libgtk2.0-dev \
libcurl4-openssl-dev \
libxml2 libxml2-dev
</pre>

### Recommended Packages
Ubuntu 14.04

* [python-dnspython](http://www.dnspython.org/)
* [python-tldextract](http://pypi.python.org/pypi/tldextract/)

<pre>
[user@localhost kraken]$ sudo pip install dnspython tldextract
</pre>

## Building and Installing
1) Setup auto-tools:

<pre>
[user@localhost kraken]$ aclocal
[user@localhost kraken]$ autoconf
[user@localhost kraken]$ automake -a
</pre>

2) Run the standard configure make make install
<pre>
[user@localhost kraken]$ ./configure
[user@localhost kraken]$ make
[user@localhost kraken]$ sudo make install
</pre>
