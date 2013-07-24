# you_get_signal.py
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
# * Neither the name of SecureState Consulting nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import kraken
import urllib2
import json
import socket

YOU_GET_SIGNAL_URL = 'http://www.yougetsignal.com/tools/web-sites-on-web-server/php/get-web-sites-on-web-server-json-data.php'

def you_get_signal_scan(host):
	ip = host['ipv4_addr']
	url_h = urllib2.urlopen(YOU_GET_SIGNAL_URL, "remoteAddress={0}&key=".format(ip))
	try:
		data = json.load(url_h)
	except:
		kraken.log(kraken.LOG_LVL_WARNING, "failed to get yougetsignal data")
		raise kraken.error("failed to get yougetsignal data")
	if data['status'].lower() != 'success':
		kraken.log(kraken.LOG_LVL_WARNING, data['message'])
		raise kraken.error(" ".join(data['message'].split()[:6]))
	if str(data.get('domainCount', '0')) == '0':
		kraken.log(kraken.LOG_LVL_DEBUG, 'you_get_signal returned 0 domains for ' + ip)
		return
	domainArray = map(lambda x: x[0], data['domainArray'])
	if not len(domainArray):
		return
	known_hostnames = kraken.host_manager.get_hostnames(ip)
	for name in known_hostnames:
		if name in domainArray:
			domainArray.remove(name)
	if not len(domainArray):
		return
	for name in domainArray:
		try:
			dnsresp = socket.gethostbyname_ex(name)
		except:
			return	# probably a "herror: [Errno 4] No address associated with name" error
		if ip in dnsresp[2]:
			kraken.host_manager.add_hostname(ip, name)

def initialize():
	kraken.callback_register('host_on_demand', you_get_signal_scan)

def main(args):
	ips = kraken.host_manager.get_hosts()
	for ip in ips:
		kraken.log(kraken.LOG_LVL_DEBUG, 'running you_get_signal on ip: ' + ip)
		you_get_signal_scan({'ipv4_addr':ip})
	return 0
