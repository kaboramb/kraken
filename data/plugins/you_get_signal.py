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
	if data['domainCount'] == 0:
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
		you_get_signal_scan({'ipv4_addr':ip})
	return 0
