import kraken

try:
	import dns.resolver
	import dns.query
	import dns.zone
	from dns.exception import DNSException
	from dns.rdataclass import *
	from dns.rdatatype import *
except ImportError as err:
	kraken.log(kraken.LOG_LVL_WARNING, "could not import dnspython, can't load zone_transfer plugin")
	raise err

def check_for_zone_transfer(host):
	domains_done = []

	for hostname in host['names']:
		domain = '.'.join(hostname.split('.')[-2:])
		if domain in domains_done:
			continue
		domains_done.append(domain)
		kraken.log(kraken.LOG_LVL_INFO, "getting NS records for " + domain)
		answers = dns.resolver.query(domain, 'NS')
		nameservers = map(str, answers)

		zone = None
		for nameserver in nameservers:
			kraken.log(kraken.LOG_LVL_INFO, "trying a zone transfer for " + domain + " from name server " + nameserver)
			try:
				zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
				kraken.log(kraken.LOG_LVL_INFO, "successful tranfser for " + domain + " on server " + nameserver)
			except (DNSException, EOFError):
				kraken.log(kraken.LOG_LVL_INFO, "transfer failed on server: " + nameserver)
				continue
		if zone == None:
			continue
		for (name, ttl, rdata) in zone.iterate_rdatas('A'):
			if name.is_wild():
				continue
			if not name.is_absolute():
				name = name.concatenate(zone.origin)
			name = name.to_text().rstrip('.')
			ip = str(rdata)
			kraken.host_manager.set_host_details({'ipv4_addr':ip, 'names':name})

def initialize():
	kraken.callback_register('host_on_demand', check_for_zone_transfer)

def main(args):
	return 0
