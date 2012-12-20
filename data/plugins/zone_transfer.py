# zone_transfer.py
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
import socket

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

def check_domain_for_zone_transfer(domain):
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
		return

	names_to_ips = {}
	for (name, ttl, rdata) in zone.iterate_rdatas('A'):
		if name.is_wild():
			continue
		if not name.is_absolute():
			name = name.concatenate(zone.origin)
		name = name.to_text().rstrip('.')
		ip = str(rdata)
		kraken.host_manager.set_host_details({'ipv4_addr':ip, 'names':name})
		if not name in names_to_ips:
			names_to_ips[name] = []
		names_to_ips[name].append(ip)

	for (name, ttl, rdata) in zone.iterate_rdatas('CNAME'):
		if name.is_wild():
			continue
		if not name.is_absolute():
			name = name.concatenate(zone.origin)
		cname = name.to_text().rstrip('.')
		if rdata.target.is_absolute():
			target = rdata.target.to_text().rstrip('.')
		else:
			target = rdata.target.concatenate(zone.origin).to_text().rstrip('.')
		if target in names_to_ips:
			for ip in names_to_ips[target]:
				kraken.host_manager.set_host_details({'ipv4_addr':ip, 'names':[target, cname]})
		else:
			try:
				dnsresp = socket.gethostbyname_ex(target)
			except:
				continue	# probably a "herror: [Errno 4] No address associated with name" error
			if ip in dnsresp[2]:
				kraken.host_manager.add_hostname(ip, [target, cname])
	return

def check_hostnames_for_zone_transfer(host):
	domains_done = []

	for hostname in host['names']:
		domain = '.'.join(hostname.split('.')[-2:])
		if domain in domains_done:
			continue
		domains_done.append(domain)
		check_domain_for_zone_transfer(domain)

def initialize():
	kraken.callback_register('host_on_demand', check_hostnames_for_zone_transfer)

def main(args):
	if not len(args):
		return 0
	for domain in args.split(' '):
		check_domain_for_zone_transfer(domain)
	return 0
