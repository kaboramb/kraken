import kraken

def report_host_up(host):
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken marked host {} as up".format(host['ipv4_addr']))
	return

def initialize():
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check initialized successfully")
	kraken.callback_register('host_on_status_up', report_host_up)
	return 0

def main(args):
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check main() method called")
	kraken.log(kraken.LOG_LVL_NOTICE, "arguments supplied are: " + str(args))
	kraken.log(kraken.LOG_LVL_NOTICE, "throwing an error...")
	raise Exception('fake')
	return 0

def finalize():
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check finalized successfully")
	return 0
