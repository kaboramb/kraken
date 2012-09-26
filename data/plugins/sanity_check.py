import kraken

def initialize():
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check initialized successfully")
	return 0

def main(args):
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check main() method called")
	kraken.log(kraken.LOG_LVL_NOTICE, "arguments supplied are: " + str(args))
	return 0

def finalize():
	kraken.log(kraken.LOG_LVL_NOTICE, "kraken plugin sanity_check finalized successfully")
	return 0
