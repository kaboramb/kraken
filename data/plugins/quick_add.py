import kraken

def main(args):
	if not len(args):
		return 0
	kraken.host_manager.quick_add_by_name(args)
	return 0
