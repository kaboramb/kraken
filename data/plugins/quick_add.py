import kraken

def main(args):
	if not len(args):
		return 0
	for name in args.split(' '):
		kraken.host_manager.quick_add_by_name(name)
	return 0
