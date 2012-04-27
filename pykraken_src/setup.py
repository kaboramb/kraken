from distutils.core import setup, Extension
import os

# this fixes the cwd so setup.py can be called from one directory up so
# the make command is easier
if os.path.basename(os.getcwd()) != 'pykraken_src':
	os.chdir('pykraken_src')

pykraken = Extension('pykraken',
			sources = [	'pykraken.c',
						'../dns_enum.c',
						'../host_manager.c',
						'../network_addr.c',
						'../whois_lookup.c',
			],
			libraries = ['cares'],
			include_dirs = ['/usr/local/include', '/usr/include', '..'],
			library_dirs = ['/usr/local/lib', '/usr/lib']
			)

setup (
	name = 'PyKraken',
	version = '0.1',
	description = 'This package allows functionality from Kraken to be used from Python',
	ext_modules = [ pykraken ]
	)
