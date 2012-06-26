from distutils.core import setup, Extension
import os

# this fixes the cwd so setup.py can be called from one directory up so
# the make command is easier
if os.path.basename(os.getcwd()) != 'pykraken_src':
	os.chdir('pykraken_src')

pykraken = Extension('pykraken',
			sources = [	'pykraken.c',
						'../src/dns_enum.c',
						'../src/host_manager.c',
						'../src/network_addr.c',
						'../src/whois_lookup.c',
						'../src/http_scan.c',
						'../src/logging.c',
			],
			libraries = ['cares', 'curl', 'uriparser', 'xml2'],
			include_dirs = ['/usr/local/include', '/usr/include', '/usr/include/libxml2', '../src'],
			library_dirs = ['/usr/local/lib', '/usr/lib'],
			define_macros = [ ('WITHOUT_LOG4C', None) ],
			)

setup (
	name = 'PyKraken',
	version = '0.1',
	description = 'This package allows functionality from Kraken to be used from Python',
	ext_modules = [ pykraken ]
	)
