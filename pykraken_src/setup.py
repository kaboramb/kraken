# setup.py
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

from distutils.core import setup, Extension
import os

# this fixes the cwd so setup.py can be called from one directory up so
# the make command is easier
if os.path.basename(os.getcwd()) != 'pykraken_src':
	os.chdir('pykraken_src')

pykraken = Extension('pykraken',
			sources = [	'pykraken.c',
						'../src/kraken_thread.c',
						'../src/kraken_options.c',
						'../src/dns_enum.c',
						'../src/host_manager.c',
						'../src/network_addr.c',
						'../src/whois_lookup.c',
						'../src/http_scan.c',
						'../src/logging.c',
						'../src/utilities.c',
						'../src/xml_utilities.c'
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
