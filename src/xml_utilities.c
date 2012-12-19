// xml_utilities.c
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
// * Neither the name of SecureState Consulting nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <assert.h>
#include <string.h>

#include "xml_utilities.h"

xmlChar *xml_convert_input(const char *in, const char *encoding) {
	xmlChar *out;
	int ret;
	int size;
	int out_size;
	int temp;
	xmlCharEncodingHandlerPtr handler;
	handler = xmlFindCharEncodingHandler(encoding);
	assert(handler != NULL);
	size = (int)strlen(in) + 1;
	out_size = size * 2 - 1;
	out = (unsigned char *)xmlMalloc((size_t) out_size);
	if (out != NULL) {
		temp = size - 1;
		ret = handler->input(out, &out_size, (const xmlChar *)in, &temp);
		if ((ret < 0) || (temp - size + 1)) {
			xmlFree(out);
			out = 0;
		} else {
			out = (unsigned char *)xmlRealloc(out, out_size + 1);
			out[out_size] = 0;  /*null terminating out */
		}
	}
	return out;
}
