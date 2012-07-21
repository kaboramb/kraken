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
