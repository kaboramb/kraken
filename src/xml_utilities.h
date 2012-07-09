#ifndef _KRAKEN_XML_UTILITIES_H
#define _KRAKEN_XML_UTILITIES_H

#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>

#define KRAKEN_XML_ENCODING "ISO-8859-1"
#define KRAKEN_XML_TIMESTAMP_LENGTH 255
#define KRAKEN_XML_VERSION "1.0"

xmlChar *xml_convert_input(const char *in, const char *encoding);

#endif
