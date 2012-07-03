#ifndef _KRAKEN_EXPORT_H
#define _KRAKEN_EXPORT_H

#include "kraken.h"

#define KRAKEN_XML_ENCODING "ISO-8859-1"
#define KRAKEN_XML_TIMESTAMP_LENGTH 255
#define KRAKEN_XML_VERSION "1.0"

int export_host_manager_to_csv(host_manager *c_host_manager, const char *dest_file);
int export_host_manager_to_xml(host_manager *c_host_manager, const char *dest_file);
int import_host_manager_from_xml(host_manager *c_host_manager, const char *source_file);

#endif
