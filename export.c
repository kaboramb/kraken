#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include "hosts.h"
#include "export.h"
#include "logging.h"

xmlChar *ConvertInput(const char *in, const char *encoding) {
	xmlChar *out;
	int ret;
	int size;
	int out_size;
	int temp;
	xmlCharEncodingHandlerPtr handler;
	handler = xmlFindCharEncodingHandler(encoding);
	if (!handler) {
		return NULL;
	}
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

int export_host_manager_to_xml(host_manager *c_host_manager, const char *dest_file) {
	xmlTextWriterPtr writer;
	xmlChar *tmp;
	single_host_info *current_host;
	whois_record *current_who;
	unsigned int current_record_i;
	unsigned int tmp_iter;
	char timestamp[KRAKEN_XML_TIMESTAMP_LENGTH + 1];
	char ipstr[INET6_ADDRSTRLEN];
	time_t t;
	struct tm *tmp_t;
	
	writer = xmlNewTextWriterFilename(dest_file, 0);
	if (writer == NULL) {
		LOGGING_QUICK_ERROR("kraken.export", "error creating the XML writer")
		return 1;
	}
	xmlTextWriterStartDocument(writer, NULL, KRAKEN_XML_ENCODING, NULL);
	xmlTextWriterStartElement(writer, BAD_CAST "kraken");
	xmlTextWriterWriteAttribute(writer, BAD_CAST "version", BAD_CAST KRAKEN_XML_VERSION);
	
	memset(timestamp, '\0', sizeof(timestamp));
	t = time(NULL);
	tmp_t = localtime(&t);
	strftime(timestamp, KRAKEN_XML_TIMESTAMP_LENGTH, "%a %b %d %C %H:%M", tmp_t);
	tmp = ConvertInput(timestamp, KRAKEN_XML_ENCODING);
	if (tmp != NULL) {
		xmlTextWriterWriteElement(writer, BAD_CAST "timestamp", tmp);
		xmlFree(tmp);
	}
	
	xmlTextWriterStartElement(writer, BAD_CAST "hosts");
	for (current_record_i = 0; current_record_i < c_host_manager->known_hosts; current_record_i++) {
		current_host = &c_host_manager->hosts[current_record_i];
		inet_ntop(AF_INET, &current_host->ipv4_addr, ipstr, sizeof(ipstr));
		
		/* make the host node */
		xmlTextWriterStartElement(writer, BAD_CAST "host");
		
		xmlTextWriterStartElement(writer, BAD_CAST "ip");
		xmlTextWriterWriteAttribute(writer, BAD_CAST "version", BAD_CAST "4");
		tmp = ConvertInput(ipstr, KRAKEN_XML_ENCODING);
		if (tmp != NULL) {
			xmlTextWriterWriteString(writer, tmp);
			xmlFree(tmp);
		}
		xmlTextWriterEndElement(writer);
		
		tmp = ConvertInput(current_host->hostname, KRAKEN_XML_ENCODING);
		if (tmp != NULL) {
			xmlTextWriterWriteElement(writer, BAD_CAST "hostname", tmp);
			xmlFree(tmp);
		}
		
		if (current_host->n_aliases > 0) {
			xmlTextWriterStartElement(writer, BAD_CAST "aliases");
			tmp_iter = 0;
			while (tmp_iter < current_host->n_aliases) {
				tmp = ConvertInput(current_host->aliases[tmp_iter], KRAKEN_XML_ENCODING);
				if (tmp != NULL) {
					xmlTextWriterWriteElement(writer, BAD_CAST "alias", tmp);
					xmlFree(tmp);
				}
				tmp_iter++;
			}
			xmlTextWriterEndElement(writer);
		}
		
		if (current_host->is_up == KRAKEN_HOST_UP) {
			xmlTextWriterWriteElement(writer, BAD_CAST "alive", BAD_CAST "true");
		} else if (current_host->is_up == KRAKEN_HOST_DOWN) {
			xmlTextWriterWriteElement(writer, BAD_CAST "alive", BAD_CAST "false");
		} else {
			xmlTextWriterWriteElement(writer, BAD_CAST "alive", BAD_CAST "unknown");
		}
		
		xmlTextWriterWriteFormatElement(writer, BAD_CAST "os", "%u", current_host->os);
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterEndElement(writer);
	
	xmlTextWriterStartElement(writer, BAD_CAST "whois_records");
	for (current_record_i = 0; current_record_i < c_host_manager->known_whois_records; current_record_i++) {
		current_who = &c_host_manager->whois_records[current_record_i];
		
		/* make the whois_record node */
		xmlTextWriterStartElement(writer, BAD_CAST "whois_record");
		
		if (strlen(current_who->cidr_s) > 0) {
			tmp = ConvertInput(current_who->cidr_s, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "cidr", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->netname) > 0) {
			tmp = ConvertInput(current_who->netname, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "netname", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->description) > 0) {
			tmp = ConvertInput(current_who->description, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "description", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->orgname) > 0) {
			tmp = ConvertInput(current_who->orgname, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "orgname", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->regdate_s) > 0) {
			tmp = ConvertInput(current_who->regdate_s, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "regdate", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->updated_s) > 0) {
			tmp = ConvertInput(current_who->updated_s, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "updated", tmp);
				xmlFree(tmp);
			}
		}
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterEndElement(writer);
	
	xmlTextWriterEndDocument(writer);
	xmlFreeTextWriter(writer);
	return 0;
}
