#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>
#include "hosts.h"
#include "host_manager.h"
#include "export.h"
#include "logging.h"
#include "whois_lookup.h"

int export_host_manager_to_csv(host_manager *c_host_manager, const char *dest_file) {
	FILE *csv_f;
	single_host_info *current_host;
	whois_record *current_who;
	unsigned int current_record_i;
	char ipstr[INET6_ADDRSTRLEN];
	
	csv_f = fopen(dest_file, "w");
	if (csv_f == NULL) {
		LOGGING_QUICK_ERROR("kraken.export", "could not open file to write CSV data to")
		return 1;
	}
	
	fprintf(csv_f, "Known Hosts:\n");
	fprintf(csv_f, "Hostname,IP Address\n");
	for (current_record_i = 0; current_record_i < c_host_manager->known_hosts; current_record_i++) {
		current_host = &c_host_manager->hosts[current_record_i];
		inet_ntop(AF_INET, &current_host->ipv4_addr, ipstr, sizeof(ipstr));
		fprintf(csv_f, "%s,%s\n", current_host->hostname, ipstr);
	}
	fprintf(csv_f, "\n");
	fprintf(csv_f, "Known Networks:\n");
	fprintf(csv_f, "Network,Network Name,Organization Name\n");
	for (current_record_i = 0; current_record_i < c_host_manager->known_whois_records; current_record_i++) {
		current_who = &c_host_manager->whois_records[current_record_i];
		fprintf(csv_f, "%s,%s,%s\n", current_who->cidr_s, current_who->netname, current_who->orgname);
	}
	logging_log("kraken.export", LOGGING_INFO, "exported %u hosts and %u whois records", c_host_manager->known_hosts, c_host_manager->known_whois_records);
	fclose(csv_f);
	return 0;
}

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
		LOGGING_QUICK_ERROR("kraken.export", "could not create the XML writer")
		return 1;
	}
	xmlTextWriterStartDocument(writer, NULL, KRAKEN_XML_ENCODING, NULL);
	xmlTextWriterStartElement(writer, BAD_CAST "kraken");
	xmlTextWriterWriteAttribute(writer, BAD_CAST "version", BAD_CAST KRAKEN_XML_VERSION);
	
	memset(timestamp, '\0', sizeof(timestamp));
	t = time(NULL);
	tmp_t = localtime(&t);
	strftime(timestamp, KRAKEN_XML_TIMESTAMP_LENGTH, "%a, %d %b %Y %T %z", tmp_t); /* RFC 2822 compliant */
	tmp = xml_convert_input(timestamp, KRAKEN_XML_ENCODING);
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
		tmp = xml_convert_input(ipstr, KRAKEN_XML_ENCODING);
		if (tmp != NULL) {
			xmlTextWriterWriteString(writer, tmp);
			xmlFree(tmp);
		}
		xmlTextWriterEndElement(writer);
		
		tmp = xml_convert_input(current_host->hostname, KRAKEN_XML_ENCODING);
		if (tmp != NULL) {
			xmlTextWriterWriteElement(writer, BAD_CAST "hostname", tmp);
			xmlFree(tmp);
		}
		
		if (current_host->n_aliases > 0) {
			xmlTextWriterStartElement(writer, BAD_CAST "aliases");
			tmp_iter = 0;
			while (tmp_iter < current_host->n_aliases) {
				tmp = xml_convert_input(current_host->aliases[tmp_iter], KRAKEN_XML_ENCODING);
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
			tmp = xml_convert_input(current_who->cidr_s, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "cidr", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->netname) > 0) {
			tmp = xml_convert_input(current_who->netname, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "netname", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->description) > 0) {
			tmp = xml_convert_input(current_who->description, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "description", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->orgname) > 0) {
			tmp = xml_convert_input(current_who->orgname, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "orgname", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->regdate_s) > 0) {
			tmp = xml_convert_input(current_who->regdate_s, KRAKEN_XML_ENCODING);
			if (tmp != NULL) {
				xmlTextWriterWriteElement(writer, BAD_CAST "regdate", tmp);
				xmlFree(tmp);
			}
		}
		if (strlen(current_who->updated_s) > 0) {
			tmp = xml_convert_input(current_who->updated_s, KRAKEN_XML_ENCODING);
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
	logging_log("kraken.export", LOGGING_INFO, "exported %u hosts and %u whois records", c_host_manager->known_hosts, c_host_manager->known_whois_records);
	return 0;
}

int import_host_record_from_xml(xmlNode *host_xml, single_host_info *tmp_host) {
	xmlNode *cur_node = NULL;
	xmlNode *alias_node = NULL;
	xmlAttr *attribute = NULL;
	xmlChar *value = NULL;
	xmlChar *attr_value = NULL;
	
	assert(host_xml != NULL);
	init_single_host(tmp_host);
	for (cur_node = host_xml->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrncmp(cur_node->name, (xmlChar *)"aliases", 7) == 0) {
			for (alias_node = cur_node->children; alias_node; alias_node = alias_node->next) {
				if (alias_node->type != XML_ELEMENT_NODE) {
					continue;
				}
				value = xmlNodeGetContent(alias_node);
				if (value == NULL) {
					continue;
				}
				if (xmlStrlen(value) == 0) {
					xmlFree(value);
					continue;
				}
				if (xmlStrncmp(alias_node->name, (xmlChar *)"alias", 5) == 0) {
					single_host_add_alias(tmp_host, (const char *)value);
				}
				xmlFree(value);
			}
			continue;
		}
		value = xmlNodeGetContent(cur_node);
		if (value == NULL) {
			continue;
		}
		if (xmlStrlen(value) == 0) {
			xmlFree(value);
			continue;
		}
		if (xmlStrncmp(cur_node->name, (xmlChar *)"ip", 2) == 0) {
			for (attribute = cur_node->properties; attribute; attribute = attribute->next) {
				if (xmlStrncmp(attribute->name, (xmlChar *)"version", 7) == 0) {
					attr_value = xmlNodeListGetString(cur_node->doc, attribute->children, 1);
					if (attr_value == NULL) {
						continue;
					}
					if (xmlStrlen(attr_value) == 0) {
						xmlFree(attr_value);
						continue;
					}
					if (xmlStrncmp(attr_value, (xmlChar *)"4", 1) == 0) {
						inet_pton(AF_INET, (const char *)value, &tmp_host->ipv4_addr);
					}
					xmlFree(attr_value);
				}
			}
		} else if (xmlStrncmp(cur_node->name, (xmlChar *)"hostname", 8) == 0) {
			strncpy(tmp_host->hostname, (const char *)value, DNS_MAX_FQDN_LENGTH);
		} else if (xmlStrncmp(cur_node->name, (xmlChar *)"alive", 5) == 0) {
			if (xmlStrncmp(value, (xmlChar *)"true", 4) == 0) {
				tmp_host->is_up = KRAKEN_HOST_UP;
			} else if (xmlStrncmp(value, (xmlChar *)"false", 5) == 0) {
				tmp_host->is_up = KRAKEN_HOST_DOWN;
			} else {
				tmp_host->is_up = KRAKEN_HOST_UNKNOWN;
			}
		} else if (xmlStrncmp(cur_node->name, (xmlChar *)"os", 2) == 0) {
			tmp_host->os = (unsigned char)atoi((const char *)value);
		}
		xmlFree(value);
	}
	return 0;
}

int import_whois_record_from_xml(xmlNode *whois_xml, whois_record *tmp_who) {
	xmlNode *cur_node = NULL;
	xmlChar *value = NULL;
	
	assert(whois_xml != NULL);
	memset(tmp_who, '\0', sizeof(whois_record));
	for (cur_node = whois_xml->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			value = xmlNodeGetContent(cur_node);
			if (value == NULL) {
				continue;
			}
			if (xmlStrlen(value) == 0) {
				xmlFree(value);
				continue;
			}
			if (xmlStrncmp(cur_node->name, (xmlChar *)"cidr", 4) == 0) {
				strncpy(tmp_who->cidr_s, (const char *)value, WHOIS_SZ_DATA_S);
			} else if (xmlStrncmp(cur_node->name, (xmlChar *)"netname", 7) == 0) {
				strncpy(tmp_who->netname, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrncmp(cur_node->name, (xmlChar *)"description", 11) == 0) {
				strncpy(tmp_who->description, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrncmp(cur_node->name, (xmlChar *)"orgname", 7) == 0) {
				strncpy(tmp_who->orgname, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrncmp(cur_node->name, (xmlChar *)"regdate", 7) == 0) {
				strncpy(tmp_who->regdate_s, (const char *)value, WHOIS_SZ_DATA_S);
			} else if (xmlStrncmp(cur_node->name, (xmlChar *)"updated", 7) == 0) {
				strncpy(tmp_who->updated_s, (const char *)value, WHOIS_SZ_DATA_S);
			}
			xmlFree(value);
		}
	}
	return 0;
}

int import_host_manager_from_xml(host_manager *c_host_manager, const char *source_file) {
	unsigned int old_host_count = 0;
	unsigned int old_whois_record_count = 0;
	xmlDoc *doc;
	xmlNode *root_element = NULL;
	xmlNode *host_records = NULL;
	xmlNode *who_records = NULL;
	xmlNode *cur_node = NULL;
	whois_record current_who;
	single_host_info current_host;
	/* xpath example http://xmlsoft.org/examples/xpath1.c */
	doc = xmlParseFile(source_file);
	if (doc == NULL) {
		LOGGING_QUICK_ERROR("kraken.export", "could not read/parse the XML document")
		return 1;
	}
	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		LOGGING_QUICK_ERROR("kraken.export", "could not retrieve the root element of the XML document")
		xmlFreeDoc(doc);
		return 2;
	}
	if (xmlStrncmp(root_element->name, (xmlChar *)"kraken", 6) != 0) {
		LOGGING_QUICK_ERROR("kraken.export", "the root XML node is not \"kraken\"")
		xmlFreeDoc(doc);
		return 3;
	}
	
	old_host_count = c_host_manager->known_hosts;
	old_whois_record_count = c_host_manager->known_whois_records;
	
	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			if (xmlStrncmp(cur_node->name, (xmlChar *)"whois_records", 13) == 0) {
				who_records = cur_node;
			} else if(xmlStrncmp(cur_node->name, (xmlChar *)"hosts", 5) == 0) {
				host_records = cur_node;
			}
		}
	}
	if ((host_records == NULL) || (who_records == NULL)) {
		LOGGING_QUICK_WARNING("kraken.export", "the XML document did not contain all the necessary nodes")
	}
	if (who_records != NULL) {
		for (cur_node = who_records->children; cur_node; cur_node = cur_node->next) {
			if (cur_node->type == XML_ELEMENT_NODE) {
				if (xmlStrncmp(cur_node->name, (xmlChar *)"whois_record", 12) == 0) {
					if (import_whois_record_from_xml(cur_node, &current_who) == 0) {
						host_manager_add_whois(c_host_manager, &current_who);
					}
				}
			}
		}
	}
	if (host_records != NULL) {
		for (cur_node = host_records->children; cur_node; cur_node = cur_node->next) {
			if (cur_node->type == XML_ELEMENT_NODE) {
				if (xmlStrncmp(cur_node->name, (xmlChar *)"host", 4) == 0) {
					if (import_host_record_from_xml(cur_node, &current_host) == 0) {
						host_manager_add_host(c_host_manager, &current_host);
						destroy_single_host(&current_host);
					}
				}
			}
		}
	}
	xmlFreeDoc(doc);
	logging_log("kraken.export", LOGGING_INFO, "imported %u hosts and %u whois records", (c_host_manager->known_hosts - old_host_count), (c_host_manager->known_whois_records - old_whois_record_count));
	return 0;
}
