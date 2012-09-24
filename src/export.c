#include "kraken.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "host_manager.h"
#include "export.h"
#include "whois_lookup.h"
#include "xml_utilities.h"

void export_csv_opts_init(export_csv_opts *e_opts) {
	memset(e_opts, '\0', sizeof(export_csv_opts));
	strcpy(e_opts->primary_delimiter, ",");
	strcpy(e_opts->secondary_delimiter, " ");
	strcpy(e_opts->new_line, "\n");
	e_opts->show_fields = 1;

	e_opts->filter_host_is_up = 0;

	e_opts->host_ipv4_addr = 1;
	e_opts->host_names = 1;

	e_opts->whois_cidr = 1;
	e_opts->whois_netname = 1;
	e_opts->whois_orgname = 1;
	return;
}

void export_csv_opts_destroy(export_csv_opts *e_opts) {
	memset(e_opts, '\0', sizeof(export_csv_opts));
	return;
}

int export_host_manager_to_csv_ex(host_manager *c_host_manager, const char *dest_file, export_csv_opts *e_opts) {
	FILE *csv_f;
	host_iter host_i;
	single_host_info *c_host;
	whois_iter whois_i;
	whois_record *current_who;
	hostname_iter hostname_i;
	char *hostname;
	char ipstr[INET6_ADDRSTRLEN];
	int use_delimiter = 0;

	csv_f = fopen(dest_file, "w");
	if (csv_f == NULL) {
		LOGGING_QUICK_ERROR("kraken.export", "could not open file to write CSV data to")
		return 1;
	}

	if (e_opts->show_fields) {
		if (e_opts->host_ipv4_addr || e_opts->host_names) {
			fprintf(csv_f, "Known Hosts:%s", e_opts->new_line);
		}
		if (e_opts->host_ipv4_addr) {
			fprintf(csv_f, "IP Address");
			use_delimiter = 1;
		}
		if (use_delimiter) {
			fprintf(csv_f, "%s", e_opts->primary_delimiter);
		}
		if (e_opts->host_names) {
			fprintf(csv_f, "Hostnames");
		}
		if (e_opts->host_ipv4_addr || e_opts->host_names) {
			fprintf(csv_f, "%s", e_opts->new_line);
		}
	}
	if (e_opts->host_ipv4_addr || e_opts->host_names) {
		host_manager_iter_host_init(c_host_manager, &host_i);
		while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
			if ((e_opts->filter_host_is_up) && (c_host->status != KRAKEN_HOST_STATUS_UP)) {
				continue;
			}
			use_delimiter = 0;
			if (e_opts->host_ipv4_addr) {
				inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));
				fprintf(csv_f, "%s", ipstr);
				use_delimiter = 1;
			}
			if (e_opts->host_names) {
				if (use_delimiter) {
					fprintf(csv_f, "%s", e_opts->primary_delimiter);
				}
				if (c_host->n_names) {
					single_host_iter_hostname_init(c_host, &hostname_i);
					while (single_host_iter_hostname_next(c_host, &hostname_i, &hostname)) {
						fprintf(csv_f, "%s%s", hostname, e_opts->secondary_delimiter);
					}
					fseek(csv_f, -strlen(e_opts->secondary_delimiter), SEEK_CUR);
					use_delimiter = 1;
				}
			}
			if (use_delimiter) {
				fprintf(csv_f, "%s", e_opts->new_line);
			}
		}
	}

	use_delimiter = 0;
	if (e_opts->show_fields) {
		if (e_opts->whois_cidr || e_opts->whois_netname || e_opts->whois_orgname) {
			if (e_opts->host_ipv4_addr || e_opts->host_names) {
				fprintf(csv_f, "%s", e_opts->new_line);
			}
			fprintf(csv_f, "Known Networks:%s", e_opts->new_line);
		}
		if (e_opts->whois_cidr) {
			fprintf(csv_f, "Network");
			use_delimiter = 1;
		}
		if (e_opts->whois_netname) {
			if (use_delimiter) {
				fprintf(csv_f, "%s", e_opts->primary_delimiter);
			}
			fprintf(csv_f, "Network Name");
			use_delimiter = 1;
		}
		if (e_opts->whois_orgname) {
			if (use_delimiter) {
				fprintf(csv_f, "%s", e_opts->primary_delimiter);
			}
			fprintf(csv_f, "Organization Name");
			use_delimiter = 1;
		}
		if (e_opts->whois_cidr || e_opts->whois_netname || e_opts->whois_orgname) {
			fprintf(csv_f, "%s", e_opts->new_line);
		}
	}

	if (e_opts->whois_cidr || e_opts->whois_netname || e_opts->whois_orgname) {
		host_manager_iter_whois_init(c_host_manager, &whois_i);
		while (host_manager_iter_whois_next(c_host_manager, &whois_i, &current_who)) {
			use_delimiter = 0;
			if (e_opts->whois_cidr) {
				if (use_delimiter) {
					fprintf(csv_f, "%s", e_opts->primary_delimiter);
				}
				fprintf(csv_f, "%s", current_who->cidr_s);
				use_delimiter = 1;
			}
			if (e_opts->whois_netname) {
				if (use_delimiter) {
					fprintf(csv_f, "%s", e_opts->primary_delimiter);
				}
				fprintf(csv_f, "%s", current_who->netname);
				use_delimiter = 1;
			}
			if (e_opts->whois_orgname) {
				if (use_delimiter) {
					fprintf(csv_f, "%s", e_opts->primary_delimiter);
				}
				fprintf(csv_f, "%s", current_who->orgname);
				use_delimiter = 1;
			}
			fprintf(csv_f, "%s", e_opts->new_line);
		}
	}

	logging_log("kraken.export", LOGGING_INFO, "exported %u hosts and %u whois records", c_host_manager->known_hosts, c_host_manager->known_whois_records);
	fclose(csv_f);
	return 0;
}

int export_host_manager_to_xml(host_manager *c_host_manager, const char *dest_file) {
	xmlTextWriterPtr writer;
	xmlChar *tmp;
	host_iter host_i;
	single_host_info *c_host;
	whois_iter whois_i;
	whois_record *current_who;
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
	host_manager_iter_host_init(c_host_manager, &host_i);
	while (host_manager_iter_host_next(c_host_manager, &host_i, &c_host)) {
		inet_ntop(AF_INET, &c_host->ipv4_addr, ipstr, sizeof(ipstr));

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

		if (c_host->n_names > 0) {
			xmlTextWriterStartElement(writer, BAD_CAST "hostnames");
			tmp_iter = 0;
			while (tmp_iter < c_host->n_names) {
				tmp = xml_convert_input(c_host->names[tmp_iter], KRAKEN_XML_ENCODING);
				if (tmp != NULL) {
					xmlTextWriterWriteElement(writer, BAD_CAST "hostname", tmp);
					xmlFree(tmp);
				}
				tmp_iter++;
			}
			xmlTextWriterEndElement(writer);
		}

		if (c_host->status == KRAKEN_HOST_STATUS_UP) {
			xmlTextWriterWriteElement(writer, BAD_CAST "status", BAD_CAST "up");
		} else if (c_host->status == KRAKEN_HOST_STATUS_DOWN) {
			xmlTextWriterWriteElement(writer, BAD_CAST "status", BAD_CAST "down");
		} else {
			xmlTextWriterWriteElement(writer, BAD_CAST "status", BAD_CAST "unknown");
		}

		xmlTextWriterWriteFormatElement(writer, BAD_CAST "os", "%u", c_host->os);
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterEndElement(writer);

	xmlTextWriterStartElement(writer, BAD_CAST "whois_records");
	host_manager_iter_whois_init(c_host_manager, &whois_i);
	while (host_manager_iter_whois_next(c_host_manager, &whois_i, &current_who)) {
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
	single_host_init(tmp_host);
	for (cur_node = host_xml->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(cur_node->name, (xmlChar *)"hostnames") == 0) {
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
				if (xmlStrcmp(alias_node->name, (xmlChar *)"hostname") == 0) {
					single_host_add_hostname(tmp_host, (const char *)value);
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
		if (xmlStrcmp(cur_node->name, (xmlChar *)"ip") == 0) {
			for (attribute = cur_node->properties; attribute; attribute = attribute->next) {
				if (xmlStrcmp(attribute->name, (xmlChar *)"version") == 0) {
					attr_value = xmlNodeListGetString(cur_node->doc, attribute->children, 1);
					if (attr_value == NULL) {
						continue;
					}
					if (xmlStrlen(attr_value) == 0) {
						xmlFree(attr_value);
						continue;
					}
					if (xmlStrcmp(attr_value, (xmlChar *)"4") == 0) {
						inet_pton(AF_INET, (const char *)value, &tmp_host->ipv4_addr);
					}
					xmlFree(attr_value);
				}
			}
		} else if (xmlStrcmp(cur_node->name, (xmlChar *)"status") == 0) {
			if (xmlStrcmp(value, (xmlChar *)"up") == 0) {
				tmp_host->status = KRAKEN_HOST_STATUS_UP;
			} else if (xmlStrcmp(value, (xmlChar *)"down") == 0) {
				tmp_host->status = KRAKEN_HOST_STATUS_DOWN;
			} else {
				tmp_host->status = KRAKEN_HOST_STATUS_UNKNOWN;
			}
		} else if (xmlStrcmp(cur_node->name, (xmlChar *)"os") == 0) {
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
			if (xmlStrcmp(cur_node->name, (xmlChar *)"cidr") == 0) {
				strncpy(tmp_who->cidr_s, (const char *)value, WHOIS_SZ_DATA_S);
			} else if (xmlStrcmp(cur_node->name, (xmlChar *)"netname") == 0) {
				strncpy(tmp_who->netname, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrcmp(cur_node->name, (xmlChar *)"description") == 0) {
				strncpy(tmp_who->description, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrcmp(cur_node->name, (xmlChar *)"orgname") == 0) {
				strncpy(tmp_who->orgname, (const char *)value, WHOIS_SZ_DATA);
			} else if (xmlStrcmp(cur_node->name, (xmlChar *)"regdate") == 0) {
				strncpy(tmp_who->regdate_s, (const char *)value, WHOIS_SZ_DATA_S);
			} else if (xmlStrcmp(cur_node->name, (xmlChar *)"updated") == 0) {
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
	single_host_info c_host;

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
	if (xmlStrcmp(root_element->name, (xmlChar *)"kraken") != 0) {
		LOGGING_QUICK_ERROR("kraken.export", "the root XML node is not \"kraken\"")
		xmlFreeDoc(doc);
		return 3;
	}

	old_host_count = c_host_manager->known_hosts;
	old_whois_record_count = c_host_manager->known_whois_records;

	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			if (xmlStrcmp(cur_node->name, (xmlChar *)"whois_records") == 0) {
				who_records = cur_node;
			} else if(xmlStrcmp(cur_node->name, (xmlChar *)"hosts") == 0) {
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
				if (xmlStrcmp(cur_node->name, (xmlChar *)"whois_record") == 0) {
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
				if (xmlStrcmp(cur_node->name, (xmlChar *)"host") == 0) {
					if (import_host_record_from_xml(cur_node, &c_host) == 0) {
						host_manager_add_host(c_host_manager, &c_host);
						single_host_destroy(&c_host);
					}
				}
			}
		}
	}
	xmlFreeDoc(doc);
	logging_log("kraken.export", LOGGING_INFO, "imported %u hosts and %u whois records", (c_host_manager->known_hosts - old_host_count), (c_host_manager->known_whois_records - old_whois_record_count));
	return 0;
}
