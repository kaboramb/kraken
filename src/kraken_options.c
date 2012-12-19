// kraken_options.c
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

#include "kraken.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>

#include "logging.h"
#include "utilities.h"
#include "xml_utilities.h"

void kraken_opts_init(kraken_opts *k_opts) {
	memset(k_opts, '\0', sizeof(struct kraken_opts));
	k_opts->dns_wordlist = NULL;
	k_opts->bing_api_key = NULL;
	return;
}

int kraken_opts_init_from_config(kraken_opts *k_opts) {
	char conf_file_path[256];

	if (kraken_conf_get_data_directory_path(conf_file_path, 256) != 0) {
		LOGGING_QUICK_ERROR("kraken.opts", "could not determine the path to the data directory")
		return 100;
	}
	if (util_dir_create_if_not_exists(conf_file_path) != 0) {
		LOGGING_QUICK_ERROR("kraken.opts", "could not create the data directory")
		return 101;
	}
	kraken_conf_get_config_file_path(conf_file_path, 256);
	logging_log("kraken.opts", LOGGING_INFO, "loading configuration file: %s", conf_file_path);
	kraken_opts_init(k_opts);

	return kraken_conf_load_config(conf_file_path, k_opts);
}

void kraken_opts_destroy(kraken_opts *k_opts) {
	if (k_opts->dns_wordlist != NULL) {
		free(k_opts->dns_wordlist);
		k_opts->dns_wordlist = NULL;
	}
	if (k_opts->bing_api_key != NULL) {
		free(k_opts->bing_api_key);
		k_opts->bing_api_key = NULL;
	}
	return;
}

int kraken_opts_get(kraken_opts *k_opts, int type, void *value) {
	switch (type) {
		case KRAKEN_OPT_DNS_WORDLIST:
			if (k_opts->dns_wordlist == NULL) {
				return -1;
			}
			*(char **)value = k_opts->dns_wordlist;
			break;
		case KRAKEN_OPT_BING_API_KEY:
			if (k_opts->bing_api_key == NULL) {
				return -1;
			}
			*(char **)value = k_opts->bing_api_key;
			break;
		default:
			return -1;
			break;
	}
	return 0;
}

int kraken_opts_set(kraken_opts *k_opts, int type, void *value) {
	void *new_value;
	switch (type) {
		case KRAKEN_OPT_DNS_WORDLIST:
			if (k_opts->dns_wordlist != NULL) {
				free(k_opts->dns_wordlist);
			}
			new_value = malloc(strlen(value) + 1);
			if (new_value == NULL) {
				return -2;
			}
			strncpy(new_value, value, strlen(value));
			k_opts->dns_wordlist = (char *)new_value;
			k_opts->dns_wordlist[strlen(value)] = '\0';
			break;
		case KRAKEN_OPT_BING_API_KEY:
			if (k_opts->bing_api_key != NULL) {
				free(k_opts->bing_api_key);
			}
			new_value = malloc(strlen(value) + 1);
			if (new_value == NULL) {
				return -2;
			}
			strncpy(new_value, value, strlen(value));
			k_opts->bing_api_key = (char *)new_value;
			k_opts->bing_api_key[strlen(value)] = '\0';
			break;
		default:
			return -1;
			break;
	}
	return 0;
}

int kraken_conf_get_data_directory_path(char *path, size_t pathsz) {
	char *envpath;

	memset(path, '\0', pathsz);
	envpath = getenv(KRAKEN_CONF_DIR_ENV_VAR);
	if (envpath == NULL) {
		return 1;
	}
	if ((strlen(envpath) + strlen(KRAKEN_CONF_DIR) + 1) > (pathsz - 1)) {
		return 2;
	}
	strcpy(path, envpath);
	strcat(path, KRAKEN_CONF_DIR_SEP);
	strcat(path, KRAKEN_CONF_DIR);
	return 0;
}

int kraken_conf_get_config_file_path(char *path, size_t pathsz) {
	int response;

	response = kraken_conf_get_data_directory_path(path, pathsz);
	if (response) {
		return response;
	}
	if ((strlen(path) + strlen(KRAKEN_CONF_FILE) + 1) > pathsz - 1) {
		return 2;
	}
	strcat(path, KRAKEN_CONF_DIR_SEP);
	strcat(path, KRAKEN_CONF_FILE);
	return 0;
}

int kraken_conf_load_config(const char *conf_path, kraken_opts *k_opts) {
	xmlDoc *doc;
	xmlNode *root_element = NULL;
	xmlNode *cur_node = NULL;
	xmlNode *dns_settings = NULL;
	xmlNode *http_settings = NULL;
	xmlAttr *attribute = NULL;
	xmlChar *value = NULL;
	int correct_type = 0;

	if (access(conf_path, R_OK) == -1) {
		logging_log("kraken.conf", LOGGING_ERROR, "could not read configuration file: %s", conf_path);
		return 1;
	}
	doc = xmlParseFile(conf_path);

	if (doc == NULL) {
		LOGGING_QUICK_ERROR("kraken.conf", "could not read/parse the XML document")
		return 2;
	}
	root_element = xmlDocGetRootElement(doc);
	if (root_element == NULL) {
		LOGGING_QUICK_ERROR("kraken.conf", "could not retrieve the root element of the XML document")
		xmlFreeDoc(doc);
		return 2;
	}
	if (xmlStrcmp(root_element->name, (xmlChar *)"kraken") != 0) {
		LOGGING_QUICK_ERROR("kraken.conf", "the root XML node is not \"kraken\"")
		xmlFreeDoc(doc);
		return 2;
	}
	for (attribute = root_element->properties; attribute != NULL; attribute = attribute->next) {
		if (xmlStrcmp(attribute->name, (xmlChar *)"type") != 0) {
			continue;
		}
		value = xmlNodeListGetString(root_element->doc, attribute->children, 1);
		assert(value != NULL);
		if (xmlStrcmp(value, (xmlChar *)"config") == 0) {
			correct_type = 1;
			break;
		}
	}
	if (!correct_type) {
		LOGGING_QUICK_ERROR("kraken.conf", "the kraken XML file was not the correct type")
		return 2;
	}
	for (cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (xmlStrcmp(cur_node->name, (xmlChar *)"dns") == 0) {
			dns_settings = cur_node;
		} else if(xmlStrcmp(cur_node->name, (xmlChar *)"http") == 0) {
			http_settings = cur_node;
		}
	}

	if (dns_settings != NULL) {
		for (cur_node = dns_settings->children; cur_node; cur_node = cur_node->next) {
			if (cur_node->type != XML_ELEMENT_NODE) {
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
			if (xmlStrcmp(cur_node->name, (xmlChar *)"hostname_wordlist") == 0) {
				if (access((char *)value, R_OK) == -1) {
					LOGGING_QUICK_WARNING("kraken.conf", "the specified dns hostname wordlist is not readable")
				} else {
					kraken_opts_set(k_opts, KRAKEN_OPT_DNS_WORDLIST, (char *)value);
				}
			}
			xmlFree(value);
		}
	}

	if (http_settings != NULL) {
		for (cur_node = http_settings->children; cur_node; cur_node = cur_node->next) {
			if (cur_node->type != XML_ELEMENT_NODE) {
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
			if (xmlStrcmp(cur_node->name, (xmlChar *)"bing_api_key") == 0) {
				kraken_opts_set(k_opts, KRAKEN_OPT_BING_API_KEY, (char *)value);
			}
			xmlFree(value);
		}
	}
	xmlFreeDoc(doc);
	return 0;
}

int kraken_conf_save_config(const char *conf_path, kraken_opts *k_opts) {
	xmlTextWriterPtr writer;
	xmlChar *xtmp;
	char *ctmp;
	int response;

	writer = xmlNewTextWriterFilename(conf_path, 0);
	if (writer == NULL) {
		LOGGING_QUICK_ERROR("kraken.conf", "could not create the XML writer")
		return -1;
	}
	xmlTextWriterStartDocument(writer, NULL, KRAKEN_XML_ENCODING, NULL);
	xmlTextWriterStartElement(writer, BAD_CAST "kraken");
	xmlTextWriterWriteAttribute(writer, BAD_CAST "version", BAD_CAST KRAKEN_XML_VERSION);
	xmlTextWriterWriteAttribute(writer, BAD_CAST "type", "config");

	xmlTextWriterStartElement(writer, BAD_CAST "dns");
	response = kraken_opts_get(k_opts, KRAKEN_OPT_DNS_WORDLIST, &ctmp);
	if (response == 0) {
		xtmp = xml_convert_input(ctmp, KRAKEN_XML_ENCODING);
		if (xtmp != NULL) {
			xmlTextWriterWriteElement(writer, BAD_CAST "hostname_wordlist", xtmp);
			xmlFree(xtmp);
		}
	}
	xmlTextWriterEndElement(writer);

	xmlTextWriterStartElement(writer, BAD_CAST "http");
	response = kraken_opts_get(k_opts, KRAKEN_OPT_BING_API_KEY, &ctmp);
	if (response == 0) {
		xtmp = xml_convert_input(ctmp, KRAKEN_XML_ENCODING);
		if (xtmp != NULL) {
			xmlTextWriterWriteElement(writer, BAD_CAST "bing_api_key", xtmp);
			xmlFree(xtmp);
		}
	}
	xmlTextWriterEndElement(writer);

	xmlTextWriterEndElement(writer);
	xmlTextWriterEndDocument(writer);
	xmlFreeTextWriter(writer);

	return 0;
}

