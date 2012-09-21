#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "utilities.h"

int util_dir_exists(const char *dir_path) {
	struct stat st;

	if (stat(dir_path, &st) == 0) {
		return 1;
	}
	return 0;
}

int util_dir_create_if_not_exists(const char *dir_path) {
	if (util_dir_exists(dir_path) == 0) {
		return mkdir(dir_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	return 0;
}

void util_str_replace(char *string, char *old, char *new) {
	char *pos = string;

	while (*pos != '\0') {
		if (*pos == *old) {
			*pos = *new;
		}
		pos++;
	}
	return;
}

void util_str_to_lower(char *string) {
	char *pos = string;

	while (*pos != '\0') {
		if ((*pos < 91) && (*pos > 64)) {
			*pos = (*pos + 32);
		}
		pos++;
	}
	return;
}

void util_str_to_upper(char *string) {
	char *pos = string;

	while (*pos != '\0') {
		if ((*pos < 123) && (*pos > 96)) {
			*pos = (*pos - 32);
		}
		pos++;
	}
	return;
}
