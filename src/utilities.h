#ifndef _UTILITIES_H
#define _UTILITIES_H

int util_dir_exists(const char *dir_path);
int util_dir_create_if_not_exists(const char *dir_path);
void util_str_replace(char *string, char *old, char *new);
void util_str_to_lower(char *string);
void util_str_to_upper(char *string);

#endif
