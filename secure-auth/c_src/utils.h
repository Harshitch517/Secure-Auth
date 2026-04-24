#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>

void get_random_bytes(void *buf, size_t len);
void generate_numeric_otp(char *out, size_t len);
bool hash_password(const char *password, char *out_hash);
bool verify_password(const char *password, const char *hash);
void sanitize_username(const char *in, char *out, size_t max_len);
bool validate_password_strength(const char *p);

#endif
