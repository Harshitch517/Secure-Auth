#include "utils.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lib/bcrypt.h"

#pragma comment(lib, "Bcrypt.lib")

void get_random_bytes(void *buf, size_t len) {
    BCryptGenRandom(NULL, (unsigned char *)buf, (unsigned long)len, 0x00000002);
}

void generate_numeric_otp(char *out, size_t len) {
    unsigned int val;
    get_random_bytes(&val, sizeof(val));
    // Simple 6-digit OTP
    sprintf(out, "%06u", val % 1000000);
}

bool hash_password(const char *password, char *out_hash) {
    char salt[BCRYPT_HASHSIZE];
    // Note: bcrypt_gensalt needs a random source. I will fix bcrypt.c to use get_random_bytes.
    if (bcrypt_gensalt(12, salt) != 0) return false;
    if (bcrypt_hashpw(password, salt, out_hash) != 0) return false;
    return true;
}

bool verify_password(const char *password, const char *hash) {
    return bcrypt_checkpw(password, hash) == 0;
}

void sanitize_username(const char *in, char *out, size_t max_len) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j < max_len - 1; i++) {
        if ((in[i] >= 'a' && in[i] <= 'z') || (in[i] >= 'A' && in[i] <= 'Z') || 
            (in[i] >= '0' && in[i] <= '9') || in[i] == '_') {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
}

bool validate_password_strength(const char *p) {
    if (strlen(p) < 12) return false;
    bool has_up = false, has_low = false, has_digit = false, has_spec = false;
    for (int i = 0; p[i]; i++) {
        if (p[i] >= 'A' && p[i] <= 'Z') has_up = true;
        else if (p[i] >= 'a' && p[i] <= 'z') has_low = true;
        else if (p[i] >= '0' && p[i] <= '9') has_digit = true;
        else if (strchr("!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~\\", p[i])) has_spec = true;
    }
    return has_up && has_low && has_digit && has_spec;
}
