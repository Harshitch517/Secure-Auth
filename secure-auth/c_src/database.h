#ifndef DATABASE_H
#define DATABASE_H

#include "lib/sqlite3.h"
#include <stdbool.h>
#include <time.h>

typedef struct {
    int id;
    char username[65];
    char email[121];
    char password_hash[257];
    char role[21];
    bool email_verified;
    int failed_login_attempts;
    time_t locked_until;
    time_t created_at;
    time_t last_login;
} User;

typedef struct {
    int id;
    int user_id;
    char code[7];
    time_t expires_at;
    bool used;
    time_t created_at;
} OTPToken;

typedef struct {
    int id;
    int user_id;
    char action[65];
    char ip_address[46];
    char *details;
    time_t timestamp;
} AuditLog;

typedef struct {
    char id[65];
    int user_id;
    time_t expires_at;
} Session;

bool db_init(const char *db_path);
void db_close();

// User operations
bool db_user_create(const User *user);
bool db_user_get_by_email(const char *email, User *user);
bool db_user_get_by_id(int id, User *user);
bool db_user_update(const User *user);
bool db_user_exists(const char *email, const char *username);

// OTP operations
bool db_otp_create(const OTPToken *otp);
bool db_otp_get_latest(int user_id, OTPToken *otp);
bool db_otp_mark_used(int id);

// Session operations
bool db_session_create(const Session *session);
bool db_session_get(const char *id, Session *session);
bool db_session_delete(const char *id);

// Audit operations
bool db_audit_log(int user_id, const char *action, const char *ip, const char *details);

#endif
