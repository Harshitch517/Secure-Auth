#include "database.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static sqlite3 *db = NULL;

bool db_init(const char *db_path) {
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    const char *sql_users = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "email TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'user',"
        "email_verified INTEGER NOT NULL DEFAULT 0,"
        "failed_login_attempts INTEGER NOT NULL DEFAULT 0,"
        "locked_until INTEGER,"
        "created_at INTEGER,"
        "last_login INTEGER"
        ");";

    const char *sql_otp = 
        "CREATE TABLE IF NOT EXISTS otp_tokens ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER NOT NULL,"
        "code TEXT NOT NULL,"
        "expires_at INTEGER NOT NULL,"
        "used INTEGER NOT NULL DEFAULT 0,"
        "created_at INTEGER,"
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";

    const char *sql_audit = 
        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER,"
        "action TEXT NOT NULL,"
        "ip_address TEXT,"
        "details TEXT,"
        "timestamp INTEGER NOT NULL,"
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";

    const char *sql_sessions = 
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id TEXT PRIMARY KEY,"
        "user_id INTEGER NOT NULL,"
        "expires_at INTEGER NOT NULL,"
        "FOREIGN KEY(user_id) REFERENCES users(id)"
        ");";

    char *err_msg = NULL;
    rc = sqlite3_exec(db, sql_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) goto error;

    rc = sqlite3_exec(db, sql_otp, 0, 0, &err_msg);
    if (rc != SQLITE_OK) goto error;

    rc = sqlite3_exec(db, sql_audit, 0, 0, &err_msg);
    if (rc != SQLITE_OK) goto error;

    rc = sqlite3_exec(db, sql_sessions, 0, 0, &err_msg);
    if (rc != SQLITE_OK) goto error;

    return true;

error:
    fprintf(stderr, "SQL error: %s\n", err_msg);
    sqlite3_free(err_msg);
    return false;
}

void db_close() {
    if (db) sqlite3_close(db);
}

bool db_user_create(const User *user) {
    const char *sql = "INSERT INTO users (username, email, password_hash, role, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user->email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user->password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, user->role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user->email_verified ? 1 : 0);
    sqlite3_bind_int64(stmt, 6, time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_user_get_by_email(const char *email, User *user) {
    const char *sql = "SELECT id, username, email, password_hash, role, email_verified, failed_login_attempts, locked_until, created_at, last_login FROM users WHERE email = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        user->id = sqlite3_column_int(stmt, 0);
        strncpy(user->username, (const char*)sqlite3_column_text(stmt, 1), 64);
        strncpy(user->email, (const char*)sqlite3_column_text(stmt, 2), 120);
        strncpy(user->password_hash, (const char*)sqlite3_column_text(stmt, 3), 256);
        strncpy(user->role, (const char*)sqlite3_column_text(stmt, 4), 20);
        user->email_verified = sqlite3_column_int(stmt, 5) != 0;
        user->failed_login_attempts = sqlite3_column_int(stmt, 6);
        user->locked_until = sqlite3_column_int64(stmt, 7);
        user->created_at = sqlite3_column_int64(stmt, 8);
        user->last_login = sqlite3_column_int64(stmt, 9);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool db_user_get_by_id(int id, User *user) {
    const char *sql = "SELECT id, username, email, password_hash, role, email_verified, failed_login_attempts, locked_until, created_at, last_login FROM users WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        user->id = sqlite3_column_int(stmt, 0);
        strncpy(user->username, (const char*)sqlite3_column_text(stmt, 1), 64);
        strncpy(user->email, (const char*)sqlite3_column_text(stmt, 2), 120);
        strncpy(user->password_hash, (const char*)sqlite3_column_text(stmt, 3), 256);
        strncpy(user->role, (const char*)sqlite3_column_text(stmt, 4), 20);
        user->email_verified = sqlite3_column_int(stmt, 5) != 0;
        user->failed_login_attempts = sqlite3_column_int(stmt, 6);
        user->locked_until = sqlite3_column_int64(stmt, 7);
        user->created_at = sqlite3_column_int64(stmt, 8);
        user->last_login = sqlite3_column_int64(stmt, 9);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool db_user_update(const User *user) {
    const char *sql = "UPDATE users SET password_hash = ?, role = ?, email_verified = ?, failed_login_attempts = ?, locked_until = ?, last_login = ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, user->password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user->role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, user->email_verified ? 1 : 0);
    sqlite3_bind_int(stmt, 4, user->failed_login_attempts);
    sqlite3_bind_int64(stmt, 5, user->locked_until);
    sqlite3_bind_int64(stmt, 6, user->last_login);
    sqlite3_bind_int(stmt, 7, user->id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_user_exists(const char *email, const char *username) {
    const char *sql = "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    bool exists = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

bool db_otp_create(const OTPToken *otp) {
    const char *sql = "INSERT INTO otp_tokens (user_id, code, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, otp->user_id);
    sqlite3_bind_text(stmt, 2, otp->code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, otp->expires_at);
    sqlite3_bind_int(stmt, 4, otp->used ? 1 : 0);
    sqlite3_bind_int64(stmt, 5, time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_otp_get_latest(int user_id, OTPToken *otp) {
    const char *sql = "SELECT id, user_id, code, expires_at, used, created_at FROM otp_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, user_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        otp->id = sqlite3_column_int(stmt, 0);
        otp->user_id = sqlite3_column_int(stmt, 1);
        strncpy(otp->code, (const char*)sqlite3_column_text(stmt, 2), 6);
        otp->code[6] = '\0';
        otp->expires_at = sqlite3_column_int64(stmt, 3);
        otp->used = sqlite3_column_int(stmt, 4) != 0;
        otp->created_at = sqlite3_column_int64(stmt, 5);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool db_otp_mark_used(int id) {
    const char *sql = "UPDATE otp_tokens SET used = 1 WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_audit_log(int user_id, const char *action, const char *ip, const char *details) {
    const char *sql = "INSERT INTO audit_logs (user_id, action, ip_address, details, timestamp) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    if (user_id > 0) sqlite3_bind_int(stmt, 1, user_id);
    else sqlite3_bind_null(stmt, 1);

    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, details, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_session_create(const Session *session) {
    const char *sql = "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, session->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, session->user_id);
    sqlite3_bind_int64(stmt, 3, session->expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db_session_get(const char *id, Session *session) {
    const char *sql = "SELECT id, user_id, expires_at FROM sessions WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        strncpy(session->id, (const char*)sqlite3_column_text(stmt, 0), 64);
        session->user_id = sqlite3_column_int(stmt, 1);
        session->expires_at = sqlite3_column_int64(stmt, 2);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}

bool db_session_delete(const char *id) {
    const char *sql = "DELETE FROM sessions WHERE id = ?;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
