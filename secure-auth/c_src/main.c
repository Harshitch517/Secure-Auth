#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define NOCRYPT
#include <windows.h>
#include <bcrypt.h>
#include "lib/mongoose.h"
#include "database.h"
#include "utils.h"
#include "assets.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

extern char *render_auth_page(const char *template_content, const User *current_user, const char *title, const char *error_msg);

static const char *s_http_addr = "http://0.0.0.0:5000";

static void log_info(const char *msg) {
    printf("[INFO] %s\n", msg);
    fflush(stdout);
}

static bool is_strong_password(const char *pass) {
    if (strlen(pass) < 8) return false;
    bool has_digit = false, has_special = false, has_upper = false, has_lower = false;
    for (int i = 0; pass[i]; i++) {
        if (isdigit(pass[i])) has_digit = true;
        else if (isupper(pass[i])) has_upper = true;
        else if (islower(pass[i])) has_lower = true;
        else if (ispunct(pass[i]) || isspace(pass[i])) has_special = true;
    }
    return has_digit && has_special && has_upper && has_lower;
}

static int get_current_user_id(struct mg_http_message *hm) {
    struct mg_str *cookie = mg_http_get_header(hm, "Cookie");
    if (cookie) {
        char session_id[65];
        struct mg_str v = mg_http_get_header_var(*cookie, mg_str("session_id"));
        if (v.len > 0 && v.len < sizeof(session_id)) {
            memcpy(session_id, v.buf, v.len);
            session_id[v.len] = '\0';
            
            Session sess;
            if (db_session_get(session_id, &sess)) {
                if (sess.expires_at > time(NULL)) {
                    return sess.user_id;
                } else {
                    log_info("Session expired");
                    db_session_delete(session_id);
                }
            } else {
                log_info("Session not found in database");
            }
        }
    }
    return 0;
}

static void handle_login(struct mg_connection *c, struct mg_http_message *hm) {
    char *error = NULL;
    if (mg_vcasecmp(&hm->method, "POST") == 0) {
        char email[128], pass[128];
        mg_http_get_var(&hm->body, "email", email, sizeof(email));
        mg_http_get_var(&hm->body, "password", pass, sizeof(pass));

        log_info("Processing login attempt...");
        User user;
        if (db_user_get_by_email(email, &user)) {
            if (verify_password(pass, user.password_hash)) {
                log_info("Password verified. Creating session...");
                Session sess;
                unsigned char rand_buf[16];
                get_random_bytes(rand_buf, 16);
                for(int i=0; i<16; i++) sprintf(&sess.id[i*2], "%02x", rand_buf[i]);
                sess.user_id = user.id;
                sess.expires_at = time(NULL) + 3600; // 1 hour session
                
                if (db_session_create(&sess)) {
                    log_info("Session created. Redirecting to dashboard...");
                    char headers[512];
                    snprintf(headers, sizeof(headers), 
                        "Location: /dashboard\r\n"
                        "Set-Cookie: session_id=%s; Path=/; HttpOnly\r\n", sess.id);
                    mg_http_reply(c, 302, headers, "");
                    return;
                } else {
                    log_info("Failed to create session in database");
                    error = "Internal server error. Please try again later.";
                }
            } else {
                log_info("Invalid password entered");
                error = "Invalid password. Please try again.";
            }
        } else {
            log_info("User not found in database");
            error = "Email not registered. Please sign up first.";
        }
    }
    
    char *html = render_auth_page(TEMPLATE_LOGIN, NULL, "Login - SecureAuth", error);
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", html);
    free(html);
}

static void handle_register(struct mg_connection *c, struct mg_http_message *hm) {
    char *error = NULL;
    if (mg_vcasecmp(&hm->method, "POST") == 0) {
        char email[128], pass[128], user_name[64];
        mg_http_get_var(&hm->body, "email", email, sizeof(email));
        mg_http_get_var(&hm->body, "password", pass, sizeof(pass));
        mg_http_get_var(&hm->body, "username", user_name, sizeof(user_name));

        log_info("Processing registration attempt...");
        if (db_user_exists(email, user_name)) {
            log_info("Registration failed: User already exists");
            error = "Email or username already in use.";
        } else if (!is_strong_password(pass)) {
            log_info("Registration failed: Weak password");
            error = "Password too weak! Must have 8+ chars, uppercase, lowercase, number, and special character.";
        } else {
            User new_user;
            memset(&new_user, 0, sizeof(User));
            strcpy(new_user.username, user_name);
            strcpy(new_user.email, email);
            hash_password(pass, new_user.password_hash);
            strcpy(new_user.role, "user");
            new_user.email_verified = 1;
            
            if (db_user_create(&new_user)) {
                log_info("Registration successful. Redirecting to login...");
                mg_http_reply(c, 302, "Location: /auth/login\r\n", "");
                return;
            } else {
                log_info("Registration failed: Database error");
                error = "Internal server error. Please try again.";
            }
        }
    }
    
    char *html = render_auth_page(TEMPLATE_REGISTER, NULL, "Register - SecureAuth", error);
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", html);
    free(html);
}

static void handle_dashboard(struct mg_connection *c, struct mg_http_message *hm) {
    int user_id = get_current_user_id(hm);
    if (user_id <= 0) {
        log_info("Unauthorized access to dashboard. Redirecting to login...");
        mg_http_reply(c, 302, "Location: /auth/login\r\n", "");
        return;
    }
    
    User user;
    if (db_user_get_by_id(user_id, &user)) {
        char *html = render_auth_page(TEMPLATE_DASHBOARD, &user, "Dashboard - SecureAuth", NULL);
        mg_http_reply(c, 200, "Content-Type: text/html\r\n", html);
        free(html);
    } else {
        mg_http_reply(c, 302, "Location: /auth/login\r\n", "");
    }
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        if (mg_match(hm->uri, mg_str("/"), NULL)) {
            mg_http_reply(c, 302, "Location: /auth/login\r\n", "");
        } else if (mg_match(hm->uri, mg_str("/auth/login"), NULL)) {
            handle_login(c, hm);
        } else if (mg_match(hm->uri, mg_str("/auth/register"), NULL)) {
            handle_register(c, hm);
        } else if (mg_match(hm->uri, mg_str("/dashboard"), NULL)) {
            handle_dashboard(c, hm);
        } else if (mg_match(hm->uri, mg_str("/auth/logout"), NULL)) {
            log_info("Logging out user...");
            mg_http_reply(c, 302, "Set-Cookie: session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\nLocation: /auth/login\r\n", "");
        } else {
            mg_http_reply(c, 404, "", "Not Found");
        }
    }
}

int main(void) {
    struct mg_mgr mgr;
    if (!db_init("instance/auth.db")) {
        printf("[ERROR] Failed to initialize database!\n");
        return 1;
    }
    mg_mgr_init(&mgr);
    if (mg_http_listen(&mgr, s_http_addr, fn, NULL) == NULL) {
        printf("[ERROR] Failed to listen on %s\n", s_http_addr);
        return 1;
    }
    printf("[INFO] Server started at %s\n", s_http_addr);
    fflush(stdout);
    for (;;) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    return 0;
}
