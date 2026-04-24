#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"
#include "assets.h"

char *replace_string(char *str, const char *old, const char *new_str) {
    if (!str || !old || !new_str) return str;
    char *result;
    int i, count = 0;
    size_t newlen = strlen(new_str);
    size_t oldlen = strlen(old);

    for (i = 0; str[i] != '\0'; i++) {
        if (strstr(&str[i], old) == &str[i]) {
            count++;
            i += oldlen - 1;
        }
    }

    result = (char *)malloc(i + count * (newlen - oldlen) + 1);
    if (!result) return str;

    i = 0;
    char *ptr = str;
    while (*ptr) {
        if (strstr(ptr, old) == ptr) {
            strcpy(&result[i], new_str);
            i += newlen;
            ptr += oldlen;
        } else {
            result[i++] = *ptr++;
        }
    }
    result[i] = '\0';
    free(str);
    return result;
}

char *render_auth_page(const char *template_content, const User *current_user, const char *title, const char *error_msg) {
    char *html = strdup(TEMPLATE_BASE);
    html = replace_string(html, "{{ title }}", title);
    html = replace_string(html, "{{ css }}", ASSET_CSS_MAIN);
    html = replace_string(html, "{{ js }}", ASSET_JS_MAIN);

    char *content = strdup(template_content);
    content = replace_string(content, "{{ error }}", error_msg ? error_msg : "");

    if (current_user) {
        char user_info[256];
        sprintf(user_info, "Logged in as %s", current_user->username);
        html = replace_string(html, "Secure Access", user_info);
    }

    html = replace_string(html, "{{ content }}", content);
    return html;
}
