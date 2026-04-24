#include "c_src/database.h"
#include "c_src/utils.h"
#include <stdio.h>
#include <string.h>

int main() {
    db_init("instance/auth.db");
    User admin;
    memset(&admin, 0, sizeof(User));
    strcpy(admin.username, "admin");
    strcpy(admin.email, "harshitola05@gmail.com");
    hash_password("Admin@123", admin.password_hash);
    strcpy(admin.role, "superadmin");
    admin.email_verified = 1;
    
    if (db_user_create(&admin)) {
        printf("Admin user created successfully!\n");
        printf("Email: harshitola05@gmail.com\n");
        printf("Password: Admin@123\n");
    } else {
        printf("Failed to create admin user (it might already exist).\n");
    }
    db_close();
    return 0;
}
