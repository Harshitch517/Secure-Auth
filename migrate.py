import sqlite3
import os

from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app()

def migrate():
    with app.app_context():
        db_path = os.path.join(app.root_path, '..', 'instance', 'auth.db')
        if not os.path.exists(db_path):
            db_path = os.path.join(app.root_path, '..', 'auth.db')
            
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            # Check if role column exists in admin_whitelist
            cursor.execute("PRAGMA table_info(admin_whitelist)")
            columns = [info[1] for info in cursor.fetchall()]
            
            if 'role' not in columns:
                print("Adding role column to admin_whitelist...")
                cursor.execute("ALTER TABLE admin_whitelist ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'")
                conn.commit()
                # Promote existing whitelists to superadmin if created by seeded admin? Wait, no, default is 'admin' so leave it.
                
            # Promote the main seeded user to superadmin
            user = User.query.filter_by(email=app.config["ADMIN_EMAIL"]).first()
            if user:
                user.role = "superadmin"
                db.session.commit()
                print(f"User {user.email} promoted to superadmin")
                
        except Exception as e:
            print(f"Migration error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    migrate()
