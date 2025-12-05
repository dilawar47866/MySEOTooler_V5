import os
from app import app, db

print("🔧 Initializing database...")

with app.app_context():
    # Create all tables
    db.create_all()
    print("✅ Database tables created successfully!")

print("🎉 Database initialization complete!")
