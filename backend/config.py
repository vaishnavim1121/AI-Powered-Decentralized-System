import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-dev-secret-change-me')
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Try PostgreSQL first (production), fall back to SQLite
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if DATABASE_URL:
        # Render provides 'postgres://' but SQLAlchemy 2.x needs 'postgresql://'
        SQLALCHEMY_DATABASE_URI = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    else:
        # Use /tmp on Render (writable), or local instance/ folder
        instance_dir = os.path.join(BASE_DIR, 'instance')
        os.makedirs(instance_dir, exist_ok=True)
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(instance_dir, 'app.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'fallback-jwt-secret-change-me')
