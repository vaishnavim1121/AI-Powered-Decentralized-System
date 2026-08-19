import os

class Config:
    SECRET_KEY = 's3cr3t-k3y-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f'
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'jwt-s3cr3t-8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0'