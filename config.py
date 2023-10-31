import os

# Each Flask web application contains a secret key which used to sign session cookies for protection against cookie data tampering.
SECRET_KEY = os.urandom(32)

# Grabs the folder where the script runs.
# In my case it is, "F:\DataScience_Ai\hobby_projects\mvc_project\src"
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode, that will refresh the page when you make changes.
DEBUG = True

# DB_USER = 'root'
# DB_PASSWORD = os.environ.get('DB_PASSWORD') or 'password'
# DB_HOST = 'db'
# DB_NAME = 'users'

JWT_SECRET = 'LRFYY4iEwYOYmU5E9xL9hUOQKiAdlJ1234odfdacp213af2favma2rfav24favlacsaa3agvdaasdfataeg3qtqgter3qrt32tdgsadfgacdsbv34t32tr4afafawfasfasf'

SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/inz'
# SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://root:{DB_PASSWORD}@db/{DB_NAME}'

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = False