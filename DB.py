from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin  # <-- Add this import

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(db.Model, UserMixin):  # <-- Add UserMixin here
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    # Password hashing methods (keep these)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Add these four Flask-Login required methods
    @property
    def is_active(self):
        return True  # All accounts are active by default

    @property
    def is_authenticated(self):
        return True  # True when user is logged in

    @property
    def is_anonymous(self):
        return False  # False for real users (True for anonymous)

    def get_id(self):
        return str(self.id)  # Must return string

class Server(db.Model):
    __tablename__ = 'servers'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

def initialize_database():
    """Safe database initialization with app context"""
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Database initialized! Tables created:", db.engine.table_names())

if __name__ == '__main__':
    from app import app
    initialize_database()