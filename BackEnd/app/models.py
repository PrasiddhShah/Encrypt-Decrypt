from . import db
from flask_login import UserMixin
from sqlalchemy import func

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(200))
    google_id = db.Column(db.String(200), unique=True)

class EncryptedData(db.Model):
    __tablename__ = 'encrypted_data'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    algorithm = db.Column(db.String(50))
    input_text = db.Column(db.Text)
    output_text = db.Column(db.Text)
    key = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=func.now())

    user = db.relationship('User', backref=db.backref('encrypted_data', lazy=True))
