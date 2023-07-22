from flask import request, jsonify
from models.user import User, db
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from services.utils import is_valid_password

bcrypt = Bcrypt()
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'email': email, 'exp': datetime.utcnow() + timedelta(minutes=3000000000)},
        "secret"
    )
    return jsonify({'access_token': token}), 200


def register_user():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    confirm_password = request.json.get('confirmPassword')
    if password != confirm_password:
        return {'message': 'Passwords do not match'}

    if not is_valid_password(password):
        return {'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit'}, 400

    user = User.query.filter_by(email=email).first()
    if user:
        return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}
    except Exception as e:
        return {'message': 'An error occurred while registering user'}

def delete_user(userId):
    user = User.query.filter_by(id=userId).first()

    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted successfully'}
        except Exception as e:
            return {'message': 'An error occurred while deleting user'}, 500
    else:
        return {'message': 'User not found'}, 404