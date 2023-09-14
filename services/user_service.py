from flask import request, jsonify
from models.user import User, db
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from services.utils import is_valid_password, is_valid_phone_number
from flask_dance.contrib.google import google
from flask_cors import cross_origin

bcrypt = Bcrypt()
@cross_origin()
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token_data = {
        'email': email,
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=3000000000)
    }

    # Generujemy token JWT
    token = jwt.encode(token_data, "secret", algorithm='HS256')
    return jsonify({'access_token': token}), 200

@cross_origin()
def register_user():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    confirm_password = request.json.get('confirmPassword')
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    phone_number = request.json.get('phone_number')
    if password != confirm_password:
        return {'message': 'Passwords do not match'}

    if not is_valid_password(password):
        return {'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit'}, 400
    if not is_valid_phone_number(phone_number):
        return {'message': 'Phone number must be exactly 9 digits'}, 400

    user = User.query.filter_by(email=email).first()
    if user:
        return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, firstname=firstname, lastname=lastname, phone_number=phone_number, email=email,
                    password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}, 200
    except Exception as e:
        return {'message': 'An error occurred while registering user'}, 500

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

def change_password():
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, "secret", algorithms=['HS256'])
        email = decoded_token.get('email')
    else:
        return jsonify({'message': 'Authorization header missing'}), 401
    current_user_email = email
    user = User.query.filter_by(email=current_user_email).first()
    if request.method == 'POST':
        if user:
            new_password = request.json.get('new_password')
            if new_password:
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                return jsonify({'message': 'Password changed successfully'}), 200
            else:
                return jsonify({'message': 'New password not provided'}), 400
        else:
            return jsonify({'message': 'User not found'}), 404

def acc():
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, "secret", algorithms=['HS256'])
        email = decoded_token.get('email')
    else:
        return jsonify({'message': 'Authorization header missing'}), 401
    current_user_email = email
    user = User.query.filter_by(email=current_user_email).first()

    if request.method == 'GET':
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
        })
    elif request.method == 'POST':
        user.username = request.json.get('username')
        user.email = request.json.get('email')
        db.session.commit()
        token = jwt.encode(
            {'email': request.json.get('email'), 'exp': datetime.utcnow() + timedelta(minutes=30)},
            "secret"
        )
        return jsonify({"accessToken": token})
