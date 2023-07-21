from flask import request, jsonify
from models.user import User, db
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt

bcrypt = Bcrypt()
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode(
        {'email': email, 'exp': datetime.utcnow() + timedelta(minutes=30)},
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

        # Sprawdź, czy istnieje użytkownik o takiej nazwie użytkownika lub adresie email
        user = User.query.filter_by(email=email).first()
        if user:
            return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)

    try:
        # Zapisz nowego użytkownika do bazy danych
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}
    except Exception as e:
        return {'message': 'An error occurred while registering user'}