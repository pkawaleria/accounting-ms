from flask import request, jsonify, current_app
from models.user import User, db
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from services.utils import is_valid_password, is_valid_phone_number
from flask_cors import cross_origin
from flask_mail import Message, Mail

bcrypt = Bcrypt()
@cross_origin()
def login_user():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token_data = {
        'email': email,
        'sub': user.id,
        'iat': datetime.utcnow(),
        'roles': 'USER',
        'exp': datetime.utcnow() + timedelta(minutes=60*24*30)
    }

    token = jwt.encode(token_data, jwt_signing_secret, algorithm='HS256')
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
        return {'message': 'Password must be at least 8 characters '
                           'long and contain at least one uppercase letter, '
                           'one lowercase letter, and one digit'}, 400
    if not is_valid_phone_number(phone_number):
        return {'message': 'Phone number must be exactly 9 digits'}, 400

    user = User.query.filter_by(email=email).first()
    if user:
        return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username,
                    firstname=firstname,
                    lastname=lastname,
                    phone_number=phone_number,
                    email=email,
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

@cross_origin()
def change_password():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
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

@cross_origin()
def acc():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
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
            'firstname': user.firstname,
            'lastname': user.lastname,
            'phone_number': user.phone_number
        })
    elif request.method == 'POST':
        new_username = request.json.get('username')
        new_email = request.json.get('email')
        new_firstname = request.json.get('firstname')
        new_lastname = request.json.get('lastname')
        new_phone_number = request.json.get('phone_number')

        existing_user_with_username = User.query.filter_by(username=new_username).first()
        existing_user_with_email = User.query.filter_by(email=new_email).first()
        existing_user_with_phone = User.query.filter_by(phone_number=new_phone_number).first()

        if existing_user_with_username and existing_user_with_username.id != user.id:
            return jsonify({'message': 'User with the same username already exists'}), 400
        if existing_user_with_email and existing_user_with_email.id != user.id:
            return jsonify({'message': 'User with the same email already exists'}), 400
        if existing_user_with_phone and existing_user_with_phone.id != user.id:
            return jsonify({'message': 'User with the same phone number already exists'}), 400

        user.username = new_username
        user.email = new_email
        user.firstname = new_firstname
        user.lastname = new_lastname
        user.phone_number = new_phone_number

        db.session.commit()

        token_data = {
            'email': email,
            'sub': user.id,
            'iat': datetime.utcnow(),
            'roles': 'USER',
            'exp': datetime.utcnow() + timedelta(minutes=60 * 24 * 30)
        }

        token = jwt.encode(token_data, jwt_signing_secret, algorithm='HS256')
        return jsonify({'access_token': token}), 200

@cross_origin()
def acc_short(id):
    u_id = id
    current_user_id = u_id
    user = User.query.filter_by(id=current_user_id).first()

    if request.method == 'GET':
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'phone_number': user.phone_number
        })


def mail_to_user():
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({'message': 'Authorization header missing'}), 401

    try:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, current_app.config.get('JWT_SECRET'), algorithms=['HS256'])

        if decoded_token.get('roles') != "USER":
            return jsonify({'message': 'Unauthorized. Only administrators can access this endpoint'}), 403

        data = request.get_json()
        user_id = data.get('id')
        subject_body = data.get('subject')
        message_body = data.get('message')

        if not user_id or not message_body:
            return jsonify({'message': 'Id and message are required'}), 400
        sender = current_app.config.get('MAIL_USERNAME')
        user = User.query.filter_by(id=user_id).first()
        user_email = user.email
        msg = Message(subject=subject_body, sender=sender, recipients=[user_email])
        msg.body = message_body
        mail = Mail(current_app)
        mail.send(msg)

        return jsonify({'message': 'Email sent successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401