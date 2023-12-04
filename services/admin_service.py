from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, current_app
from flask_bcrypt import Bcrypt
from flask_cors import cross_origin
from flask_mail import Message, Mail

from models.user import Admin, db, Permission_a, User
from services.utils import is_valid_password, is_valid_phone_number
from utils.admin_error_codes import ERROR_DICT

bcrypt = Bcrypt()


@cross_origin()
def login_admin():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')

    email = request.json.get('email')
    password = request.json.get('password')

    user = Admin.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'code': 'ACC02', 'message': ERROR_DICT['ACC02']}), 401

    if user.isSuperAdmin:
        payload = {
            'email': user.email,
            'sub': user.id if user else None,
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow(),
            'roles': 'ADMIN',
            'isSuperAdmin': True
        }
    else:
        permissions = [permission.code for permission in user.permissions]
        payload = {
            'email': user.email,
            'sub': user.id if user else None,
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow(),
            'roles': 'ADMIN',
            'permissions': permissions
        }

    token = jwt.encode(payload, jwt_signing_secret, algorithm='HS256')
    return jsonify({'access_token': token}), 200


@cross_origin()
def register_admin():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    phone_number = request.json.get('phone_number')
    confirm_password = request.json.get('confirmPassword')
    if password != confirm_password:
        return jsonify({'code': 'ACC02', 'message': ERROR_DICT['ACC02']})

    if not is_valid_password(password):
        return jsonify({'code': 'ACC03', 'message': ERROR_DICT['ACC03']}), 400

    if not is_valid_phone_number(phone_number):
        return jsonify({'code': 'ACC04', 'message': ERROR_DICT['ACC04']}), 400

    user = Admin.query.filter_by(email=email).first()
    if user:
        return jsonify({'code': 'ACC05', 'message': ERROR_DICT['ACC05']})

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Admin(username=username, firstname=firstname, lastname=lastname, phone_number=phone_number, email=email,
                     password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'Admin registered successfully'}, 200
    except Exception as e:
        return jsonify({'code': 'ACC06', 'message': ERROR_DICT['ACC06']})


@cross_origin()
def get_admin_perms(adminId):
    admin = Admin.query.get(adminId)

    if admin:
        permissions = [{'id': permission.id, 'code': permission.code, 'description_short': permission.description_short} for permission in admin.permissions]
        return jsonify({'permissions': permissions})
    else:
        return jsonify({'code': 'ACC07', 'message': ERROR_DICT['ACC07']}), 404


@cross_origin()
def get_all_admins():
    admins = Admin.query.all()
    admin_list = []

    for admin in admins:
        admin_data = {
            'id': admin.id,
            'username': admin.username,
            'email': admin.email
        }
        admin_list.append(admin_data)

    return jsonify(admin_list)


@cross_origin()
def get_all_users():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        role = decoded_token.get('roles')
        if role == "ADMIN":
            users = User.query.all()
            users_list = []

            for user in users:
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'isBanned': user.isBanned
                }
                users_list.append(user_data)

            return jsonify(users_list), 200
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401


@cross_origin()
def get_user_by_id(user_id):
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')

    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        role = decoded_token.get('roles')

        if role == "ADMIN":
            user = User.query.get(user_id)

            if user:
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'firstname': user.firstname,
                    'lastname': user.lastname,
                    'phone_number': user.phone_number,
                    'email': user.email,
                    'isBanned': user.isBanned
                }

                return jsonify(user_data), 200
            else:
                return jsonify({'code': 'ACC09', 'message': ERROR_DICT['ACC09']}), 404
        else:
            return jsonify({'code': 'ACC10', 'message': ERROR_DICT['ACC10']}), 403
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401


@cross_origin()
def block_user(user_id):
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')

    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        role = decoded_token.get('roles')

        if role == "ADMIN":
            user = User.query.get(user_id)

            if user and user.isBanned is False:
                user.isBanned = True
                db.session.commit()
                return jsonify({'message': 'User has been blocked successfully'}), 200
            else:
                return jsonify({'code': 'ACC09', 'message': ERROR_DICT['ACC09']}), 404
        else:
            return jsonify({'code': 'ACC11', 'message': ERROR_DICT['ACC11']}), 403
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401


@cross_origin()
def unblock_user(user_id):
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')

    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        role = decoded_token.get('roles')

        if role == "ADMIN":
            user = User.query.get(user_id)

            if user and user.isBanned is True:
                user.isBanned = False
                db.session.commit()
                return jsonify({'message': 'User has been unblocked successfully'}), 200
            else:
                return jsonify({'code': 'ACC09', 'message': ERROR_DICT['ACC09']}), 404
        else:
            return jsonify({'code': 'ACC12', 'message': ERROR_DICT['ACC13']}), 403
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401

def get_all_perms():
    permissions = Permission_a.query.all()

    data = {
        'permissions': [
            {
                'id': permission.id,
                'code': permission.code,
                'description_short': permission.description_short,
                'description_long': permission.description_long
            }
            for permission in permissions
        ]
    }

    return jsonify(data)


def add_perm(adminId, permissionId):
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    try:
        admin = Admin.query.get(adminId)
        if not admin:
            return jsonify({'code': 'ACC07', 'message': ERROR_DICT['ACC07']}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'code': 'ACC13', 'message': ERROR_DICT['ACC13']}), 404

        if permission not in admin.permissions:
            admin.permissions.append(permission)
            db.session.commit()

            all_permissions = Permission_a.query.all()

            if all(p in admin.permissions for p in all_permissions):
                admin.isSuperAdmin = True
                db.session.commit()

            if admin.isSuperAdmin:
                payload = {
                    'email': admin.email,
                    'sub': admin.id,
                    'exp': datetime.utcnow() + timedelta(days=1),
                    'iat': datetime.utcnow(),
                    'roles': 'ADMIN',
                    'isSuperAdmin': True
                }
            else:
                permissions = [p.code for p in admin.permissions]
                payload = {
                    'email': admin.email,
                    'sub': admin.id,
                    'exp': datetime.utcnow() + timedelta(days=1),
                    'iat': datetime.utcnow(),
                    'roles': 'ADMIN',
                    'permissions': permissions
                }

            token = jwt.encode(payload, jwt_signing_secret, algorithm='HS256')
            return jsonify({'message': 'Permission added to admin successfully', 'access_token': token}), 200
        else:
            return jsonify({'code': 'ACC14', 'message': ERROR_DICT['ACC14']}), 409
    except Exception as e:
        return jsonify({'code': 'ACC15', 'message': ERROR_DICT['ACC15']}), 500


def del_perm(adminId, permissionId):
    try:
        admin = Admin.query.get(adminId)
        if not admin:
            return jsonify({'code': 'ACC07', 'message': ERROR_DICT['ACC07']}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'code': 'ACC12', 'message': ERROR_DICT['ACC13']}), 404

        if permission in admin.permissions:
            admin.permissions.remove(permission)
            all_permissions = Permission_a.query.all()
            if not all(p in admin.permissions for p in all_permissions):
                admin.isSuperAdmin = False

            db.session.commit()

            jwt_signing_secret = current_app.config.get('JWT_SECRET')
            permissions = [p.code for p in admin.permissions]
            payload = {
                'email': admin.email,
                'sub': admin.id,
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'roles': 'ADMIN',
                'permissions': permissions
            }
            token = jwt.encode(payload, jwt_signing_secret, algorithm='HS256')

            return jsonify({'message': 'Permission removed from admin successfully', 'access_token': token})
        else:
            return jsonify({'code': 'ACC16', 'message': ERROR_DICT['ACC16']}), 400
    except Exception as e:
        return jsonify({'code': 'ACC17', 'message': ERROR_DICT['ACC17']}), 500


def init_perms():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        role = decoded_token.get('roles')
        if role == "ADMIN":
            if Permission_a.query.count() == 0:
                permissions = [
                    Permission_a(code="ADM001", description_short="Usuwanie ogłoszeń",
                                 description_long="Usuwanie dowolnych ogłoszeń z portalu"),
                    Permission_a(code="ADM002", description_short="Akceptacja ogłoszeń",
                                 description_long="Akceptowanie ogłoszeń oczekujących w kolejce"),
                    Permission_a(code="ADM003", description_short="Nadawanie uprawnień",
                                 description_long="Nadawanie uprawnień innym administratorom"),
                    Permission_a(code="ADM004", description_short="Dodawanie kategorii",
                                 description_long="Dodawanie nowych kategorii dla ogłoszeń"),
                    Permission_a(code="ADM005", description_short="Edycja ogłoszeń",
                                 description_long="Edycja istniejących ogłoszeń na portalu"),
                    Permission_a(code="ADM006", description_short="Blokowanie użytkowników",
                                 description_long="Blokowanie kont użytkowników"),
                    Permission_a(code="ADM007", description_short="Edycja kategorii",
                                 description_long="Edycja istniejących kategorii dla ogłoszeń"),
                    Permission_a(code="ADM008", description_short="Rejestracja admina",
                                 description_long="Możliwość utworzenia konta admina"),
                ]
                for permission in permissions:
                    db.session.add(permission)

                db.session.commit()
                return jsonify({'message': 'Permissions initialized successfuly'}), 201
            else:
                return jsonify({'code': 'ACC19', 'message': ERROR_DICT['ACC19']}), 400
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401


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
    admin = Admin.query.filter_by(email=current_user_email).first()

    if request.method == 'GET':
        return jsonify({
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'firstname': admin.firstname,
            'lastname': admin.lastname,
            'phone_number': admin.phone_number
        })
    elif request.method == 'POST':
        new_username = request.json.get('username')
        new_email = request.json.get('email')
        new_firstname = request.json.get('firstname')
        new_lastname = request.json.get('lastname')
        new_phone_number = request.json.get('phone_number')

        existing_user_with_username = Admin.query.filter_by(username=new_username).first()
        existing_user_with_email = Admin.query.filter_by(email=new_email).first()
        existing_user_with_phone = Admin.query.filter_by(phone_number=new_phone_number).first()

        if existing_user_with_username and existing_user_with_username.id != admin.id:
            return jsonify({'code': 'ACC20', 'message': ERROR_DICT['ACC20']}), 409
        if existing_user_with_email and existing_user_with_email.id != admin.id:
            return jsonify({'code': 'ACC21', 'message': ERROR_DICT['ACC21']}), 409
        if existing_user_with_phone and existing_user_with_phone.id != admin.id:
            return jsonify({'code': 'ACC22', 'message': ERROR_DICT['ACC22']}), 409

        admin.username = new_username
        admin.email = new_email
        admin.firstname = new_firstname
        admin.lastname = new_lastname
        admin.phone_number = new_phone_number

        db.session.commit()

        if admin.isSuperAdmin:
            token_data = {
                'email': admin.email,
                'sub': admin.id,
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'roles': 'ADMIN',
                'isSuperAdmin': True
            }
        else:
            permissions = [p.code for p in admin.permissions]
            token_data = {
                'email': admin.email,
                'sub': admin.id,
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'roles': 'ADMIN',
                'permissions': permissions
            }

        token = jwt.encode(token_data, jwt_signing_secret, algorithm='HS256')
        return jsonify({'access_token': token}), 200

@cross_origin()
def acc_short(id):
    u_id = id
    current_user_id = u_id
    admin = Admin.query.filter_by(id=current_user_id).first()

    if request.method == 'GET':
        return jsonify({
            'id': admin.id,
            'username': admin.username,
            'email': admin.email,
            'phone_number': admin.phone_number
        })

def change_password():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, jwt_signing_secret, algorithms=['HS256'])
        email = decoded_token.get('email')
    else:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401
    current_user_email = email
    admin = Admin.query.filter_by(email=current_user_email).first()
    if request.method == 'POST':
        if admin:
            new_password = request.json.get('new_password')
            if new_password:
                admin.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                return jsonify({'message': 'Password changed successfully'}), 200
            else:
                return jsonify({'code': 'ACC23', 'message': ERROR_DICT['ACC23']}), 400
        else:
            return jsonify({'code': 'ACC07', 'message': ERROR_DICT['ACC07']}), 404

def init_test_users():
    if Permission_a.query.count() == 0:
        permissions = [
            Permission_a(code="ADM001", description_short="Usuwanie ogłoszeń",
                         description_long="Usuwanie dowolnych ogłoszeń z portalu"),
            Permission_a(code="ADM002", description_short="Akceptacja ogłoszeń",
                         description_long="Akceptowanie ogłoszeń oczekujących w kolejce"),
            Permission_a(code="ADM003", description_short="Nadawanie uprawnień",
                         description_long="Nadawanie uprawnień innym administratorom"),
            Permission_a(code="ADM004", description_short="Dodawanie kategorii",
                         description_long="Dodawanie nowych kategorii dla ogłoszeń"),
            Permission_a(code="ADM005", description_short="Edycja ogłoszeń",
                         description_long="Edycja istniejących ogłoszeń na portalu"),
            Permission_a(code="ADM006", description_short="Blokowanie użytkowników",
                         description_long="Blokowanie kont użytkowników"),
            Permission_a(code="ADM007", description_short="Edycja kategorii",
                         description_long="Edycja istniejących kategorii dla ogłoszeń"),
            Permission_a(code="ADM008", description_short="Rejestracja admina",
                         description_long="Możliwość utworzenia konta admina"),
        ]
        for permission in permissions:
            db.session.add(permission)

        db.session.commit()
    try:
        # Tworzenie testowych użytkowników
        user1 = User(username='testuser1', firstname='John', lastname='Doe', phone_number='123456789',
                     email='user1@example.com')
        user1.password = bcrypt.generate_password_hash('Haslo123').decode('utf-8')
        user2 = User(username='testuser2', firstname='Jane', lastname='Smith', phone_number='987654321',
                     email='user2@example.com')
        user2.password = bcrypt.generate_password_hash('Haslo123').decode('utf-8')

        # Tworzenie testowych administratorów
        admin1 = Admin(username='admin1', firstname='Admin', lastname='One', phone_number='111111111',
                       email='admin@admin.com')
        admin1.password = bcrypt.generate_password_hash('Haslo123').decode('utf-8')
        admin2 = Admin(username='admin2', firstname='Admin', lastname='Two', phone_number='222222222',
                       email='admin2@admin2.com')
        admin2.password = bcrypt.generate_password_hash('Haslo123').decode('utf-8')

        # Pobieranie wszystkich uprawnień
        all_permissions = Permission_a.query.all()

        # Przypisywanie wszystkich uprawnień do pierwszego administratora
        for permission in all_permissions:
            admin1.permissions.append(permission)

        # Ustawianie flagi isSuperAdmin na True dla pierwszego administratora
        admin1.isSuperAdmin = True

        # Dodawanie użytkowników i administratorów do bazy danych
        db.session.add(user1)
        db.session.add(user2)
        db.session.add(admin1)
        db.session.add(admin2)
        db.session.commit()

        return jsonify({'message': 'Test users and admins initialized successfully'}), 201

    except Exception as e:
        return jsonify({'code': 'ACC24', 'message': ERROR_DICT['ACC24']}), 500


def send_email():
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({'code': 'ACC08', 'message': ERROR_DICT['ACC08']}), 401

    try:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, current_app.config.get('JWT_SECRET'), algorithms=['HS256'])

        if decoded_token.get('roles') != "ADMIN":
            return jsonify({'code': 'ACC25', 'message': ERROR_DICT['ACC25']}), 403

        data = request.get_json()
        user_id = data.get('id')
        subject_body = data.get('subject')
        message_body = data.get('message')

        if not user_id or not message_body:
            return jsonify({'code': 'ACC26', 'message': ERROR_DICT['ACC26']}), 400
        sender = current_app.config.get('MAIL_USERNAME')
        user = User.query.filter_by(id=user_id).first()
        user_email = user.email
        msg = Message(subject=subject_body, sender=sender, recipients=[user_email])
        msg.body = message_body
        mail = Mail(current_app)
        mail.send(msg)

        return jsonify({'message': 'Email sent successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'code': 'ACC27', 'message': ERROR_DICT['ACC27']}), 401
    except jwt.InvalidTokenError:
        return jsonify({'code': 'ACC28', 'message': ERROR_DICT['ACC28']}), 401
