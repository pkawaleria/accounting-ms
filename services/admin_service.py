from flask import request, jsonify, current_app
from models.user import Admin, db, Permission_a, User
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from services.utils import is_valid_password, is_valid_phone_number
from flask_cors import cross_origin
from flask_mail import Message, Mail

bcrypt = Bcrypt()

@cross_origin()
def login_admin():
    jwt_signing_secret = current_app.config.get('JWT_SECRET')

    email = request.json.get('email')
    password = request.json.get('password')

    user = Admin.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

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
        return {'message': 'Passwords do not match'}

    if not is_valid_password(password):
        return {'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit'}, 400

    if not is_valid_phone_number(phone_number):
        return {'message': 'Phone number must be exactly 9 digits'}, 400

    user = Admin.query.filter_by(email=email).first()
    if user:
        return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Admin(username=username,firstname=firstname, lastname=lastname, phone_number=phone_number, email=email,
                     password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}
    except Exception as e:
        return {'message': 'An error occurred while registering user'}

@cross_origin()
def get_admin_perms(adminId):
    admin = Admin.query.get(adminId)

    if admin:
        permissions = [{'id': permission.id, 'code': permission.code, 'description_short': permission.description_short} for permission in admin.permissions]
        return jsonify({'permissions': permissions})
    else:
        return jsonify({'message': 'Admin not found'}), 404

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
        return jsonify({'message': 'Authorization header missing'}), 401

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
                return jsonify({'message': 'User not found'}), 404
        else:
            return jsonify({'message': 'Unauthorized. Only administrators can access this data.'}), 401
    else:
        return jsonify({'message': 'Authorization header missing'}), 401

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
                return jsonify({'message': 'User not found'}), 404
        else:
            return jsonify({'message': 'Unauthorized. Only administrators can block users.'}), 401
    else:
        return jsonify({'message': 'Authorization header missing'}), 401

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
                return jsonify({'message': 'User not found'}), 404
        else:
            return jsonify({'message': 'Unauthorized. Only administrators can unblock users.'}), 401
    else:
        return jsonify({'message': 'Authorization header missing'}), 401

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
            return jsonify({'message': 'Admin not found'}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'message': 'Permission not found'}), 404

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
            return jsonify({'message': 'Admin already has this permission'}), 400
    except Exception as e:
        return jsonify({'message': 'An error occurred while adding permission'}), 500


def del_perm(adminId, permissionId):
    try:
        admin = Admin.query.get(adminId)
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'message': 'Permission not found'}), 404

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
            return jsonify({'message': 'Admin does not have this permission'}), 400
    except Exception as e:
        return jsonify({'message': 'An error occurred while removing permission'}), 500


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
                return jsonify({'message': 'Permissions_a is not empty'}), 500
    else:
        return jsonify({'message': 'Authorization header missing'}), 401


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
            return jsonify({'message': 'User with the same username already exists'}), 400
        if existing_user_with_email and existing_user_with_email.id != admin.id:
            return jsonify({'message': 'User with the same email already exists'}), 400
        if existing_user_with_phone and existing_user_with_phone.id != admin.id:
            return jsonify({'message': 'User with the same phone number already exists'}), 400

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
        return jsonify({'message': 'Authorization header missing'}), 401
    current_user_email = email
    user = Admin.query.filter_by(email=current_user_email).first()
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

def init_test_users():
    if Permission_a.query.count() == 0:
        permissions = [
            Permission_a(code="ADM001", description_short="Usuwanie ogloszen",
                         description_long="Usuwanie dowolnych ogloszen z portalu"),
            Permission_a(code="ADM002", description_short="Akceptacja ogloszen",
                         description_long="Akceptowanie ogloszen oczekujacych w kolejce"),
            Permission_a(code="ADM003", description_short="Nadawanie uprawnien",
                         description_long="Nadawanie uprawnien innym administratorom"),
            Permission_a(code="ADM004", description_short="Dodawanie kategorii",
                         description_long="Dodawanie nowych kategorii dla ogloszen"),
            Permission_a(code="ADM005", description_short="Edycja ogloszen",
                         description_long="Edycja istniejacych ogloszen na portalu"),
            Permission_a(code="ADM006", description_short="Blokowanie uzytkownikow",
                         description_long="Blokowanie kont uzytkownikow"),
            Permission_a(code="ADM007", description_short="Edycja kategorii",
                         description_long="Edycja istniejacych kategorii dla ogloszen"),
            Permission_a(code="ADM008", description_short="Rejestracja admina",
                         description_long="Mozliwosc utworzenia konta admina"),
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
        return jsonify({'message': 'An error occurred while initializing test users and admins'}), 500


def send_email():
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({'message': 'Authorization header missing'}), 401

    try:
        token = authorization_header.split(' ')[1]
        decoded_token = jwt.decode(token, current_app.config.get('JWT_SECRET'), algorithms=['HS256'])

        if decoded_token.get('roles') != "ADMIN":
            return jsonify({'message': 'Unauthorized. Only administrators can access this endpoint'}), 403

        data = request.get_json()
        user_email = data.get('email')
        subject_body = data.get('subject')
        message_body = data.get('message')

        if not user_email or not message_body:
            return jsonify({'message': 'Email and message are required'}), 400
        sender = current_app.config.get('MAIL_USERNAME')
        msg = Message(subject=subject_body, sender=sender, recipients=[user_email])
        msg.body = message_body
        mail = Mail(current_app)
        mail.send(msg)

        return jsonify({'message': 'Email sent successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
