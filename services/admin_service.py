from flask import request, jsonify
from models.user import Admin, db, Permission_a
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt

bcrypt = Bcrypt()


def login_admin():
    email = request.json.get('email')
    password = request.json.get('password')
    permissions = []

    user = Admin.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    permissions = user.get_permissions()

    payload = {
        'sub': user.id if user else None,
        'exp': datetime.utcnow() + timedelta(days=1),
        'permissions': permissions
    }

    token = jwt.encode(payload, "sekret", algorithm='HS256')
    return jsonify({'access_token': token}), 200


def register_admin():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    confirm_password = request.json.get('confirmPassword')
    if password != confirm_password:
        return {'message': 'Passwords do not match'}

        # Sprawdź, czy istnieje użytkownik o takiej nazwie użytkownika lub adresie email
        user = Admin.query.filter_by(email=email).first()
        if user:
            return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Admin(username=username, email=email, password=hashed_password)

    try:
        # Zapisz nowego użytkownika do bazy danych
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}
    except Exception as e:
        return {'message': 'An error occurred while registering user'}

def get_admin_perms(adminId):
    # Wyszukaj admina o podanym ID
    admin = Admin.query.get(adminId)

    if admin:
        # Pobierz uprawnienia admina
        permissions = [permission.description_short for permission in admin.permissions]
        return jsonify({'permissions': permissions})
    else:
        # Jeśli admin o podanym ID nie istnieje, zwróć odpowiedni komunikat
        return jsonify({'message': 'Admin not found'}), 404


def get_all_perms():
    # Pobierz wszystkie rekordy z tabeli Permission_a
    permissions = Permission_a.query.all()

    # Przygotuj dane JSON z listą uprawnień
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