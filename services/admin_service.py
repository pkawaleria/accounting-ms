from flask import request, jsonify
from models.user import Admin, db, Permission_a
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
from services.utils import is_valid_password

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

    if not is_valid_password(password):
        return {'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one digit'}, 400

    user = Admin.query.filter_by(email=email).first()
    if user:
        return {'message': 'Username or email already exists'}

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Admin(username=username, email=email, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}
    except Exception as e:
        return {'message': 'An error occurred while registering user'}

def get_admin_perms(adminId):
    admin = Admin.query.get(adminId)

    if admin:
        permissions = [permission.description_short for permission in admin.permissions]
        return jsonify({'permissions': permissions})
    else:
        return jsonify({'message': 'Admin not found'}), 404


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


def add_perm(adminId,permissionId):
    try:
        admin = Admin.query.get(adminId)
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'message': 'Permission not found'}), 404

        admin.permissions.append(permission)

        db.session.commit()

        return jsonify({'message': 'Permission added to admin successfully'})
    except Exception as e:
        return jsonify({'message': 'An error occurred while adding permission'}), 500
def del_perm(adminId,permissionId):
    try:
        admin = Admin.query.get(adminId)
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        permission = Permission_a.query.get(permissionId)
        if not permission:
            return jsonify({'message': 'Permission not found'}), 404

        if permission.admin_id != admin.id:
            return jsonify({'message': 'Permission is not associated with this admin'}), 400

        admin.permissions.remove(permission)

        db.session.commit()

        return jsonify({'message': 'Permission removed from admin successfully'})
    except Exception as e:
        return jsonify({'message': 'An error occurred while removing permission'}), 500