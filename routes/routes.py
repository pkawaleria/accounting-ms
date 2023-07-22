from flask import Blueprint
from controllers.userController import index, login, register, delete_user
from controllers.adminController import login as login_a, register as register_a, get_admin_permissions, get_all_permisions, add_permission, delete_permission

user = Blueprint('user', __name__)
admin = Blueprint('admin', __name__)

user.route('/', methods=['GET'])(index)
user.route('/login', methods=['POST'])(login)
user.route('/register', methods=['POST'])(register)
user.route('/<string:userId>/delete', methods=['DELETE'])(delete_user)

admin.route('/login', methods=['POST'])(login_a)
admin.route('/register', methods=['POST'])(register_a)
admin.route('/<string:adminId>/permissions', methods=['GET'])(get_admin_permissions)
admin.route('/permissions', methods=['GET'])(get_all_permisions)
admin.route('/<string:adminId>/permissions/<string:permissionId>', methods=['POST'])(add_permission)
admin.route('/<string:adminId>/permissions/<string:permissionId>', methods=['DELETE'])(delete_permission)