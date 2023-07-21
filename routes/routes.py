from flask import Blueprint
from controllers.userController import index, login, register
from controllers.adminController import login as login_a, register as register_a, get_admin_permissions, get_all_permisions

user = Blueprint('user', __name__)
admin = Blueprint('admin', __name__)

user.route('/', methods=['GET'])(index)
user.route('/login', methods=['POST'])(login)
user.route('/register', methods=['POST'])(register)

admin.route('/login', methods=['POST'])(login_a)
admin.route('/register', methods=['POST'])(register_a)
admin.route('/<string:adminId>/permissions', methods=['GET'])(get_admin_permissions)
admin.route('/permissions', methods=['GET'])(get_all_permisions)