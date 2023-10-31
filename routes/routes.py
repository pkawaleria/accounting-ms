from flask import Blueprint
from controllers.userController import index, login, register, delete_user, change_passwd, account, account_short
from controllers.adminController import login as login_a, register as register_a, get_admin_permissions, \
    get_all_permisions, add_permission, delete_permission, initialize_permissions, account as account_a, \
    acc_short as acc_short_a, change_passwd as change_passwd_a, get_admins

user = Blueprint('user', __name__)
admin = Blueprint('admin', __name__)

user.route('/', methods=['GET'])(index)
user.route('/login', methods=['POST'])(login)
user.route('/register', methods=['POST'])(register)
user.route('/<string:userId>/delete', methods=['DELETE'])(delete_user)
user.route('/changepasswd', methods=['POST'])(change_passwd)
user.route('/account_info', methods=['POST', 'GET'])(account)
user.route('/account_info_short/<string:id>', methods=['GET'])(account_short)

admin.route('/login', methods=['POST'])(login_a)
admin.route('/register', methods=['POST'])(register_a)
admin.route('/<string:adminId>/permissions', methods=['GET'])(get_admin_permissions)
admin.route('/permissions', methods=['GET'])(get_all_permisions)
admin.route('/<string:adminId>/permissions/<string:permissionId>', methods=['POST'])(add_permission)
admin.route('/<string:adminId>/permissions/<string:permissionId>', methods=['DELETE'])(delete_permission)
admin.route('/initialize_permissions', methods=['GET'])(initialize_permissions)
admin.route('/account_info', methods=['POST', 'GET'])(account_a)
admin.route('/account_info_short/<string:id>', methods=['GET'])(acc_short_a)
admin.route('/changepasswd', methods=['POST'])(change_passwd_a)
admin.route('/get_all_admins', methods=['GET'])(get_admins)

