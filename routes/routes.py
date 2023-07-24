from flask import Blueprint
from controllers.userController import index, login, register, delete_user, glogin
from controllers.adminController import login as login_a, register as register_a, get_admin_permissions, get_all_permisions, add_permission, delete_permission
from flask_dance.contrib.google import make_google_blueprint, google

user = Blueprint('user', __name__)
admin = Blueprint('admin', __name__)


google_blueprint = make_google_blueprint(
        client_id="1072841860109-2vil2ks5rde24hhshfkfcilsmrm0p19s.apps.googleusercontent.com",
        client_secret="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",
        offline=True,
        scope=["profile", "email"]
    )

google_blueprint.route('/login', methods=['POST'])(glogin)

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

