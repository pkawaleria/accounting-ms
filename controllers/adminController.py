from services.admin_service import login_admin, register_admin, get_admin_perms, get_all_perms, add_perm, del_perm, init_perms, acc, acc_short, \
    change_password, get_all_admins, init_test_users, get_all_users, get_user_by_id, block_user, unblock_user


def index():
    return {'status': 'OK'}

def register():
    return register_admin()

def login():
    return login_admin()


def get_admin_permissions(adminId):
    return get_admin_perms(adminId)

def get_all_permisions():
    return get_all_perms()

def add_permission(adminId,permissionId):
    return add_perm(adminId,permissionId)

def delete_permission(adminId,permissionId):
    return del_perm(adminId,permissionId)

def initialize_permissions():
    return init_perms()

def account():
    return acc()

def account_short(id):
    return acc_short(id)

def change_passwd():
    return change_password()

def get_admins():
    return get_all_admins()

def test_users():
    return init_test_users()

def get_users():
    return get_all_users()
def get_single_user(id):
    return get_user_by_id(id)

def block_u(id):
    return block_user(id)

def unblock_u(id):
    return unblock_user(id)