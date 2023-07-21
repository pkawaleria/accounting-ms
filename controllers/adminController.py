from services.admin_service import login_admin, register_admin, get_admin_perms, get_all_perms


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
