from services.user_service import login_user, register_user, delete_user as del_user, change_password, acc, acc_short

def index():
    return {'status': 'OK'}
def register():
    return register_user()

def login():
    return login_user()

def delete_user(userId):
    return del_user(userId)

def change_passwd():
    return change_password()

def account():
    return acc()

def account_short(id):
    return acc_short(id)
