from services.user_service import login_user, register_user, delete_user as del_user, google_login

def index():
    return {'status': 'OK'}
def register():
    return register_user()

def login():
    return login_user()

def delete_user(userId):
    return del_user(userId)

def glogin():
    return google_login()

