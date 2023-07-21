from services.user_service import login_user, register_user


def index():
    return {'status': 'OK'}
def register():
    return register_user()

def login():
    return login_user()