from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="User")
    permissions = db.relationship('Permission_u', backref='user', lazy=True)

    def __repr__(self):
        return '<userid %r>' % self.id

class Permission_u(db.Model):
    __tablename__ = 'permissions_u'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    description_short = db.Column(db.String(40), nullable=False)
    description_long = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Admin")
    permissions = db.relationship('Permission_a', backref='admin', lazy=True)
    def __repr__(self):
        return '<userid %r>' % self.id

    def get_permissions(self):
        return [permission.description_short for permission in self.permissions]

class Permission_a(db.Model):
    __tablename__ = 'permissions_a'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    description_short = db.Column(db.String(40), nullable=False)
    description_long = db.Column(db.String(200), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'))