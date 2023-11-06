from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstname = db.Column(db.String(20), unique=False, nullable=False)
    lastname = db.Column(db.String(30), unique=False, nullable=False)
    phone_number = db.Column(db.String(9), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="User")
    isBanned = db.Column(db.Boolean, nullable=False, default=False)
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


admin_permissions = db.Table(
    'admin_permissions',
    db.Column('admin_id', db.Integer, db.ForeignKey('admins.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions_a.id'), primary_key=True)
)


class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    firstname = db.Column(db.String(20), unique=False, nullable=False)
    lastname = db.Column(db.String(30), unique=False, nullable=False)
    phone_number = db.Column(db.String(9), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Admin")
    isSuperAdmin = db.Column(db.Boolean, nullable=False, default=False)
    permissions = db.relationship('Permission_a', secondary=admin_permissions, back_populates='admins')

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
    admins = db.relationship('Admin', secondary=admin_permissions, back_populates='permissions')
