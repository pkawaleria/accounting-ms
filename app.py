from flask import Flask
from flask_migrate import Migrate
from routes.routes import user, admin
from models.user import db
from flask_bcrypt import Bcrypt
from flask_cors import CORS

bcrypt = Bcrypt()


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config.from_object('config')
    bcrypt.init_app(app)
    db.init_app(app)
    return app


app = create_app()

app.register_blueprint(user, url_prefix='/users')
app.register_blueprint(admin, url_prefix='/admin')
migrate = Migrate(app, db)

if __name__ == '__main__':  # Running the app
    app.run(debug=True)
