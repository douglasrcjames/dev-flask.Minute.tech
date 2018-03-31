from flask import Flask, render_template
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)
mail = Mail(app)


from minutetech.main.routes import main
from minutetech.technician.routes import technician
app.register_blueprint(main)
app.register_blueprint(technician, url_prefix="/technician")

# Error Handlers


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(405)
def method_not_found(e):
    return render_template("405.html"), 405


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500
