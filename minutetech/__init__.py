from flask import Flask

app = Flask(__name__)

from minutetech.main.routes import mod
from minutetech.technician.routes import mod

app.register_blueprint(main.routes.mod)
app.register_blueprint(technician.routes.mod, url_prefix="/technician") #url_prefix allows us to www.minute.tech/api/api.html