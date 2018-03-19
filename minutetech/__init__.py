##########################################################################
##########################################################################
#########################################  MINUTE.TECH SOURCE CODE by: Dou
##########################################################################
##########################################################################

from flask import Flask
from minutetech.main.routes import mod
from minutetech.technician.routes import mod

app = Flask(__name__)

# Key cross-referenced from flaskapp.wsgi
app.config['SECRET_KEY'] = 'quincyisthebestdog11'

# Flask ReCaptcha
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lc54UgUAAAAAPj5zf-R_pmKlnC_gBQSQ7EYfkzU'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lc54UgUAAAAAKvQv4x3QaYwKx5iZHAWiTO8Ft05'
app.config['TESTING'] = True  # turns reacaptcha off/on

app.register_blueprint(main.routes.mod)
# url_prefix allows us to www.minute.tech/api/api.html
app.register_blueprint(technician.routes.mod, url_prefix="/technician")
