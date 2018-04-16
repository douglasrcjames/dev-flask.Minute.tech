import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = 'quincyisthebestdog11'

MAX_CONTENT_LENGTH = 16 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/user_info')
IMAGES_CACHE = os.path.join(BASE_DIR, '../../tmp/flask-images')

WTF_CSRF_ENABLED = True
WTF_CSRF_SECRET_KEY = '2dz+fGD@lQ%?TwqZy-YpEcYU1q:GaSk!>CxNT5'

if os.environ.get('FLASK_ENV') == 'DEV':
    DEBUG = False
    RECAPTCHA_PUBLIC_KEY = '6LdYWksUAAAAANDZN1ooSZJ1cp7x2Z0Pfcc9Cz4n'
    RECAPTCHA_PRIVATE_KEY = '6LdYWksUAAAAAM0Hw43BxoN5fsuZQcndGcp5MNx5'
else:
    DEBUG = False
    RECAPTCHA_PUBLIC_KEY = '6Lc54UgUAAAAAPj5zf-R_pmKlnC_gBQSQ7EYfkzU'
    RECAPTCHA_PRIVATE_KEY = '6Lc54UgUAAAAAKvQv4x3QaYwKx5iZHAWiTO8Ft05'


SQLALCHEMY_DATABASE_URI = "mysql://test:welcomeback11@localhost/minutetech"
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_SERVER = 'smtp.zoho.com'
MAIL_USERNAME = 'test@minute.tech'
MAIL_PASSWORD = 'welcomeback11'
MAIL_DEFAULT_SENDER = 'test@minute.tech'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USE_TLS = False
MAIL_DEBUG = False
