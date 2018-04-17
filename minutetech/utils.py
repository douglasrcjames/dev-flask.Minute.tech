from flask import session, flash, redirect, url_for
from functools import wraps  # For login_required
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if ('logged_in') in session:
            # arguments and key word arguments
            return f(*args, **kwargs)
        else:
            flash(u'You need to login first.', 'danger')
            return redirect(url_for('main.login'))
    return wrap
