###### INCLUDED LIBRARIES ######
import os
import sys
import os.path
from flask import Flask, render_template, flash, request, url_for, redirect, session, send_file, send_from_directory, Blueprint
from wtforms import Form, BooleanField, TextField, PasswordField, SelectField, RadioField, TextAreaField, DateField, DateTimeField, StringField, validators
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename  # For secure file uploads
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from passlib.hash import sha256_crypt  # To encrypt the password
from MySQLdb import escape_string as thwart  # To prevent SQL injection
from flask_mail import Mail, Message
# Email confirmation link that has a short lifespan
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from functools import wraps  # For login_required
# Custom f(x)
from dbconnect import connection
from .forms import ContactForm, RegistrationForm, AskForm, EditAccountForm, PasswordResetForm, EmailResetForm, PhoneResetForm
# Might be able to delete some of these from _ imports, test later for
# dependencies in files/folders.

app = Flask(__name__)
mod = Blueprint('main', __name__, template_folder='templates')
# Key cross-referenced from flaskapp.wsgi
app.config['SECRET_KEY'] = 'quincyisthebestdog11'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # For token
# Flask Mail
app.config.from_pyfile('config.cfg')
mail = Mail(app)

# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# UPLOAD_FOLDER = '/var/www/FlaskApp/FlaskApp/static/user_info/prof_pic'
# ALLOWED_EXTENSIONS = set(['png','jpg','jpeg','gif'])

#############  TESTING B4 POST (all normal testing should be in the dev.mi
# TESTING route
# @mod.route('/test/', methods=['GET','POST'])
# def test():
# 	error = ''
# 	try:
# 		c, conn = connection()
# 		if request.method == "POST":
# 			msg = Message("Minute.tech - Email Verification", sender = "admin@minute.tech", recipients=[session['email']])
# 			msg.body = render_template('email_verify.txt')
# 			msg.html = render_template('email_verify.html')
# 			mail.send(msg)
# 			flash(u'Submitted', 'success')
# 			return redirect(url_for('main.test'))

# 		return render_template("test.html", error = error)

# 	except Exception as e:
# 		return render_template("500.html", error = e)

############################ END Testing Layer 0 #########################

############################ 1st Layer Pages (Visible to all visitors) ###


def login_required(f):
    # not 100% how this works
    # techlogged_in doesnt look like its user anywhere, be sure of these and
    # delete if not anywhere else
    @wraps(f)
    def wrap(*args, **kwargs):
        if ('logged_in' or 'techlogged_in') in session:
            # arguments and key word arguments
            return f(*args, **kwargs)
        else:
            flash(u'You need to login first.', 'danger')
            return redirect(url_for('main.login'))
    return wrap


@mod.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    session.clear()
    flash(u'You have been logged out!', 'danger')
    return redirect(url_for('main.homepage'))


@mod.route('/', methods=['GET', 'POST'])
def homepage():
    # if user posts a question to the pool
    form = AskForm(request.form)
    if request.method == "POST" and form.validate():
        difficulty = 0
        title = 'Not provided'
        body = form.body.data
        tags = 'Not provided'
        priority = 500
        clientcid = session['clientcid']

        c, conn = connection()
        c.execute("INSERT INTO tickets (cid, difficulty, priority, title, tags) VALUES (%s, %s, %s, %s, %s)",
                  (clientcid, difficulty, priority, title, tags))
        conn.commit()
        # Get qid after the ticket is generated after an initial "ask" page
        # request
        c.execute(
            "SELECT qid FROM tickets WHERE cid = (%s) AND title = (%s)", (clientcid, title))
        qid = c.fetchone()[0]
        conn.commit()
        c.execute("INSERT INTO threads (qid, cid, body) VALUES (%s, %s, %s)",
                  (qid, clientcid, body))
        conn.commit()
        c.close()
        conn.close()
        flash(u'Submission successful. We have added your question to the pool!', 'success')
        return redirect(url_for('main.homepage'))

    else:
        error = "We couldn't post your question, please make sure you filled out all the fields properly and try again!"
        return render_template("main.html", form=form)


@mod.route('/about/', methods=['GET', 'POST'])
def about():
    uid = 0
    try:
        form = ContactForm(request.form)
        if request.method == "POST" and form.validate():
            message = form.message.data
            # If user is logged in, set email to their email, otherwise, empty
            # (on html side)
            email = form.email.data

            # Get user ID
            if 'logged_in' in session:
                if session['logged_in'] == 'client':
                    uid = session['clientcid']
                if session['logged_in'] == 'tech':
                    uid = session['techtid']

            # Throw data in database
            c, conn = connection()
            c.execute(
                "INSERT INTO contact (message, email, uid) VALUES (%s, %s, %s)", (message, email, uid))
            conn.commit()
            c.close()
            conn.close()
            flash(
                u'Submission successful. We will get back to you as soon as possible!', 'success')
            return redirect(url_for('main.about'))

        else:
            error = "We couldn't post your comment, please make sure you filled out all the fields properly, or try reloading the page and asking again."
            return render_template("about.html", form=form)

    except Exception as e:
        return render_template("500.html", error=e)
# CLIENT LOGIN


@mod.route('/login/', methods=['GET', 'POST'])
def login():
    global count
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            c.execute("SELECT * FROM clients WHERE email = (%s)",
                      (thwart(request.form['email']),))
            pdata = c.fetchone()[3]

            if sha256_crypt.verify(request.form['password'], pdata):
                email = request.form['email']
                # putting these close and commit
                # functions outside the 'if' will break code
                conn.commit()
                c.close()
                conn.close()
                session['logged_in'] = 'client'
                session['email'] = thwart(email)
                flash(u'You are now logged in.', 'success')
                return redirect(url_for("main.account"))

            else:
                count += 1
                error = "Invalid credentials, try again. Tries: {}".format(
                    count)

        return render_template("login.html", error=error)

    except Exception as e:
        error = "Invalid credentials, try again."
        return render_template("login.html", error=error)

# will remove this once I get the forms.py linked properly


# class RegistrationForm(Form):
#     first_name = TextField('First Name', [validators.Length(min=1, max=50)])
#     last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
#     email = TextField('Email Address', [validators.Length(min=6, max=50)])
#     phone = TextField('Phone Number', [validators.Length(min=10, max=20)])
#     czip = TextField('ZIP', [validators.Length(min=2, max=16)])
#     password = PasswordField('Password', [validators.Required(
#     ), validators.EqualTo('confirm', message="Passwords must match.")])
#     confirm = PasswordField('Repeat Password')
#     recaptcha = RecaptchaField()

# CLIENT REGISTER


@mod.route('/register/', methods=['GET', 'POST'])
def register_page():
    error = ''
    try:
        form = RegistrationForm(request.form)
        if request.method == "POST" and form.validate():
            first_name = form.first_name.data
            last_name = form.last_name.data
            email = form.email.data
            phone = form.phone.data
            address = "Not provided"
            city = "Not provided"
            state = "NA"
            czip = form.czip.data
            bio = "Not provided"
            password = sha256_crypt.encrypt((str(form.password.data)))
            c, conn = connection()

            # check if already exists
            x = c.execute(
                "SELECT * FROM clients WHERE email = (%s)", (thwart(email),))
            y = c.execute(
                "SELECT * FROM clients WHERE phone = (%s)", (thwart(phone),))

            if int(x) > 0:
                flash(
                    u'That email already has an account, please try a new email or send an email to help@minute.tech', 'danger')
                return render_template('register.html', form=form)
            elif int(y) > 0:
                flash(
                    u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
                return render_template('register.html', form=form)
            else:
                # make sure this default pic is in the correct folder!!
                default_prof_pic = url_for(
                    'static', filename='user_info/prof_pic/default.jpg')
                c.execute("INSERT INTO clients (email, phone, password) VALUES (%s, %s, %s)", (thwart(
                    email), thwart(phone), thwart(password)))
                c.execute("INSERT INTO cpersonals (first_name, last_name, address, city, state, zip, bio, prof_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (thwart(
                    first_name), thwart(last_name), address, city, state, thwart(czip), bio, default_prof_pic))
                conn.commit()
                flash(u'Thanks for registering!', 'success')
                c.close()
                conn.close()

                session['logged_in'] = 'client'
                # we get the client ID on the first page after it is generated,
                # dont worry
                session['clientcid'] = 0
                session['email'] = email
                session['phone'] = phone
                session['rating'] = 500
                session['first_name'] = first_name
                session['last_name'] = last_name
                session['address'] = address
                session['city'] = city
                session['state'] = state
                session['czip'] = czip
                session['reg_date'] = 0
                session['bio'] = bio
                # change this when the server goes live to the proper folder
                session['prof_pic'] = default_prof_pic
                # Send confirmation email
                token = s.dumps(email, salt='email-confirm')
                msg = Message("Minute.tech - Email Verification",
                              sender="test@minute.tech", recipients=[email])
                link = url_for('main.email_verify',
                               token=token, _external=True)
                msg.body = render_template(
                    'email/email_verify.txt', link=link, first_name=first_name)
                msg.html = render_template(
                    'email/email_verify.html', link=link, first_name=first_name)
                mail.send(msg)
                return redirect(url_for('main.account'))

        return render_template("register.html", form=form)

    except Exception as e:
        return "Error: {}".format(e)


@mod.route('/email_verify/<token>')
def email_verify(token):
    try:
        c, conn = connection()
        if 'logged_in' in session:
            email = s.loads(token, salt='email-confirm', max_age=3600)
            if session['logged_in'] == 'client':
                cid = session['clientcid']
                c.execute(
                    "UPDATE cpersonals SET email_verify = 1 WHERE cid = (%s)", (cid,))
                conn.commit()
                c.close()
                conn.close()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('main.account'))

            elif session['logged_in'] == 'tech':
                tid = session['techtid']
                c.execute(
                    "UPDATE tpersonals SET email_verify = 1 WHERE tid = (%s)", (tid,))
                conn.commit()
                c.close()
                conn.close()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('main.techaccount'))

        else:
            flash(u'Log in first, then click the link again', 'danger')
            return redirect(url_for('main.login'))

        render_template("main.html")
    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))

# @mod.route('/forgot_password/<token>')
# def forgot_password(token):
# 	try:
# 		email = s.loads(token, salt='email-confirm', max_age=3600)
# 		form = PasswordResetForm(request.form)
# 		if request.method == "POST" and form.validate():
# 			password = sha256_crypt.encrypt((str(form.password.data)))
# 			c, conn = connection()
# 			c.execute("UPDATE clients SET password = %s WHERE cid = (%s)", (thwart(password), cid))
# 			conn.commit()
# 			flash(u'Password successfully changed!', 'success')
# 			c.close()
# 			conn.close()
# 			#make sure token cant be used twice
# 			return redirect(url_for('main.account'))

# 		return render_template("forgot_password.html", form=form)

# 	except SignatureExpired:
# 		flash(u'The token has expired', 'danger')
# 		return redirect(url_for('main.homepage'))

# @mod.route('/fforgot_password/')
# def fforgot_password():
# 	try:
# 		# Send confirmation email
# 		f_email = request.form['f_email']
# 		token = s.dumps(email, salt='forgot-password')
# 		msg = Message("Minute.tech - Forgot Password", sender = "admin@minute.tech", recipients=[f_email])
# 		link = url_for('main.forgot_password', token=token, _external=True)
# 		msg.body = render_template('forgot_password-email.txt', link=link, first_name=first_name)
# 		msg.html = render_template('forgot_password-email.html', link=link, first_name=first_name)
# 		mail.send(msg)
# 		flash(u'Password reset link sent to email', 'success')
# 		return redirect(url_for('main.homepage'))

# 	except Exception as e:
# 		return(str(e))

############################################ END 1st Layer ###############

############################################ CLIENT TICKET SYSTEM ########

############## CLIENT SECTION ##########################


@mod.route('/ask/', methods=['GET', 'POST'])
def ask():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['clientcid']
            c.execute(
                "UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
            conn.commit()
            c.close()
            conn.close()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.ask'))

        return render_template("account/ask.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)


@mod.route('/resolved/', methods=['GET', 'POST'])
def resolved():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['clientcid']
            c.execute(
                "UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
            conn.commit()
            c.close()
            conn.close()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.resolved'))

        return render_template("account/resolved.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)


@mod.route('/pending/', methods=['GET', 'POST'])
def pending():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['clientcid']
            c.execute(
                "UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
            conn.commit()
            c.close()
            conn.close()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.pending'))

        return render_template("account/pending.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)

##############  END CLIENT SECTION ##########################

############################################ END CLIENT TICKET SYSTEM ####

############################################ CLIENT ACCOUNT SYSTEM #######


@mod.route('/account/', methods=['GET', 'POST'])
def account():
    error = ''
    try:
        # Declare form early on, so the form is referenced before assignment
        form = EditAccountForm(request.form)
        if session['logged_in'] == 'client':
            # grab all the clients info
            c, conn = connection()
            email = session['email']
            c.execute("SELECT cid FROM clients WHERE email = (%s)", (email,))
            clientcid = c.fetchone()[0]
            c.execute("SELECT phone FROM clients WHERE email = (%s)", (email,))
            phone = c.fetchone()[0]
            c.execute("SELECT rating FROM clients WHERE email = (%s)", (email,))
            rating = c.fetchone()[0]
            c.execute(
                "SELECT first_name FROM cpersonals WHERE cid = (%s)", (clientcid,))
            first_name = c.fetchone()[0]
            c.execute(
                "SELECT last_name FROM cpersonals WHERE cid = (%s)", (clientcid,))
            last_name = c.fetchone()[0]
            c.execute(
                "SELECT address FROM cpersonals WHERE cid = (%s)", (clientcid,))
            address = c.fetchone()[0]
            c.execute("SELECT city FROM cpersonals WHERE cid = (%s)",
                      (clientcid,))
            city = c.fetchone()[0]
            c.execute(
                "SELECT state FROM cpersonals WHERE cid = (%s)", (clientcid,))
            state = c.fetchone()[0]
            c.execute("SELECT zip FROM cpersonals WHERE cid = (%s)", (clientcid,))
            czip = c.fetchone()[0]
            c.execute(
                "SELECT birth_month FROM cpersonals WHERE cid = (%s)", (clientcid,))
            birth_month = c.fetchone()[0]
            c.execute(
                "SELECT birth_day FROM cpersonals WHERE cid = (%s)", (clientcid,))
            birth_day = c.fetchone()[0]
            c.execute(
                "SELECT birth_year FROM cpersonals WHERE cid = (%s)", (clientcid,))
            birth_year = c.fetchone()[0]
            c.execute("SELECT bio FROM cpersonals WHERE cid = (%s)", (clientcid,))
            bio = c.fetchone()[0]
            c.execute(
                "SELECT reg_date FROM cpersonals WHERE cid = (%s)", (clientcid,))
            reg_date = c.fetchone()[0]
            # For now, just putting the prof_pic url into the BLOB
            c.execute(
                "SELECT prof_pic FROM cpersonals WHERE cid = (%s)", (clientcid,))
            prof_pic = c.fetchone()[0]
            conn.commit()
            c.close()
            conn.close()
            session['clientcid'] = clientcid
            session['phone'] = phone
            session['rating'] = rating
            session['first_name'] = first_name
            session['last_name'] = last_name
            session['address'] = address
            session['city'] = city
            session['state'] = state
            session['czip'] = czip
            session['birth_month'] = birth_month
            session['birth_day'] = birth_day
            session['birth_year'] = birth_year
            session['bio'] = bio
            session['reg_date'] = reg_date
            session['prof_pic'] = prof_pic
            session['pconfirm'] = 0
            session['econfirm'] = 0
            session['phconfirm'] = 0
            #//END grab all the clients info
            c, conn = connection()

            # Get value before placing into textarea-box...
            # had to do this method because value=session.bio wasnt working in
            # jinja
            form.bio.data = session['bio']
            if request.method == 'POST' and form.validate():
                first_name = form.first_name.data
                last_name = form.last_name.data
                #email = form.email.data
                #phone = form.phone.data
                address = form.address.data
                city = form.city.data
                state = form.state.data
                czip = form.czip.data
                birth_month = form.birth_month.data
                birth_day = form.birth_day.data
                birth_year = form.birth_year.data
                bio = request.form['bio']
                clientcid = session['clientcid']

                # c.execute("UPDATE clients SET email = %s, phone = %s WHERE cid = (%s)", (email, phone, clientcid))
                c.execute("UPDATE cpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE cid = (%s)", (thwart(
                    first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(czip), birth_month, birth_day, birth_year, bio, clientcid))
                conn.commit()
                c.close()
                conn.close()
                session['first_name'] = first_name
                session['last_name'] = last_name
                # session['email'] = email
                # session['phone'] = phone
                session['address'] = address
                session['city'] = city
                session['state'] = state
                session['czip'] = czip
                session['birth_month'] = birth_month
                session['birth_day'] = birth_day
                session['birth_year'] = birth_year
                session['bio'] = bio

                flash(u'Your account is successfully updated.', 'success')
                return redirect(url_for('main.account'))
        else:
            # this probably isnt necessary since 500 error catches it as no
            # seesion variable called 'logged_in'
            flash(u'Try logging in as a client', 'secondary')

        return render_template("account/account.html", form=form, error=error)

    except Exception as e:
        return render_template("500.html", error=e)

# PASSWORD CONFIRM


@mod.route('/password_confirm/', methods=['GET', 'POST'])
def password_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            c.execute("SELECT * FROM clients WHERE email = (%s)",
                      (thwart(request.form['email']),))
            pdata = c.fetchone()[3]

            if sha256_crypt.verify(request.form['password'], pdata):
                # putting these close and commit
                # functions outside the 'if' will break code
                conn.commit()
                c.close()
                conn.close()
                session['pconfirm'] = 1
                flash(u'Successfully authorized.', 'success')
                return redirect(url_for("main.password_reset"))

            else:
                error = "Invalid credentials, try again."

        return render_template("account/password_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/password_confirm.html", error=error)

# PASSWORD RESET


@mod.route('/password_reset/', methods=['GET', 'POST'])
def password_reset():
    error = ''
    try:
        if session['pconfirm'] == 1:
            form = PasswordResetForm(request.form)
            if request.method == "POST" and form.validate():
                cid = session['clientcid']
                password = sha256_crypt.encrypt((str(form.password.data)))
                c, conn = connection()
                c.execute(
                    "UPDATE clients SET password = %s WHERE cid = (%s)", (thwart(password), cid))
                conn.commit()
                flash(u'Password successfully changed!', 'success')
                c.close()
                conn.close()
                # so they cant get back in!
                session['pconfirm'] = 0
                return redirect(url_for('main.account'))

            return render_template("account/password_reset.html", form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))

# EMAIL CONFIRM


@mod.route('/email_confirm/', methods=['GET', 'POST'])
def email_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            c.execute("SELECT * FROM clients WHERE email = (%s)",
                      (thwart(request.form['email']),))
            pdata = c.fetchone()[3]

            if sha256_crypt.verify(request.form['password'], pdata):
                # putting these close and commit
                # functions outside the 'if' will break code
                conn.commit()
                c.close()
                conn.close()
                session['econfirm'] = 1
                flash(u'Successfully authorized.', 'success')
                return redirect(url_for("main.email_reset"))

            else:
                error = "Invalid credentials, try again."

        return render_template("account/email_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/email_confirm.html", error=error)

# EMAIL RESET


@mod.route('/email_reset/', methods=['GET', 'POST'])
def email_reset():
    error = ''
    try:
        if session['econfirm'] == 1:
            form = EmailResetForm(request.form)
            c, conn = connection()
            if request.method == "POST" and form.validate():
                cid = session['clientcid']
                email = form.email.data
                # check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
                # if form input and the session are the same, we dont care,
                # because nothing will change
                if(email != session["email"]):
                    # too many perethesis, but something is wrong with the the
                    # syntax of the intx for statement
                    x = c.execute(
                        "SELECT * FROM clients WHERE email = (%s)", (thwart(email),))
                    conn.commit()
                    if int(x) > 0:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That email already has an account, please try a different email.', 'danger')
                        return render_template('account/email_reset.html', form=form)

                c.execute(
                    "UPDATE clients SET email = %s WHERE cid = (%s)", (thwart(email), cid))
                conn.commit()
                flash(u'Email successfully changed!', 'success')
                c.close()
                conn.close()
                session['email'] = email
                # so they cant get back in!
                session['econfirm'] = 0
                return redirect(url_for('main.account'))

            return render_template("account/email_reset.html", form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))

# PHONE CONFIRM


@mod.route('/phone_confirm/', methods=['GET', 'POST'])
def phone_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            c.execute("SELECT * FROM clients WHERE email = (%s)",
                      (thwart(request.form['email']),))
            pdata = c.fetchone()[3]

            if sha256_crypt.verify(request.form['password'], pdata):
                # putting these close and commit
                # functions outside the 'if' will break code
                conn.commit()
                c.close()
                conn.close()
                session['phconfirm'] = 1
                flash(u'Successfully authorized.', 'success')
                return redirect(url_for("main.phone_reset"))

            else:
                error = "Invalid credentials, try again."

        return render_template("account/phone_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/phone_confirm.html", error=error)

# PHONE RESET


@mod.route('/phone_reset/', methods=['GET', 'POST'])
def phone_reset():
    error = ''
    try:
        if session['phconfirm'] == 1:
            form = PhoneResetForm(request.form)
            if request.method == "POST" and form.validate():
                c, conn = connection()
                cid = session['clientcid']
                phone = form.phone.data
                # check if phone number exists first
                if(phone != session["phone"]):
                    # too many perethesis, but something is wrong with the the
                    # syntax of the intx for statement
                    x = c.execute(
                        "SELECT * FROM clients WHERE phone = (%s)", (thwart(phone),))
                    conn.commit()
                    if int(x) > 0:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That phone already has an account, please try a different phone.', 'danger')
                        return render_template('account/phone_reset.html', form=form)

                c.execute(
                    "UPDATE clients SET phone = %s WHERE cid = (%s)", (thwart(phone), cid))
                conn.commit()
                flash(u'Phone number successfully changed!', 'success')
                c.close()
                conn.close()
                # so they cant get back in!
                session['phconfirm'] = 0
                return redirect(url_for('main.account'))

            return render_template("account/phone_reset.html", form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('homepage'))

    except Exception as e:
        return(str(e))

# #### PROFILE PIC UPLOAD ####
# # Based after https://gist.github.com/greyli/81d7e5ae6c9baf7f6cdfbf64e8a7c037
# # For uploading files

# ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
# # /var/www/FlaskApp/FlaskApp/static/legal/MinutetechLLC_tos.pdf
# app.config['UPLOADED_PHOTOS_DEST'] = 'static/user_info/prof_pic'
# photos = UploadSet('photos', IMAGES)
# configure_uploads(app, photos)
# patch_request_class(app)  # set maximum file size, default is 16MB

# class ProfilePictureForm(FlaskForm):
# 	prof_pic = FileField(validators=[FileAllowed(photos, u'Image only!')])

# @mod.route('/profile_picture_upload/', methods=['GET','POST'])
# def profile_picture_upload():
# 	form = ProfilePictureForm()
# 	cid = str(session['clientcid'])
# 	first_name = session['first_name']
# 	#default_prof_pic = 'app/uploads/photos/static/user_info/prof_pic/default.jpg'
# 	#user_prof_pic = cid+'_'+first_name+'_'+'.png'
# 	if form.validate_on_submit():
# 		# Checks if the prof_pic is set yet. if set, then dont need to delete the old picture on the server
# 		if session['prof_pic'] != url_for('static', filename='user_info/prof_pic/default.jpg'):
# 			#need to delete or move the old prof_pic if it was set! Prevents users from adding too many pictures
# 			os.remove('static/user_info/prof_pic/'+cid+'_'+first_name+'.png')
        #flash(u'Your account is successfully updated.', 'success')
# 			flash("You already have a file on the server!")
# 		filename = photos.save(form.prof_pic.data, name=cid+'_'+first_name+'.png')
# 		file_url = photos.url(filename)
# 		session['prof_pic'] = file_url
# 		c, conn = connection()
# 		c.execute("UPDATE cpersonals SET prof_pic = %s WHERE cid = (%s)", (file_url, cid))

# 		conn.commit()
# 		c.close()
# 		conn.close()
# 	else:
# 		file_url = None

# return render_template('profile_picture_upload.html', form=form,
# file_url=file_url)

# #### END PROFILE PIC UPLOAD ####

## Error Handlers ##


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")


@app.errorhandler(405)
def method_not_found(e):
    return render_template("405.html")


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html")


## Sending Files (for display on email, probably a better way to do this) ##

@mod.route('/MinutetechLLC_tos/')
def return_tos():
    return send_file('static/legal/MinutetechLLC_tos.pdf', attachment_filename='MinutetechLLC_tos.pdf')


@mod.route('/Minutetech_Logo/')
def return_logo():
    return send_file('static/images/Icon_1000x1000px.png', attachment_filename='Icon_1000x1000px.png')


@mod.route('/coffee-lady/')
def return_pic1():
    return send_file('static/images/lady-logo-email-banner.png', attachment_filename='lady-logo-email-banner.png')


@mod.route('/Minutetech_Long_Logo/')
def return_logo_long():
    return send_file('static/images/Secondary_long.png')


@mod.route('/Minutetech_rocket_ship/')
def return_tocket_ship():
    return send_file('static/flat-icons/008-startup.png')

# # Univers Black
# @mod.route('/Minutetech_font_black/')
# def return_font_black():
# 	return send_file('static/media/fonts/Univers/Univers-Black.otf')
# # Univers Light Condensed
# @mod.route('/Minutetech_font_light/')
# def return_font_light():
# 	return send_file('static/media/fonts/Univers/Univers-CondensedLight.otf')


@mod.route('/file_downloads/')
def file_downloads():
    return render_template('downloads.html')
############################################ END ACCOUNT SYSTEM ##########

if __name__ == "__main__":
    app.run(debug=True)
