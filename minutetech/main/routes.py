# INCLUDED LIBRARIES #
import os
# import sys
import os.path
from flask import (render_template, flash, request,
                   url_for, redirect, session,
                   send_file,
                   # send_from_directory,
                   Blueprint)
from werkzeug.utils import secure_filename
# from wtforms import (Form, BooleanField, TextField,
#                      PasswordField, SelectField, RadioField, TextAreaField,
#                      DateField, DateTimeField, StringField, validators)

# from wtforms.widgets import TextArea
# from wtforms.validators import DataRequired
# from flask_wtf import FlaskForm, RecaptchaField
# from flask_wtf.file import FileField, FileRequired, FileAllowed
# from werkzeug.utils import secure_filename  # For secure file uploads
# from flask_uploads import (UploadSet, configure_uploads,
#                            IMAGES, patch_request_class)
from passlib.hash import sha256_crypt  # To encrypt the password
from MySQLdb import escape_string as thwart  # To prevent SQL injection
from flask_mail import Message  # , Mail
# Email confirmation link that has a short lifespan
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from functools import wraps  # For login_required
# Custom f(x)
from minutetech.dbconnect import connection
from forms import (ContactForm, RegistrationForm, AskForm,
                   EditAccountForm,
                   PasswordResetForm, EmailResetForm, PhoneResetForm,
                   ProfilePictureForm, photos)
from minutetech.config import SECRET_KEY, UPLOAD_FOLDER
from minutetech import mail


main = Blueprint('main', __name__, template_folder='templates')

s = URLSafeTimedSerializer(SECRET_KEY)  # For token

# Flask Uploads
# app.config['UPLOADED_PHOTOS_DEST'] = 'static/user_info/prof_pic'
# configure_uploads(app, photos)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
# patch_request_class(app)


# 1st Layer Pages (Visible to all visitors)

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


@main.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    session.clear()
    flash(u'You have been logged out!', 'danger')
    return redirect(url_for('main.homepage'))


@main.route('/', methods=['GET', 'POST'])
def homepage():
    # if user posts a question to the pool
    form = AskForm(request.form)
    if request.method == "POST" and form.validate():
        difficulty = 0
        title = 'Not provided'
        body = form.body.data
        tags = 'Not provided'
        priority = 500
        cid = session['cid']

        c, conn = connection()
        c.execute("INSERT INTO tickets (cid, difficulty, priority, title, tags) VALUES (%s, %s, %s, %s, %s)",
                  (cid, difficulty, priority, title, tags))
        conn.commit()
        c.execute(
            "SELECT qid FROM tickets WHERE cid = (%s) AND title = (%s)", (cid, title))
        qid = c.fetchone()[0]
        conn.commit()
        c.execute("INSERT INTO threads (qid, cid, body) VALUES (%s, %s, %s)",
                  (qid, cid, body))
        conn.commit()
        c.close()
        conn.close()
        flash(u'Submission successful. We have added your question to the pool!', 'success')
        return redirect(url_for('main.homepage'))

    else:
        error = "We couldn't post your question, please make sure you filled out all the fields properly and try again!"
        return render_template("main.html", form=form)


@main.route('/about/', methods=['GET', 'POST'])
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
                    uid = session['cid']
                if session['logged_in'] == 'tech':
                    uid = session['tid']

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

count = 1


@main.route('/login/', methods=['GET', 'POST'])
def login():
    global count
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM clients WHERE email = (%s)",
                          (thwart(request.form['email']),))
            # Prevent login to another account from this stage
            if int(x) > 0:
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
                    error = "Invalid credentials, try again. Tries: {}".format(
                        count)
            else:
                error = "Invalid authentication, try again. Tries: {}".format(
                    count)
            count += 1

        return render_template("login.html", error=error)

    except Exception as e:
        error = e
        return render_template("login.html", error=error)


@main.route('/register/', methods=['GET', 'POST'])
def register_page():
<<<<<<< HEAD
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
                session['cid'] = 0
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
                session['prof_pic'] = default_prof_pic
                # Send confirmation email
                token = s.dumps(email, salt='email-confirm')
                print "*" * 10
                print token
                print "*" * 10
                msg = Message("Minute.tech - Email Verification",
                              sender="test@minute.tech", recipients=[email])
                link = url_for('main.email_verify',
                               token=token, _external=True)
                msg.body = render_template(
                    'email/email_verify.txt', link=link, first_name=first_name)
                msg.html = render_template(
                    'email/email_verify.html', link=link, first_name=first_name)
                # from IPython import embed
                # embed()
                mail.send(msg)
                return redirect(url_for('main.account'))

        return render_template("register.html", form=form)

    except Exception as e:
        return "Error: {}".format(e)


@main.route('/email_verify/<token>')
def email_verify(token):
    try:
        c, conn = connection()
        if 'logged_in' in session:
            email = s.loads(token, salt='email-confirm', max_age=3600)
            if session['logged_in'] == 'client':
                cid = session['cid']
                c.execute(
                    "UPDATE cpersonals SET email_verify = 1 WHERE cid = (%s)", (cid,))
                conn.commit()
                c.close()
                conn.close()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('main.account'))

            elif session['logged_in'] == 'tech':
                flash(u'Log in as a client first, then click the link again', 'danger')
                return redirect(url_for('main.login'))

        else:
            flash(u'Log in as a client first, then click the link again', 'danger')
            return redirect(url_for('main.login'))

        render_template("main.html")
    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))

# @main.route('/forgot_password/<token>')
=======
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
				session['cid'] = 0
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
				session['prof_pic'] = default_prof_pic
				# Send confirmation email
				token = s.dumps(email, salt='email-verify')
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


@mod.route('/email/email_verify/<token>')
def email_verify(token):
	try:
		c, conn = connection()
		if 'logged_in' in session:
			email = s.loads(token, salt='email-verify', max_age=3600)
			if session['logged_in'] == 'client':
				cid = session['cid']
				c.execute(
					"UPDATE cpersonals SET email_verify = 1 WHERE cid = (%s)", (cid,))
				conn.commit()
				c.close()
				conn.close()
				flash(u'Email successfully verified!', 'success')
				return redirect(url_for('main.account'))

			elif session['logged_in'] == 'tech':
				flash(u'Log in as a client first, then click the link again', 'danger')
				return redirect(url_for('main.login'))

		else:
			flash(u'Log in as a client first, then click the link again', 'danger')
			return redirect(url_for('main.login'))

	except SignatureExpired:
		flash(u'The token has expired', 'danger')
		return redirect(url_for('main.homepage'))


# @mod.route('/forgot_password/<token>')
>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677
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


@main.route('/fforgot_password/')
def fforgot_password():
    try:
        # Send confirmation email
        f_email = request.form['f_email']
        token = s.dumps(email, salt='forgot-password')
        msg = Message("Minute.tech - Forgot Password",
                      sender="admin@minute.tech", recipients=[f_email])
        link = url_for('main.forgot_password', token=token, _external=True)
        msg.body = render_template(
            'forgot_password-email.txt', link=link, first_name=first_name)
        msg.html = render_template(
            'forgot_password-email.html', link=link, first_name=first_name)
        mail.send(msg)
        flash(u'Password reset link sent to email', 'success')
        return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))

############### END 1st Layer ###############

################ 2nd Layer #################


@main.route('/ask/', methods=['GET', 'POST'])
def ask():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['cid']
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


@main.route('/resolved/', methods=['GET', 'POST'])
def resolved():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['cid']
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


@main.route('/pending/', methods=['GET', 'POST'])
def pending():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            cid = session['cid']
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


@main.route('/account/', methods=['GET', 'POST'])
def account():
<<<<<<< HEAD
    error = ''
    try:
        # Declare form early on, so the form is referenced before assignment
        form = EditAccountForm(request.form)
        if session['logged_in'] == 'client':
            # grab all the clients info
            c, conn = connection()
            email = session['email']

            c.execute("""
                SELECT c.cid, c.phone, c.rating,
                p.first_name, p.last_name, p.address, p.city, p.state,
                p.zip, p.birth_month, p.birth_day, p.birth_year, p.bio,
                p.reg_date, p.prof_pic
                FROM clients c, cpersonals p
                WHERE c.email = (%s) and c.cid=p.cid
                """,
                      (email,))
            client = c.fetchone()
            cid = client[0]
            phone = client[1]
            rating = client[2]
            first_name = client[3]
            last_name = client[4]
            address = client[5]
            city = client[6]
            state = client[7]
            czip = client[8]
            birth_month = client[9]
            birth_day = client[10]
            birth_year = client[11]
            bio = client[12]
            reg_date = client[13]
            # For now, just putting the prof_pic url into the BLOB
            prof_pic = client[14]
            conn.commit()
            c.close()
            conn.close()
            session['cid'] = cid
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
                if 'prof_pic' in request.files:
                    new_prof_pic = request.files['prof_pic']
                    if allowed_file(new_prof_pic.filename):
                        filename = secure_filename(new_prof_pic.filename)
                        old_prof_pic = os.path.join(UPLOAD_FOLDER,
                                                    os.path.basename(prof_pic))
                        if os.path.exists(old_prof_pic):
                            os.unlink(old_prof_pic)
                        new_prof_pic.save(os.path.join(
                            UPLOAD_FOLDER, filename))
                        prof_pic = '/static/user_info/' + filename
                        c.execute("""
                            UPDATE cpersonals SET prof_pic=%s
                            where cid = (%s)""",
                                  (thwart(prof_pic), cid))
                first_name = form.first_name.data
                last_name = form.last_name.data
                address = form.address.data
                city = form.city.data
                state = form.state.data
                czip = form.czip.data
                birth_month = form.birth_month.data
                birth_day = form.birth_day.data
                birth_year = form.birth_year.data
                bio = request.form['bio']
                cid = session['cid']
                c.execute("UPDATE cpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE cid = (%s)", (thwart(
                    first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(czip), birth_month, birth_day, birth_year, bio, cid))
                conn.commit()
                c.close()
                conn.close()
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

                flash(u'Your account is successfully updated.', 'success')
                return redirect(url_for('main.account'))
        else:
            # this probably isnt necessary since 500 error catches it as no
            # session variable called 'logged_in'
            flash(u'Try logging in as a client', 'secondary')

        return render_template("account/index.html", form=form, error=error)

    except Exception as e:
        return render_template("500.html", error=e)
=======
	error = ''
	try:
		# Declare form early on, so the form is referenced before assignment
		form = EditAccountForm(request.form)
		if session['logged_in'] == 'client':
			# grab all the clients info
			c, conn = connection()
			email = session['email']
			c.execute("SELECT cid FROM clients WHERE email = (%s)", (email,))
			cid = c.fetchone()[0]
			c.execute("SELECT phone FROM clients WHERE email = (%s)", (email,))
			phone = c.fetchone()[0]
			c.execute("SELECT rating FROM clients WHERE email = (%s)", (email,))
			rating = c.fetchone()[0]
			c.execute(
				"SELECT first_name FROM cpersonals WHERE cid = (%s)", (cid,))
			first_name = c.fetchone()[0]
			c.execute(
				"SELECT last_name FROM cpersonals WHERE cid = (%s)", (cid,))
			last_name = c.fetchone()[0]
			c.execute(
				"SELECT address FROM cpersonals WHERE cid = (%s)", (cid,))
			address = c.fetchone()[0]
			c.execute("SELECT city FROM cpersonals WHERE cid = (%s)",
					  (cid,))
			city = c.fetchone()[0]
			c.execute(
				"SELECT state FROM cpersonals WHERE cid = (%s)", (cid,))
			state = c.fetchone()[0]
			c.execute("SELECT zip FROM cpersonals WHERE cid = (%s)", (cid,))
			czip = c.fetchone()[0]
			c.execute(
				"SELECT birth_month FROM cpersonals WHERE cid = (%s)", (cid,))
			birth_month = c.fetchone()[0]
			c.execute(
				"SELECT birth_day FROM cpersonals WHERE cid = (%s)", (cid,))
			birth_day = c.fetchone()[0]
			c.execute(
				"SELECT birth_year FROM cpersonals WHERE cid = (%s)", (cid,))
			birth_year = c.fetchone()[0]
			c.execute("SELECT bio FROM cpersonals WHERE cid = (%s)", (cid,))
			bio = c.fetchone()[0]
			c.execute(
				"SELECT reg_date FROM cpersonals WHERE cid = (%s)", (cid,))
			reg_date = c.fetchone()[0]
			c.execute(
				"SELECT email_verify FROM cpersonals WHERE cid = (%s)", (cid,))
			email_verify = c.fetchone()[0]
			# For now, just putting the prof_pic url into the BLOB
			c.execute(
				"SELECT prof_pic FROM cpersonals WHERE cid = (%s)", (cid,))
			prof_pic = c.fetchone()[0]
			conn.commit()
			c.close()
			conn.close()
			session['cid'] = cid
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
			session['email_verify'] = email_verify
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
				address = form.address.data
				city = form.city.data
				state = form.state.data
				czip = form.czip.data
				birth_month = form.birth_month.data
				birth_day = form.birth_day.data
				birth_year = form.birth_year.data
				bio = request.form['bio']
				cid = session['cid']
				c.execute("UPDATE cpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE cid = (%s)", (thwart(
					first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(czip), birth_month, birth_day, birth_year, bio, cid))
				conn.commit()
				c.close()
				conn.close()
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

				flash(u'Your account is successfully updated.', 'success')
				return redirect(url_for('main.account'))
		else:
			# this probably isnt necessary since 500 error catches it as no
			# session variable called 'logged_in'
			flash(u'Try logging in as a client', 'secondary')

		return render_template("account/index.html", form=form, error=error)

	except Exception as e:
		return render_template("500.html", error=e)
>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677

# PASSWORD CONFIRM


@main.route('/password_confirm/', methods=['GET', 'POST'])
def password_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM clients WHERE email = (%s)",
                          (thwart(request.form['email']),))
            # Prevent login to another account from this stage
            if int(x) > 0 and request.form['email'] == session['email']:
                pdata = c.fetchone()[3]
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
            else:
                error = "Invalid authentication, try again."

        return render_template("account/password_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/password_confirm.html", error=error)

# PASSWORD RESET


@main.route('/password_reset/', methods=['GET', 'POST'])
def password_reset():
    error = ''
    try:
        if session['pconfirm'] == 1:
            form = PasswordResetForm(request.form)
            if request.method == "POST" and form.validate():
                cid = session['cid']
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


@main.route('/email_confirm/', methods=['GET', 'POST'])
def email_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM clients WHERE email = (%s)",
                          (thwart(request.form['email']),))
            # Prevent login to another account from this stage
            if int(x) > 0 and request.form['email'] == session['email']:
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
            else:
                error = "Invalid authentication, try again."

        return render_template("account/email_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/email_confirm.html", error=error)

# EMAIL RESET


@main.route('/email_reset/', methods=['GET', 'POST'])
def email_reset():
    error = ''
    try:
        if session['econfirm'] == 1:
            form = EmailResetForm(request.form)
            c, conn = connection()
            if request.method == "POST" and form.validate():
                cid = session['cid']
                email = form.email.data
                if(email != session["email"]):
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


@main.route('/phone_confirm/', methods=['GET', 'POST'])
def phone_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM clients WHERE email = (%s)",
                          (thwart(request.form['email']),))
            # Prevent login to another account from this stage
            if int(x) > 0 and request.form['email'] == session['email']:
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
            else:
                error = "Invalid authentication, try again."
        return render_template("account/phone_confirm.html", error=error)

    except Exception as e:
        error = e
        return render_template("account/phone_confirm.html", error=error)

# PHONE RESET


@main.route('/phone_reset/', methods=['GET', 'POST'])
def phone_reset():
    error = ''
    try:
        if session['phconfirm'] == 1:
            form = PhoneResetForm(request.form)
            if request.method == "POST" and form.validate():
                c, conn = connection()
                cid = session['cid']
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
                session["phone"] = phone
                # so they cant get back in!
                session['phconfirm'] = 0
                return redirect(url_for('main.account'))

            return render_template("account/phone_reset.html", form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('homepage'))

    except Exception as e:
        return(str(e))

@mod.route('/email/send_email_verify/', methods=['GET', 'POST'])
def send_email_verify():
	if 'logged_in' in session and request.method == "GET":
		email = session['email']
		first_name = session['first_name']
		# Send confirmation email
		token = s.dumps(email, salt='email-verify')
		msg = Message("Minute.tech - Email Verification",
					  sender="test@minute.tech", recipients=[email])
		link = url_for('main.email_verify',
					   token=token, _external=True)
		msg.body = render_template(
			'email/send_email_verify.txt', link=link, first_name=first_name)
		msg.html = render_template(
			'email/send_email_verify.html', link=link, first_name=first_name)
		mail.send(msg)
		flash(u'Verification email sent', 'success')
		return redirect(url_for('main.account'))
	else:
		flash(u'Log in as a client first, then click the link again', 'danger')
		return redirect(url_for('main.login'))

#### PROFILE PIC UPLOAD ####
# Based after https://gist.github.com/greyli/81d7e5ae6c9baf7f6cdfbf64e8a7c037
# For uploading files
# /var/www/FlaskApp/FlaskApp/static/legal/MinutetechLLC_tos.pdf
# set maximum file size, default is 16MB


@main.route('/profile_picture_upload/', methods=['GET', 'POST'])
def profile_picture_upload():
    form = ProfilePictureForm()
    cid = str(session['cid'])
    first_name = session['first_name']
    # default_prof_pic = 'app/uploads/photos/static/user_info/prof_pic/default.jpg'
    # user_prof_pic = cid+'_'+first_name+'_'+'.png'
    if form.validate_on_submit():
        # Checks if the prof_pic is set yet. if set, then dont need to delete
        # the old picture on the server
        if session['prof_pic'] != url_for('static', filename='user_info/prof_pic/default.jpg'):
            # need to delete or move the old prof_pic if it was set! Prevents
            # users from adding too many pictures
            os.remove('static/user_info/prof_pic/' +
                      cid + '_' + first_name + '.png')
            flash(u'Your account is successfully updated.', 'success')
            # flash("You already have a file on the server!")
        filename = photos.save(
            form.prof_pic.data, name=cid + '_' + first_name + '.png')
        file_url = photos.url(filename)
        session['prof_pic'] = file_url
        c, conn = connection()
        c.execute(
            "UPDATE cpersonals SET prof_pic = %s WHERE cid = (%s)", (file_url, cid))
        conn.commit()
        c.close()
        conn.close()
    else:
        file_url = None

    return render_template('account/profile_picture_upload.html', form=form,
                           file_url=file_url)

# #### END PROFILE PIC UPLOAD ####

<<<<<<< HEAD
=======
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

>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677
## Sending Files (for display on email, probably a better way to do this) ##


@main.route('/MinutetechLLC_tos/')
def return_tos():
    return send_file('static/legal/MinutetechLLC_tos.pdf', attachment_filename='MinutetechLLC_tos.pdf')

<<<<<<< HEAD

@main.route('/Minutetech_Logo/')
=======
@mod.route('/Minutetech_Logo/')
>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677
def return_logo():
    return send_file('static/images/Icon_1000x1000px.png', attachment_filename='Icon_1000x1000px.png')

<<<<<<< HEAD

@main.route('/coffee-lady/')
def return_pic1():
    return send_file('static/images/lady-logo-email-banner.png', attachment_filename='lady-logo-email-banner.png')

=======
@mod.route('/coffee-lady/')
def return_pic1():
	return send_file('static/images/lady-logo-email-banner750x500.png', attachment_filename='lady-logo-email-banner750x500.png')
>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677

@main.route('/Minutetech_Long_Logo/')
def return_logo_long():
    return send_file('static/images/Secondary_long.png')


@main.route('/Minutetech_rocket_ship/')
def return_tocket_ship():
    return send_file('static/flat-icons/008-startup.png')

<<<<<<< HEAD

# if __name__ == "__main__":
#     app.run(debug=True)
=======
if __name__ == "__main__":
	app.run(debug=True)
>>>>>>> f630e9b9ac8577f5c975ba4c5e202262bdb71677
