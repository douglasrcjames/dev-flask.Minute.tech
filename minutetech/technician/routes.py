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
from itsdangerous import URLSafeTimedSerializer, SignatureExpired # Email confirmation link that has a short lifespan
from functools import wraps  # For login_required
# Custom f(x)
from ..dbconnect import connection
from ..forms import TechRegistrationForm, TechEditAccountForm, TechPasswordResetForm, TechEmailResetForm, TechPhoneResetForm, TechSignatureForm
# Might be able to delete some of these from _ imports, test later for dependencies in files/folders.

app = Flask(__name__)
mod = Blueprint('technician', __name__, template_folder='templates')
# Key cross-referenced from flaskapp.wsgi
app.config['SECRET_KEY'] = 'quincyisthebestdog11'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # For token
# Flask Mail
app.config.from_pyfile('config.cfg')
mail = Mail(app)
##############  1st Layer SECTION  ####################
def login_required(f):
	#not 100% how this works
	# logged_in doesnt look like its user anywhere, be sure of these and delete if not anywhere else
	@wraps(f)
	def wrap(*args, **kwargs):
		if ('logged_in') in session:
			#arguments and key word arguments
			return f(*args, **kwargs)
		else:
			flash(u'You need to login first.', 'danger')
			return redirect(url_for('technician.login'))
	return wrap

@mod.route('/logout/', methods=['GET','POST'])
@login_required
def logout():
	session.clear()
	flash(u'You have been logged out!', 'danger')
	return redirect(url_for('main.homepage'))

@mod.route('/login/', methods=['GET','POST'])
def login():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['email']),))
			pdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], pdata):
				email = request.form['email']
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['logged_in'] = ''
				session['email'] = thwart(email)
				flash(u'You are now logged in.', 'success')
				return redirect(url_for('technician.account'))
			
			else:
				error = "Invalid credentials, try again."

		return render_template('technician/login.html', error = error)
		
	except Exception as e:
		error = e
		return render_template('technician/login.html', error = error)
	
@mod.route('/register/', methods=['GET','POST'])
def register_page():
	error = ''
	try:
		form = TechRegistrationForm(request.form)
		if request.method == "POST" and form.validate():
			first_name = form.first_name.data
			last_name = form.last_name.data
			email = form.email.data
			phone = form.phone.data
			address = form.address.data
			city = form.city.data
			state = form.state.data
			tzip = form.tzip.data
			bio = "Not provided"
			password = sha256_crypt.encrypt((str(form.password.data)))
			c, conn = connection()

			#check if already exists
			x = c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(email),))
			y = c.execute("SELECT * FROM technicians WHERE phone = (%s)", (thwart(phone),))

			if int(x) > 0:
				flash(u'That email already has an account, please try a new email or send an email to help@minute.', 'danger')
				return render_template('technician/register.html', form=form)
			elif int(y) > 0:
				flash(u'That phone already has an account, please try a new phone or send an email to help@minute.', 'danger')
				return render_template('technician/register.html', form=form)
			else:
				default_prof_pic = url_for('static', filename='_user_info/prof_pic/default.jpg')
				c.execute("INSERT INTO technicians (email, phone, password) VALUES (%s, %s, %s)", (thwart(email), thwart(phone), thwart(password)))
				c.execute("INSERT INTO tpersonals (first_name, last_name, address, city, state, zip, bio, prof_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (thwart(first_name), thwart(last_name), thwart(address), thwart(city), state, thwart(tzip), bio, default_prof_pic))
				conn.commit()
				flash(u'Thanks for registering!', 'success')
				c.close()
				conn.close()

				session['logged_in'] = ''

				#tid will be inputted once generated
				session['tid'] = 0
				session['email'] = email
				session['phone'] = phone
				session['rating'] = 0
				session['first_name'] = first_name
				session['last_name'] = last_name
				session['address'] = address
				session['city'] = city
				session['state'] = state
				session['tzip'] = tzip
				session['reg_date'] = 0
				session['bio'] = bio
				#change this when the server goes live to the proper folder
				session['prof_pic'] = default_prof_pic
				# Send confirmation email
				token = s.dumps(email, salt='email-confirm')
				msg = Message("Minute. - Email Verification", sender = "test@minute.", recipients=[email])
				link = url_for('technician.email.email_verify', token=token, _external=True)
				msg.body = render_template('technician/email/verify.txt', link=link, first_name=first_name)
				msg.html = render_template('technician/email/verify.html', link=link, first_name=first_name)
				mail.send(msg)
				return redirect(url_for('technician.account'))

		return render_template('technician/register.html', form=form)


	except Exception as e:
		return(str(e))

##############  2nd Layer SECTION  ####################
@mod.route('/answer/', methods=['GET','POST'])
def answer():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['tid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('technician.answer'))

		return render_template('technician/answer.html', error = error)

	except Exception as e:
		return render_template('500.html', error = e)

@mod.route('/resolved/', methods=['GET','POST'])
def resolved():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['tid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('technician.resolved'))

		return render_template('technician/resolved.html', error = error)

	except Exception as e:
		return render_template('500.html', error = e)


@mod.route('/room/?select_q=<select_q>', methods=['GET','POST'])
def room(select_q):
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['tid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('main.homepage'))

		return render_template('technician/room.html', error = error)

	except Exception as e:
		return render_template('500.html', error = e)


@mod.route('/pending/', methods=['GET','POST'])
def pending():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['tid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('technician.pending'))

		return render_template('technician/pending.html', error = error)

	except Exception as e:
		return render_template('500.html', error = e)

@mod.route('/account/', methods=['GET','POST'])
def account():
	error = ''
	# Using this global variable is tough because each time I redirect, even to the same page, it forgets the value. Make it a session varaible maybe?
	try:
		# Declare form early on, so the form is referenced before assignment
		form = TechEditAccountForm(request.form)
		if session['logged_in'] == '':
			#grab all the clients info
			c, conn = connection()
			email = session['email']
			c.execute("SELECT tid FROM technicians WHERE email = (%s)", (email,))
			tid = c.fetchone()[0]
			c.execute("SELECT phone FROM technicians WHERE email = (%s)", (email,))
			phone = c.fetchone()[0]
			c.execute("SELECT rating FROM technicians WHERE email = (%s)", (email,))
			rating = c.fetchone()[0]
			c.execute("SELECT first_name FROM tpersonals WHERE tid = (%s)", (tid,))
			first_name = c.fetchone()[0]
			c.execute("SELECT last_name FROM tpersonals WHERE tid = (%s)", (tid,))
			last_name = c.fetchone()[0]
			c.execute("SELECT address FROM tpersonals WHERE tid = (%s)", (tid,))
			address = c.fetchone()[0]
			c.execute("SELECT city FROM tpersonals WHERE tid = (%s)", (tid,))
			city = c.fetchone()[0]
			c.execute("SELECT state FROM tpersonals WHERE tid = (%s)", (tid,))
			state = c.fetchone()[0]
			c.execute("SELECT zip FROM tpersonals WHERE tid = (%s)", (tid,))
			tzip = c.fetchone()[0]
			c.execute("SELECT birth_month FROM tpersonals WHERE tid = (%s)", (tid,))
			birth_month = c.fetchone()[0]
			c.execute("SELECT birth_day FROM tpersonals WHERE tid = (%s)", (tid,))
			birth_day = c.fetchone()[0]
			c.execute("SELECT birth_year FROM tpersonals WHERE tid = (%s)", (tid,))
			birth_year = c.fetchone()[0]
			c.execute("SELECT bio FROM tpersonals WHERE tid = (%s)", (tid,))
			bio = c.fetchone()[0]
			c.execute("SELECT reg_date FROM tpersonals WHERE tid = (%s)", (tid,))
			reg_date = c.fetchone()[0]
			# For now, just putting the prof_pic url into the BLOB
			c.execute("SELECT prof_pic FROM tpersonals WHERE tid = (%s)", (tid,))
			prof_pic = c.fetchone()[0]
			conn.commit()
			c.close()
			conn.close()
			session['tid'] = tid
			session['phone'] = phone
			session['rating'] = rating
			session['first_name'] = first_name
			session['last_name'] = last_name
			session['address'] = address
			session['city'] = city
			session['state'] = state
			session['tzip'] = tzip
			session['birth_month'] = birth_month
			session['birth_day'] = birth_day
			session['birth_year'] = birth_year
			session['bio'] = bio
			session['reg_date'] = reg_date
			session['prof_pic'] = prof_pic
			session['pconfirm'] = 0
			session['phconfirm'] = 0
			session['econfirm'] = 0
			#//END grab all the clients info
			c, conn = connection()
			
			#Get value before placing into textarea-box... 
			#had to do this method because value=session.bio wasnt working in jinja
			form.bio.data = session['bio']
			if request.method == 'POST' and form.validate():
				first_name = form.first_name.data
				last_name = form.last_name.data
				address = form.address.data
				city = form.city.data
				state = form.state.data
				tzip = form.tzip.data
				birth_month = form.birth_month.data
				birth_day = form.birth_day.data
				birth_year = form.birth_year.data
				bio = request.form['bio']
				tid = session['tid']
				c.execute("UPDATE tpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE tid = (%s)", (thwart(first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(tzip), birth_month, birth_day, birth_year, bio, tid))
				conn.commit()
				c.close()
				conn.close()
				session['first_name'] = first_name
				session['last_name'] = last_name
				session['address'] = address
				session['city'] = city
				session['state'] = state
				session['tzip'] = tzip
				session['birth_month'] = birth_month
				session['birth_day'] = birth_day
				session['birth_year'] = birth_year
				session['bio'] = bio
				flash(u'Your account is successfully updated.', 'success')
				return redirect(url_for('technician.account'))
		else:
			flash(u'Try logging out and back in again!', 'secondary')
			return redirect(url_for('homepage'))

		return render_template('technician/index.html', form=form, error = error)

	except Exception as e:
		return render_template('500.html', error = e)

@mod.route('/duties/', methods=['GET','POST'])
def _duties():
	return render_template('technician/duties.html')

@mod.route('/tech_signature/', methods=['GET','POST'])
def tech_signature():
	form = TechSignatureForm(request.form)
	if request.method == "POST" and form.validate():
		signature = form.signature.data
		tid = session['tid']
		c, conn = connection()
		c.execute("UPDATE tpersonals SET signature = %s WHERE tid = (%s)", (thwart(signature), tid))
		conn.commit()
		c.close()
		conn.close()
		flash(u'Submission successful. We will contact you soon.', 'success')
		return redirect(url_for('technician.account'))

	else:
		error = "Please enter your name!"
		return render_template('technician/tech_signature.html', form=form)

#PASSWORD CONFIRM
@mod.route('/password_confirm/', methods=['GET','POST'])
def password_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['email']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['pconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for('technician.password_reset'))
			
			else:
				error = "Invalid credentials, try again."

		return render_template('technician/password_confirm.html', error = error)
		
	except Exception as e:
		error = e
		return render_template('technician/password_confirm.html', error = error)

# PASSWORD RESET
@mod.route('/password_reset/', methods=['GET','POST'])
def password_reset():
	error = ''
	try:
		if session['pconfirm'] == 1:
			form = TechPasswordResetForm(request.form)
			if request.method == "POST" and form.validate():
				tid = session['tid']
				password = sha256_crypt.encrypt((str(form.password.data)))
				c, conn = connection()
				c.execute("UPDATE technicians SET password = %s WHERE tid = (%s)", (thwart(password), tid))
				conn.commit()
				flash(u'Password successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['pconfirm'] = 0
				return redirect(url_for('technician.account'))

			return render_template('technician/password_reset.html', form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('main.homepage'))

	except Exception as e:
		return(str(e))

# EMAIL CONFIRM
@mod.route('/email_confirm/', methods=['GET','POST'])
def email_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['email']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['econfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for('technician.email_reset'))
			
			else:
				error = "Invalid credentials, try again."

		return render_template('technician/email_confirm.html', error = error)
		
	except Exception as e:
		error = e
		return render_template('technician/email_confirm.html', error = error)

# EMAIL RESET
@mod.route('/email_reset/', methods=['GET','POST'])
def email_reset():
	error = ''
	try:
		if session['econfirm'] == 1:
			form = TechEmailResetForm(request.form)
			c, conn = connection()
			if request.method == "POST" and form.validate():
				tid = session['tid']
				email = form.email.data
				#check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
				# if form input and the session are the same, we dont care, because nothing will change
				if(email != session["email"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(email),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That email already has an account, please try a different email.', 'danger')
						return render_template('technician/email_reset.html', form=form)

				c.execute("UPDATE technicians SET email = %s WHERE tid = (%s)", (thwart(email), tid))
				conn.commit()
				flash(u'Email successfully changed!', 'success')
				c.close()
				conn.close()
				session['email'] = email
				#so they cant get back in!
				session['econfirm'] = 0
				return redirect(url_for('technician.account'))

			return render_template('technician/email_reset.html', form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('main.homepage'))

	except Exception as e:
		return(str(e))

# PHONE CONFIRM
@mod.route('/phone_confirm/', methods=['GET','POST'])
def phone_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['email']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['phconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for('technician.phone_reset'))
			
			else:
				error = "Invalid credentials, try again."

		return render_template('technician/phone_confirm.html', error = error)
		
	except Exception as e:
		error = e
		return render_template('technician/phone_confirm.html', error = error)


# PHONE RESET
@mod.route('/phone_reset/', methods=['GET','POST'])
def phone_reset():
	error = ''
	try:
		if session['phconfirm'] == 1:
			form = TechPhoneResetForm(request.form)
			if request.method == "POST" and form.validate():
				#check if phone number exists first
				tid = session['tid']
				phone = form.phone.data
				c, conn = connection()
				if(phone != session["phone"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM technicians WHERE phone = (%s)", (thwart(phone),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That phone already has an account, please try a different phone.', 'danger')
						return render_template('technician/phone_reset.html', form=form)

				c.execute("UPDATE technicians SET phone = %s WHERE tid = (%s)", (thwart(phone), tid))
				conn.commit()
				flash(u'Phone number successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['phconfirm'] = 0
				return redirect(url_for('technician.account'))

			return render_template('technician/phone_reset.html', form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('main.homepage'))

	except Exception as e:
		return(str(e))



# #### PROFILE PIC UPLOAD ####
# # Based after https://gist.github.com/greyli/81d7e5ae6c9baf7f6cdfbf64e8a7c037
# # For uploading files
# _PROF_PIC_UPLOAD_FOLDER = 'static/_user_info/prof_pic'
# ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
# app.config['_UPLOADED_PHOTOS_DEST'] = os.getcwd()
# photos = UploadSet('photos', IMAGES)
# configure_uploads(app, photos)
# patch_request_class(app)  # set maximum file size, default is 16MB

# class ProfilePictureForm(FlaskForm):
# 	prof_pic = FileField(validators=[FileAllowed(photos, u'Image only!')])

# @mod.route('/_profile_picture_upload/', methods=['GET','POST'])
# def _profile_picture_upload():
# 	form = ProfilePictureForm()
# 	tid = str(session['tid'])
# 	first_name = session['first_name']
# 	default_prof_pic = url_for('static', filename='user_info/prof_pic/default.jpg')
# 	user_prof_pic = tid+'_'+first_name+'_'+'.png'
# 	if form.validate_on_submit():
# 		filename = photos.save(form.prof_pic.data, folder=_PROF_PIC_UPLOAD_FOLDER,name=tid+'_'+first_name+'_'+'.png')
# 		file_url = photos.url(filename)
# 		# Checks if the prof_pic is set yet. if set, then dont need to delete the old picture on the server
# 		# if session['prof_pic'] != 'http://138.68.238.112/var/www/FlaskApp/FlaskApp/_uploads/photos/static/_user_info/prof_pic/default.jpg':
# 		# 	#need to delete or move the old prof_pic if it was set! Prevents users from adding too many pictures
#flash(u'Submission successful. We will contact you soon.', 'success')
# 		# 	flash("You already have a file on the server!")
# 		#If the user_prof_pic is there, then  
# 		session['prof_pic'] = file_url
# 		c, conn = connection()
# 		c.execute("UPDATE tpersonals SET prof_pic = %s WHERE tid = (%s)", (file_url, tid))
# 		conn.commit()
# 		c.close()
# 		conn.close()
# 	else:
# 		file_url = None

# 	return render_template('_profile_picture_upload.html', form=form, file_url=file_url)
##############  END TECHNICIAN SECTION  ####################