###################################################################################################################################################################
###################################################################################################################################################################
#########################################  MINUTE.TECH SOURCE CODE by: Douglas James with Minute.tech LLC #########################################################
###################################################################################################################################################################
###################################################################################################################################################################

###### INCLUDED LIBRARIES ######
import os, sys, os.path
from flask import Flask, render_template, flash, request, url_for, redirect, session, send_file, send_from_directory
# WTForms
from wtforms import Form, BooleanField, TextField, PasswordField, SelectField, RadioField, TextAreaField, DateField, DateTimeField, StringField, validators
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired
# Flask WTF 
# -different than WTForms!
# -has reCAPTCHA!
# -builds ontop of Flask and wtforms
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
# For secure file uploads
from werkzeug.utils import secure_filename
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired #email confirmation link that has a short lifespan
# To encrypt the password
from passlib.hash import sha256_crypt
# For SQL injection
from MySQLdb import escape_string as thwart
from functools import wraps
# My custom database connection function
from dbconnect import connection
# UPLOAD_FOLDER = '/var/www/FlaskApp/FlaskApp/static/user_info/prof_pic'
# ALLOWED_EXTENSIONS = set(['png','jpg','jpeg','gif'])
app = Flask(__name__, static_folder='static')
# Key cross-referenced from flaskapp.wsgi
app.config['SECRET_KEY'] = 'quincyisthebestdog11'
#For Flask Mail
app.config.from_pyfile('config.cfg')
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) #token for email confirmation
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lc54UgUAAAAAPj5zf-R_pmKlnC_gBQSQ7EYfkzU'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lc54UgUAAAAAKvQv4x3QaYwKx5iZHAWiTO8Ft05'
app.config['TESTING'] = False #turns reacaptcha off/on
## GLOBALS

#############  FUNCTIONS  ##################

#temporary to ask questions on homepage
#will eventually want a new user to be able to type a question out, but directed to sign up page immediatly, but their question is still saved and placed in database
@app.route('/test/', methods=['GET','POST'])
def test():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			msg = Message("Minute.tech - Email Verification", sender = "admin@minute.tech", recipients=[session['email']])
			msg.body = render_template('email_verify.txt')
			msg.html = render_template('email_verify.html')
			mail.send(msg)
			flash(u'Submitted', 'success')
			return redirect(url_for('test'))

		return render_template("test.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

############################ PAGES #################################
class AskForm(Form):
	body = TextAreaField('Desciption', [validators.Length(min=10, max=2000)])

@app.route('/', methods=['GET','POST'])
def homepage():
	#if user posts a question to the pool
	form = AskForm(request.form)
	if request.method == "POST" and form.validate():
		difficulty =  0
		title = 'Not provided'
		body = form.body.data
		tags = 'Not provided'
		priority = 500
		clientcid = session['clientcid']

		c, conn = connection()
		c.execute("INSERT INTO tickets (cid, difficulty, priority, title, tags) VALUES (%s, %s, %s, %s, %s)", (clientcid, difficulty, priority, title, tags))
		conn.commit()
		# Get qid after the ticket is generated after an initial "ask" page request
		c.execute("SELECT qid FROM tickets WHERE cid = (%s) AND title = (%s)", (clientcid, title))
		qid = c.fetchone()[0]
		conn.commit()
		c.execute("INSERT INTO threads (qid, cid, body) VALUES (%s, %s, %s)", (qid, clientcid, body))
		conn.commit()
		c.close()
		conn.close()
		flash(u'Submission successful. We have added your question to the pool!', 'success')
		return redirect(url_for('homepage'))

	else:
		error = "We couldn't post your question, please make sure you filled out all the fields properly and try again!"
		return render_template("main.html", form=form)

class ContactForm(Form):
	message = TextAreaField('Message', [validators.Length(min=10, max=2000)])
	email = TextField('Email', [validators.Optional()])

@app.route('/about/', methods=['GET','POST'])
def about():
	uid = 0
	try:
		form = ContactForm(request.form)
		if request.method == "POST" and form.validate():
			message = form.message.data
			# If user is logged in, set email to their email, otherwise, empty (on html side)
			email = form.email.data
			
			# Get user ID
			if 'logged_in' in session:
				if session['logged_in'] == 'client':
					uid = session['clientcid']
				if session['logged_in'] == 'tech':
					uid = session['techtid']

			# Throw data in database
			c, conn = connection()
			c.execute("INSERT INTO contact (message, email, uid) VALUES (%s, %s, %s)", (message, email, uid))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Submission successful. We will get back to you as soon as possible!', 'success')
			return redirect(url_for('about'))

		else:
			error = "We couldn't post your comment, please make sure you filled out all the fields properly, or try reloading the page and asking again."
			return render_template("about.html", form=form)

	except Exception as e:
		return render_template("500.html", error = e)

@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html")

@app.errorhandler(405)
def method_not_found(e):
	return render_template("405.html")

@app.errorhandler(500)
def internal_server_error(e):
	return render_template("500.html")


############################################ TICKET SYSTEM #########################################################

############## CLIENT SECTION ##########################

@app.route('/ask/', methods=['GET','POST'])
def ask():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			cid = session['clientcid']
			c.execute("UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('ask'))

		return render_template("ask.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@app.route('/resolved/', methods=['GET','POST'])
def resolved():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			cid = session['clientcid']
			c.execute("UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('resolved'))

		return render_template("resolved.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@app.route('/pending/', methods=['GET','POST'])
def pending():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			cid = session['clientcid']
			c.execute("UPDATE cpersonals SET launch_email = 1 WHERE cid = (%s)", (cid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('pending'))

		return render_template("pending.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

##############  END CLIENT SECTION ##########################

##############  TECHNICIAN SECTION  ####################
@app.route('/answer/', methods=['GET','POST'])
def answer():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['techtid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('answer'))

		return render_template("answer.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@app.route('/techresolved/', methods=['GET','POST'])
def techresolved():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['techtid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('techresolved'))

		return render_template("techresolved.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)


@app.route('/techroom/?select_q=<select_q>', methods=['GET','POST'])
def techroom(select_q):
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['techtid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('techroom'))

		return render_template("techroom.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)


@app.route('/techpending/', methods=['GET','POST'])
def techpending():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			tid = session['techtid']
			c.execute("UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
			conn.commit()
			c.close()
			conn.close()
			flash(u'Thanks, we got you down!', 'success')
			return redirect(url_for('techpending'))

		return render_template("techpending.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

##############  END TECHNICIAN SECTION  ####################

############################################ END TICKET SYSTEM #########################################################


############################################ ACCOUNT SYSTEM #########################################################
class EditAccountForm(Form):
	first_name = TextField('First Name', [validators.Length(min=1, max=50)])
	last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	#email = TextField('Email Address', [validators.Length(min=6, max=50)])
	#phone = TextField('Phone Number', [validators.Length(min=10, max=20)])
	address = TextField('Street Address', [validators.Length(min=6, max=100)])
	city = TextField('City', [validators.Length(min=2, max=50)])
	state = TextField('State', [validators.Length(min=2, max=50)])
	czip = TextField('ZIP', [validators.Length(min=2, max=16)])
	birth_month = TextField('Birthday', [validators.Length(min=2, max=16)])
	birth_day = TextField('&nbsp;', [validators.Length(min=1, max=2)])
	birth_year = TextField('&nbsp;', [validators.Length(min=4, max=4)])
	bio = TextAreaField('Personal Description', [validators.Length(min=1, max=2000)], widget=TextArea())
	# password = PasswordField('Password', [validators.Required(), validators.EqualTo('techconfirm', message ="Passwords must match.")])
	# confirm = PasswordField('Repeat Password')

@app.route('/account/', methods=['GET','POST'])
def account():
	error = ''
	try:
		# Declare form early on, so the form is referenced before assignment
		form = EditAccountForm(request.form)
		if session['logged_in'] == 'client':
			#grab all the clients info
			c, conn = connection()
			email = session['email']
			c.execute("SELECT cid FROM clients WHERE email = (%s)", (email,))
			clientcid = c.fetchone()[0]
			c.execute("SELECT phone FROM clients WHERE email = (%s)", (email,))
			phone = c.fetchone()[0]
			c.execute("SELECT rating FROM clients WHERE email = (%s)", (email,))
			rating = c.fetchone()[0]
			c.execute("SELECT first_name FROM cpersonals WHERE cid = (%s)", (clientcid,))
			first_name = c.fetchone()[0]
			c.execute("SELECT last_name FROM cpersonals WHERE cid = (%s)", (clientcid,))
			last_name = c.fetchone()[0]
			c.execute("SELECT address FROM cpersonals WHERE cid = (%s)", (clientcid,))
			address = c.fetchone()[0]
			c.execute("SELECT city FROM cpersonals WHERE cid = (%s)", (clientcid,))
			city = c.fetchone()[0]
			c.execute("SELECT state FROM cpersonals WHERE cid = (%s)", (clientcid,))
			state = c.fetchone()[0]
			c.execute("SELECT zip FROM cpersonals WHERE cid = (%s)", (clientcid,))
			czip = c.fetchone()[0]
			c.execute("SELECT birth_month FROM cpersonals WHERE cid = (%s)", (clientcid,))
			birth_month = c.fetchone()[0]
			c.execute("SELECT birth_day FROM cpersonals WHERE cid = (%s)", (clientcid,))
			birth_day = c.fetchone()[0]
			c.execute("SELECT birth_year FROM cpersonals WHERE cid = (%s)", (clientcid,))
			birth_year = c.fetchone()[0]
			c.execute("SELECT bio FROM cpersonals WHERE cid = (%s)", (clientcid,))
			bio = c.fetchone()[0]
			c.execute("SELECT reg_date FROM cpersonals WHERE cid = (%s)", (clientcid,))
			reg_date = c.fetchone()[0]
			# For now, just putting the prof_pic url into the BLOB
			c.execute("SELECT prof_pic FROM cpersonals WHERE cid = (%s)", (clientcid,))
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
			
			#Get value before placing into textarea-box... 
			#had to do this method because value=session.bio wasnt working in jinja
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
				c.execute("UPDATE cpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE cid = (%s)", (thwart(first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(czip), birth_month, birth_day, birth_year, bio, clientcid))
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
				return redirect(url_for('account'))
		else:
			#this probably isnt necessary since 500 error catches it as no seesion variable called 'logged_in'
			flash(u'Try logging in as a client', 'secondary')

		return render_template("account.html", form=form, error = error)

	except Exception as e:
		return render_template("500.html", error = e)

#PASSWORD CONFIRM
@app.route('/password_confirm/', methods=['GET','POST'])
def password_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(request.form['email']),))
			pdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], pdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['pconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("password_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("password_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("password_confirm.html", error = error)

class PasswordResetForm(Form):
	password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')

# PASSWORD RESET
@app.route('/password_reset/', methods=['GET','POST'])
def password_reset():
	error = ''
	try:
		if session['pconfirm'] == 1:
			form = PasswordResetForm(request.form)
			if request.method == "POST" and form.validate():
				cid = session['clientcid']
				password = sha256_crypt.encrypt((str(form.password.data)))
				c, conn = connection()
				c.execute("UPDATE clients SET password = %s WHERE cid = (%s)", (thwart(password), cid))
				conn.commit()
				flash(u'Password successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['pconfirm'] = 0
				return redirect(url_for('account'))

			return render_template("password_reset.html", form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('homepage'))

	except Exception as e:
		return(str(e))

# EMAIL CONFIRM
@app.route('/email_confirm/', methods=['GET','POST'])
def email_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(request.form['email']),))
			pdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], pdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['econfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("email_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("email_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("email_confirm.html", error = error)

class EmailResetForm(Form):
	email = TextField('Email', [validators.Required(), validators.EqualTo('confirm', message ="Emails must match.")])
	confirm = TextField('Repeat Email')

# EMAIL RESET
@app.route('/email_reset/', methods=['GET','POST'])
def email_reset():
	error = ''
	try:
		if session['econfirm'] == 1:
			form = EmailResetForm(request.form)
			c, conn = connection()
			if request.method == "POST" and form.validate():
				cid = session['clientcid']
				email = form.email.data
				#check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
				# if form input and the session are the same, we dont care, because nothing will change
				if(email != session["email"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(email),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That email already has an account, please try a different email.', 'danger')
						return render_template('email_reset.html', form=form)

				c.execute("UPDATE clients SET email = %s WHERE cid = (%s)", (thwart(email), cid))
				conn.commit()
				flash(u'Email successfully changed!', 'success')
				c.close()
				conn.close()
				session['email'] = email
				#so they cant get back in!
				session['econfirm'] = 0
				return redirect(url_for('account'))

			return render_template("email_reset.html", form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('homepage'))

	except Exception as e:
		return(str(e))

# PHONE CONFIRM
@app.route('/phone_confirm/', methods=['GET','POST'])
def phone_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(request.form['email']),))
			pdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], pdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['phconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("phone_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("phone_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("phone_confirm.html", error = error)

class PhoneResetForm(Form):
	phone = TextField('Phone', [validators.Required(), validators.EqualTo('confirm', message ="Phone numbers must match.")])
	confirm = TextField('Repeat Phone')

# PHONE RESET
@app.route('/phone_reset/', methods=['GET','POST'])
def phone_reset():
	error = ''
	try:
		if session['phconfirm'] == 1:
			form = PhoneResetForm(request.form)
			if request.method == "POST" and form.validate():
				c, conn = connection()
				cid = session['clientcid']
				phone = form.phone.data
				#check if phone number exists first
				if(phone != session["phone"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM clients WHERE phone = (%s)", (thwart(phone),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That phone already has an account, please try a different phone.', 'danger')
						return render_template('phone_reset.html', form=form)
				
				c.execute("UPDATE clients SET phone = %s WHERE cid = (%s)", (thwart(phone), cid))
				conn.commit()
				flash(u'Phone number successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['phconfirm'] = 0
				return redirect(url_for('account'))

			return render_template("phone_reset.html", form=form)
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

# @app.route('/profile_picture_upload/', methods=['GET','POST'])
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

# 	return render_template('profile_picture_upload.html', form=form, file_url=file_url)

# #### END PROFILE PIC UPLOAD ####

# TECH ACCOUNT
class TechEditAccountForm(Form):
	techfirst_name = TextField('First Name', [validators.Length(min=1, max=50)])
	techlast_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	# techemail = TextField('Email Address', [validators.Length(min=6, max=50)])
	# techphone = TextField('Phone Number', [validators.Length(min=10, max=20)])
	techaddress = TextField('Street Address', [validators.Length(min=6, max=100)])
	techcity = TextField('City', [validators.Length(min=2, max=50)])
	techstate = TextField('State', [validators.Length(min=2, max=50)])
	techzip = TextField('ZIP', [validators.Length(min=2, max=16)])
	techbirth_month = TextField('Birthday', [validators.Length(min=2, max=16)])
	techbirth_day = TextField('&nbsp;', [validators.Length(min=1, max=2)])
	techbirth_year = TextField('&nbsp;', [validators.Length(min=4, max=4)])
	techbio = TextAreaField('Personal Description', [validators.Length(min=1, max=2000)], widget=TextArea())
	# password = PasswordField('Password', [validators.Required(), validators.EqualTo('techconfirm', message ="Passwords must match.")])

@app.route('/techaccount/', methods=['GET','POST'])
def techaccount():
	error = ''
	# Using this global variable is tough because each time I redirect, even to the same page, it forgets the value. Make it a session varaible maybe?
	try:
		# Declare form early on, so the form is referenced before assignment
		form = TechEditAccountForm(request.form)
		if session['logged_in'] == 'tech':
			#grab all the clients info
			c, conn = connection()
			techemail = session['techemail']
			c.execute("SELECT tid FROM technicians WHERE email = (%s)", (techemail,))
			techtid = c.fetchone()[0]
			c.execute("SELECT phone FROM technicians WHERE email = (%s)", (techemail,))
			techphone = c.fetchone()[0]
			c.execute("SELECT rating FROM technicians WHERE email = (%s)", (techemail,))
			techrating = c.fetchone()[0]
			c.execute("SELECT first_name FROM tpersonals WHERE tid = (%s)", (techtid,))
			techfirst_name = c.fetchone()[0]
			c.execute("SELECT last_name FROM tpersonals WHERE tid = (%s)", (techtid,))
			techlast_name = c.fetchone()[0]
			c.execute("SELECT address FROM tpersonals WHERE tid = (%s)", (techtid,))
			techaddress = c.fetchone()[0]
			c.execute("SELECT city FROM tpersonals WHERE tid = (%s)", (techtid,))
			techcity = c.fetchone()[0]
			c.execute("SELECT state FROM tpersonals WHERE tid = (%s)", (techtid,))
			techstate = c.fetchone()[0]
			c.execute("SELECT zip FROM tpersonals WHERE tid = (%s)", (techtid,))
			techzip = c.fetchone()[0]
			c.execute("SELECT birth_month FROM tpersonals WHERE tid = (%s)", (techtid,))
			techbirth_month = c.fetchone()[0]
			c.execute("SELECT birth_day FROM tpersonals WHERE tid = (%s)", (techtid,))
			techbirth_day = c.fetchone()[0]
			c.execute("SELECT birth_year FROM tpersonals WHERE tid = (%s)", (techtid,))
			techbirth_year = c.fetchone()[0]
			c.execute("SELECT bio FROM tpersonals WHERE tid = (%s)", (techtid,))
			techbio = c.fetchone()[0]
			c.execute("SELECT reg_date FROM tpersonals WHERE tid = (%s)", (techtid,))
			techreg_date = c.fetchone()[0]
			# For now, just putting the prof_pic url into the BLOB
			c.execute("SELECT prof_pic FROM tpersonals WHERE tid = (%s)", (techtid,))
			techprof_pic = c.fetchone()[0]
			conn.commit()
			c.close()
			conn.close()
			session['techtid'] = techtid
			session['techphone'] = techphone
			session['techrating'] = techrating
			session['techfirst_name'] = techfirst_name
			session['techlast_name'] = techlast_name
			session['techaddress'] = techaddress
			session['techcity'] = techcity
			session['techstate'] = techstate
			session['techzip'] = techzip
			session['techbirth_month'] = techbirth_month
			session['techbirth_day'] = techbirth_day
			session['techbirth_year'] = techbirth_year
			session['techbio'] = techbio
			session['techreg_date'] = techreg_date
			session['techprof_pic'] = techprof_pic
			session['tpconfirm'] = 0
			session['tphconfirm'] = 0
			session['teconfirm'] = 0
			#//END grab all the clients info
			c, conn = connection()
			
			#Get value before placing into textarea-box... 
			#had to do this method because value=session.bio wasnt working in jinja
			form.techbio.data = session['techbio']
			if request.method == 'POST' and form.validate():
				techfirst_name = form.techfirst_name.data
				techlast_name = form.techlast_name.data
				# techemail = form.techemail.data
				# techphone = form.techphone.data
				techaddress = form.techaddress.data
				techcity = form.techcity.data
				techstate = form.techstate.data
				techzip = form.techzip.data
				techbirth_month = form.techbirth_month.data
				techbirth_day = form.techbirth_day.data
				techbirth_year = form.techbirth_year.data
				techbio = request.form['techbio']
				techtid = session['techtid']

				# c.execute("UPDATE technicians SET email = %s, phone = %s WHERE tid = (%s)", (techemail, techphone, techtid))
				c.execute("UPDATE tpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE tid = (%s)", (thwart(techfirst_name), thwart(techlast_name), thwart(techaddress), thwart(techcity), thwart(techstate), thwart(techzip), techbirth_month, techbirth_day, techbirth_year, techbio, techtid))
				conn.commit()
				c.close()
				conn.close()
				session['techfirst_name'] = techfirst_name
				session['techlast_name'] = techlast_name
				# session['techemail'] = techemail
				# session['techphone'] = techphone
				session['techaddress'] = techaddress
				session['techcity'] = techcity
				session['techstate'] = techstate
				session['techzip'] = techzip
				session['techbirth_month'] = techbirth_month
				session['techbirth_day'] = techbirth_day
				session['techbirth_year'] = techbirth_year
				session['techbio'] = techbio
				flash(u'Your account is successfully updated.', 'success')
				return redirect(url_for('techaccount'))

		else:
			flash(u'Try logging out and back in again!', 'secondary')
			return redirect(url_for('homepage'))

		return render_template("techaccount.html", form=form, error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@app.route('/tech_duties/', methods=['GET','POST'])
def tech_duties():
	return render_template("tech_duties.html")

class TechSignatureForm(Form):
	signature = TextField('Signature (Please enter your full name)', [validators.Length(min=2, max=100)])

@app.route('/tech_signature/', methods=['GET','POST'])
def tech_signature():
	form = TechSignatureForm(request.form)
	if request.method == "POST" and form.validate():
		signature = form.signature.data
		techtid = session['techtid']
		c, conn = connection()
		c.execute("UPDATE tpersonals SET signature = %s WHERE tid = (%s)", (thwart(signature), techtid))
		conn.commit()
		c.close()
		conn.close()
		flash(u'Submission successful. We will contact you soon.', 'success')
		return redirect(url_for('techaccount'))

	else:
		error = "Please enter your name!"
		return render_template("tech_signature.html", form=form)

#PASSWORD CONFIRM
@app.route('/techpassword_confirm/', methods=['GET','POST'])
def techpassword_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['techemail']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['techpassword'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['tpconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("techpassword_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("techpassword_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("techpassword_confirm.html", error = error)

class TechPasswordResetForm(Form):
	techpassword = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')

# PASSWORD RESET
@app.route('/techpassword_reset/', methods=['GET','POST'])
def techpassword_reset():
	error = ''
	try:
		if session['tpconfirm'] == 1:
			form = TechPasswordResetForm(request.form)
			if request.method == "POST" and form.validate():
				tid = session['techtid']
				techpassword = sha256_crypt.encrypt((str(form.techpassword.data)))
				c, conn = connection()
				c.execute("UPDATE technicians SET password = %s WHERE tid = (%s)", (thwart(techpassword), tid))
				conn.commit()
				flash(u'Password successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['tpconfirm'] = 0
				return redirect(url_for('techaccount'))

			return render_template("techpassword_reset.html", form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('homepage'))

	except Exception as e:
		return(str(e))

# EMAIL CONFIRM
@app.route('/techemail_confirm/', methods=['GET','POST'])
def techemail_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['techemail']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['techpassword'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['teconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("techemail_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("techemail_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("techemail_confirm.html", error = error)

class TechEmailResetForm(Form):
	techemail = TextField('Email', [validators.Required(), validators.EqualTo('confirm', message ="Emails must match.")])
	confirm = TextField('Repeat Email')

# EMAIL RESET
@app.route('/techemail_reset/', methods=['GET','POST'])
def techemail_reset():
	error = ''
	try:
		if session['teconfirm'] == 1:
			form = TechEmailResetForm(request.form)
			c, conn = connection()
			if request.method == "POST" and form.validate():
				tid = session['techtid']
				techemail = form.techemail.data
				#check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
				# if form input and the session are the same, we dont care, because nothing will change
				if(techemail != session["techemail"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(techemail),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That email already has an account, please try a different email.', 'danger')
						return render_template('techemail_reset.html', form=form)

				c.execute("UPDATE technicians SET email = %s WHERE tid = (%s)", (thwart(techemail), tid))
				conn.commit()
				flash(u'Email successfully changed!', 'success')
				c.close()
				conn.close()
				session['techemail'] = techemail
				#so they cant get back in!
				session['teconfirm'] = 0
				return redirect(url_for('techaccount'))

			return render_template("techemail_reset.html", form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('homepage'))

	except Exception as e:
		return(str(e))

# PHONE CONFIRM
@app.route('/techphone_confirm/', methods=['GET','POST'])
def techphone_confirm():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['techemail']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['techpassword'], tpdata):
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['tphconfirm'] = 1
				flash(u'Successfully authorized.', 'success')
				return redirect(url_for("techphone_reset"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("techphone_confirm.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("techphone_confirm.html", error = error)

class TechPhoneResetForm(Form):
	techphone = TextField('Phone', [validators.Required(), validators.EqualTo('confirm', message ="Phone numbers must match.")])
	confirm = TextField('Repeat Phone')

# PHONE RESET
@app.route('/techphone_reset/', methods=['GET','POST'])
def techphone_reset():
	error = ''
	try:
		if session['tphconfirm'] == 1:
			form = TechPhoneResetForm(request.form)
			if request.method == "POST" and form.validate():
				#check if phone number exists first
				tid = session['techtid']
				techphone = form.techphone.data
				c, conn = connection()
				if(techphone != session["techphone"]):
					# too many perethesis, but something is wrong with the the syntax of the intx for statement
					x = c.execute("SELECT * FROM technicians WHERE phone = (%s)", (thwart(techphone),))
					conn.commit()
					if int(x) > 0:
						#redirect them if they need to recover an old email from and old account
						flash(u'That phone already has an account, please try a different phone.', 'danger')
						return render_template('techphone_reset.html', form=form)

				c.execute("UPDATE technicians SET phone = %s WHERE tid = (%s)", (thwart(techphone), tid))
				conn.commit()
				flash(u'Phone number successfully changed!', 'success')
				c.close()
				conn.close()
				#so they cant get back in!
				session['tphconfirm'] = 0
				return redirect(url_for('techaccount'))

			return render_template("techphone_reset.html", form=form)
		else:
			flash(u'Not allowed there!', 'danger')
			return redirect(url_for('homepage'))

	except Exception as e:
		return(str(e))



# #### PROFILE PIC UPLOAD ####
# # Based after https://gist.github.com/greyli/81d7e5ae6c9baf7f6cdfbf64e8a7c037
# # For uploading files
# TECH_PROF_PIC_UPLOAD_FOLDER = 'static/tech_user_info/prof_pic'
# ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
# app.config['TECH_UPLOADED_PHOTOS_DEST'] = os.getcwd()
# photos = UploadSet('photos', IMAGES)
# configure_uploads(app, photos)
# patch_request_class(app)  # set maximum file size, default is 16MB

# class TechProfilePictureForm(FlaskForm):
# 	techprof_pic = FileField(validators=[FileAllowed(photos, u'Image only!')])

# @app.route('/tech_profile_picture_upload/', methods=['GET','POST'])
# def tech_profile_picture_upload():
# 	form = TechProfilePictureForm()
# 	techtid = str(session['techtid'])
# 	techfirst_name = session['techfirst_name']
# 	default_prof_pic = url_for('static', filename='user_info/prof_pic/default.jpg')
# 	user_prof_pic = techtid+'_'+techfirst_name+'_'+'.png'
# 	if form.validate_on_submit():
# 		filename = photos.save(form.techprof_pic.data, folder=TECH_PROF_PIC_UPLOAD_FOLDER,name=techtid+'_'+techfirst_name+'_'+'.png')
# 		file_url = photos.url(filename)
# 		# Checks if the prof_pic is set yet. if set, then dont need to delete the old picture on the server
# 		# if session['techprof_pic'] != 'http://138.68.238.112/var/www/FlaskApp/FlaskApp/_uploads/photos/static/tech_user_info/prof_pic/default.jpg':
# 		# 	#need to delete or move the old prof_pic if it was set! Prevents users from adding too many pictures
#flash(u'Submission successful. We will contact you soon.', 'success')
# 		# 	flash("You already have a file on the server!")
# 		#If the user_prof_pic is there, then  
# 		session['techprof_pic'] = file_url
# 		c, conn = connection()
# 		c.execute("UPDATE tpersonals SET prof_pic = %s WHERE tid = (%s)", (file_url, techtid))
# 		conn.commit()
# 		c.close()
# 		conn.close()
# 	else:
# 		file_url = None

# 	return render_template('tech_profile_picture_upload.html', form=form, file_url=file_url)

def login_required(f):
	#not 100% how this works
	# techlogged_in doesnt look like its user anywhere, be sure of these and delete if not anywhere else
	@wraps(f)
	def wrap(*args, **kwargs):
		if ('logged_in' or 'techlogged_in') in session:
			#arguments and key word arguments
			return f(*args, **kwargs)
		else:
			flash(u'You need to login first.', 'danger')
			return redirect(url_for('login'))
	return wrap

@app.route('/logout/', methods=['GET','POST'])
@login_required
def logout():
	session.clear()
	flash(u'You have been logged out!', 'danger')
	return redirect(url_for('homepage'))

	
#CLIENT LOGIN
@app.route('/login/', methods=['GET','POST'])
def login():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(request.form['email']),))
			pdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['password'], pdata):
				email = request.form['email']
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['logged_in'] = 'client'
				session['email'] = thwart(email)
				flash(u'You are now logged in.', 'success')
				return redirect(url_for("account"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("login.html", error = error)
		
	except Exception as e:
		error = "Invalid credentials, try again."
		return render_template("login.html", error = error)

#TECH LOGIN
@app.route('/techlogin/', methods=['GET','POST'])
def tech_login():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(request.form['techemail']),))
			tpdata = c.fetchone()[3]
				
			if sha256_crypt.verify(request.form['techpassword'], tpdata):
				techemail = request.form['techemail']
				#putting these close and commit 
				#functions outside the 'if' will break code
				conn.commit()
				c.close()
				conn.close()
				session['logged_in'] = 'tech'
				session['techemail'] = thwart(techemail)
				flash(u'You are now logged in.', 'success')
				return redirect(url_for("techaccount"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("techlogin.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("techlogin.html", error = error)

@app.route('/forgot_password/<token>')
def forgot_password(token):
	try:
		email = s.loads(token, salt='email-confirm', max_age=3600)
		form = PasswordResetForm(request.form)
		if request.method == "POST" and form.validate():
			password = sha256_crypt.encrypt((str(form.password.data)))
			c, conn = connection()
			c.execute("UPDATE clients SET password = %s WHERE cid = (%s)", (thwart(password), cid))
			conn.commit()
			flash(u'Password successfully changed!', 'success')
			c.close()
			conn.close()
			#make sure token cant be used twice
			return redirect(url_for('account'))

		return render_template("forgot_password.html", form=form)
			
	except SignatureExpired:
		flash(u'The token has expired', 'danger')
		return redirect(url_for('homepage'))

@app.route('/fforgot_password/')
def fforgot_password():
	try:
		# Send confirmation email
		f_email = request.form['f_email']
		token = s.dumps(email, salt='forgot-password')
		msg = Message("Minute.tech - Forgot Password", sender = "admin@minute.tech", recipients=[f_email])
		link = url_for('forgot_password', token=token, _external=True)
		msg.body = render_template('forgot_password-email.txt', link=link, first_name=first_name)
		msg.html = render_template('forgot_password-email.html', link=link, first_name=first_name)
		mail.send(msg)
		flash(u'Password reset link sent to email', 'success')
		return redirect(url_for('homepage'))
	
	except Exception as e:
		return(str(e))

#CLIENT REGISTER
class RegistrationForm(Form):
	first_name = TextField('First Name', [validators.Length(min=1, max=50)])
	last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	email = TextField('Email Address', [validators.Length(min=6, max=50)])
	phone = TextField('Phone Number', [validators.Length(min=10, max=20)])
	czip = TextField('ZIP', [validators.Length(min=2, max=16)])
	password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')
	recaptcha = RecaptchaField()

@app.route('/register/', methods=['GET','POST'])
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

			#check if already exists
			x = c.execute("SELECT * FROM clients WHERE email = (%s)", (thwart(email),))
			y = c.execute("SELECT * FROM clients WHERE phone = (%s)", (thwart(phone),))

			if int(x) > 0:
				flash(u'That email already has an account, please try a new email or send an email to help@minute.tech', 'danger')
				return render_template('register.html', form=form)
			elif int(y) > 0:
				flash(u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
				return render_template('register.html', form=form)
			else:
				#make sure this default pic is in the correct folder!!
				default_prof_pic = url_for('static', filename='user_info/prof_pic/default.jpg')
				c.execute("INSERT INTO clients (email, phone, password) VALUES (%s, %s, %s)", (thwart(email), thwart(phone), thwart(password)))
				c.execute("INSERT INTO cpersonals (first_name, last_name, address, city, state, zip, bio, prof_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (thwart(first_name), thwart(last_name), address, city, state, thwart(czip), bio, default_prof_pic))
				conn.commit()
				flash(u'Thanks for registering!', 'success')
				c.close()
				conn.close()

				session['logged_in'] = 'client'
				#we get the client ID on the first page after it is generated, dont worry
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
				#change this when the server goes live to the proper folder
				session['prof_pic'] = default_prof_pic

				# Send confirmation email
				token = s.dumps(email, salt='email-confirm')
				msg = Message("Minute.tech - Email Verification", sender = "admin@minute.tech", recipients=[email])
				link = url_for('email_verify', token=token, _external=True)
				msg.body = render_template('email_verify.txt', link=link, first_name=first_name)
				msg.html = render_template('email_verify.html', link=link, first_name=first_name)
				mail.send(msg)
				return redirect(url_for('account'))

		return render_template("register.html", form=form)


	except Exception as e:
		return(str(e))

@app.route('/email_verify/<token>')
def email_verify(token):
	try:
		c, conn = connection()
		if 'logged_in' in session:
			email = s.loads(token, salt='email-confirm', max_age=3600)
			if session['logged_in'] == 'client':
				cid = session['clientcid']
				c.execute("UPDATE cpersonals SET email_verify = 1 WHERE cid = (%s)", (cid,))
				conn.commit()
				c.close()
				conn.close()
				flash(u'Email successfully verified!', 'success')
				return redirect(url_for('account'))

			elif session['logged_in'] == 'tech':
				tid = session['techtid']
				c.execute("UPDATE tpersonals SET email_verify = 1 WHERE tid = (%s)", (tid,))
				conn.commit()
				c.close()
				conn.close()
				flash(u'Email successfully verified!', 'success')
				return redirect(url_for('techaccount'))
			
		else:
			flash(u'Log in first, then click the link again', 'danger')
			return redirect(url_for('login'))

		render_template("main.html")
	except SignatureExpired:
		flash(u'The token has expired', 'danger')
		return redirect(url_for('homepage'))

#TECH REGISTER
class TechRegistrationForm(Form):
	techfirst_name = TextField('First Name', [validators.Length(min=1, max=50)])
	techlast_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	techemail = TextField('Email Address', [validators.Length(min=6, max=50)])
	techphone = TextField('Phone Number', [validators.Length(min=10, max=20)])
	techaddress = TextField('Street Address', [validators.Length(min=6, max=100)])
	techcity = TextField('City', [validators.Length(min=2, max=50)])
	techstate = TextField('State', [validators.Length(min=2, max=50)])
	techzip = TextField('ZIP', [validators.Length(min=2, max=16)])
	techpassword = PasswordField('Password', [validators.Required(), validators.EqualTo('techconfirm', message ="Passwords must match.")])
	techconfirm = PasswordField('Repeat Password')
	recaptcha = RecaptchaField()
	
@app.route('/techregister/', methods=['GET','POST'])
def tech_register_page():
	error = ''
	try:
		form = TechRegistrationForm(request.form)
		if request.method == "POST" and form.validate():
			techfirst_name = form.techfirst_name.data
			techlast_name = form.techlast_name.data
			techemail = form.techemail.data
			techphone = form.techphone.data
			techaddress = form.techaddress.data
			techcity = form.techcity.data
			techstate = form.techstate.data
			techzip = form.techzip.data
			techbio = "Not provided"
			techpassword = sha256_crypt.encrypt((str(form.techpassword.data)))
			c, conn = connection()

			#check if already exists
			x = c.execute("SELECT * FROM technicians WHERE email = (%s)", (thwart(techemail),))
			y = c.execute("SELECT * FROM technicians WHERE phone = (%s)", (thwart(techphone),))

			if int(x) > 0:
				flash(u'That email already has an account, please try a new email or send an email to help@minute.tech', 'danger')
				return render_template('techregister.html', form=form)
			elif int(y) > 0:
				flash(u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
				return render_template('techregister.html', form=form)
			else:
				default_prof_pic = url_for('static', filename='tech_user_info/prof_pic/default.jpg')
				c.execute("INSERT INTO technicians (email, phone, password) VALUES (%s, %s, %s)", (thwart(techemail), thwart(techphone), thwart(techpassword)))
				c.execute("INSERT INTO tpersonals (first_name, last_name, address, city, state, zip, bio, prof_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (thwart(techfirst_name), thwart(techlast_name), thwart(techaddress), thwart(techcity), techstate, thwart(techzip), techbio, default_prof_pic))
				conn.commit()
				flash(u'Thanks for registering!', 'success')
				c.close()
				conn.close()

				session['logged_in'] = 'tech'

				#tid will be inputted once generated
				session['techtid'] = 0
				session['techemail'] = techemail
				session['techphone'] = techphone
				session['techrating'] = 500
				session['techfirst_name'] = techfirst_name
				session['techlast_name'] = techlast_name
				session['techaddress'] = techaddress
				session['techcity'] = techcity
				session['techstate'] = techstate
				session['techzip'] = techzip
				session['techreg_date'] = 0
				session['techbio'] = techbio
				#change this when the server goes live to the proper folder
				session['techprof_pic'] = default_prof_pic
				# Send confirmation email
				token = s.dumps(techemail, salt='email-confirm')
				msg = Message("Minute.tech - Email Verification", sender = "admin@minute.tech", recipients=[techemail])
				link = url_for('email_verify', token=token, _external=True)
				msg.body = render_template('email_verify.txt', link=link, first_name=techfirst_name)
				msg.html = render_template('email_verify.html', link=link, first_name=techfirst_name)
				mail.send(msg)
				return redirect(url_for('techaccount'))

		return render_template("techregister.html", form=form)


	except Exception as e:
		return(str(e))


## Sending Files ##

@app.route('/MinutetechLLC_tos/')
def return_tos():
	return send_file('static/legal/MinutetechLLC_tos.pdf', attachment_filename='MinutetechLLC_tos.pdf')

@app.route('/Minutetech_Logo/')
def return_logo():
	return send_file('static/images/Icon_1000x1000px.png', attachment_filename='Icon_1000x1000px.png')

@app.route('/coffee-lady/')
def return_pic1():
	return send_file('static/images/lady-logo-email-banner.png', attachment_filename='lady-logo-email-banner.png')

@app.route('/Minutetech_Long_Logo/')
def return_logo_long():
	return send_file('static/images/Secondary_long.png')

@app.route('/Minutetech_rocket_ship/')
def return_tocket_ship():
	return send_file('static/flat-icons/008-startup.png')

# # Univers Black
# @app.route('/Minutetech_font_black/')
# def return_font_black():
# 	return send_file('static/media/fonts/Univers/Univers-Black.otf')
# # Univers Light Condensed
# @app.route('/Minutetech_font_light/')
# def return_font_light():
# 	return send_file('static/media/fonts/Univers/Univers-CondensedLight.otf')

@app.route('/file_downloads/')
def file_downloads():
    return render_template('downloads.html')
############################################ END ACCOUNT SYSTEM #########################################################

if __name__ == "__main__":
	app.run(debug=True)