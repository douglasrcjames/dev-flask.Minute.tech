import os, sys, os.path
from flask import Flask, render_template, flash, request, url_for, redirect, session, send_file, send_from_directory, Blueprint
from wtforms import Form, BooleanField, TextField, PasswordField, SelectField, RadioField, TextAreaField, DateField, DateTimeField, StringField, validators
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename # For secure file uploads
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from passlib.hash import sha256_crypt # To encrypt the password
from MySQLdb import escape_string as thwart # To prevent SQL injection
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired # Email confirmation link that has a short lifespan
from functools import wraps # For login_required
# Custom f(x)

# Might be able to delete some of these from _ imports, test later for dependencies in files/folders.

mod = Blueprint('technician', __name__, template_folder='templates')

##############  1st Layer SECTION  ####################
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
			return redirect(url_for('main.login'))
	return wrap

@mod.route('/logout/', methods=['GET','POST'])
@login_required
def logout():
	session.clear()
	flash(u'You have been logged out!', 'danger')
	return redirect(url_for('main.homepage'))

#TECH LOGIN
@mod.route('/login/', methods=['GET','POST'])
def login():
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
				return redirect(url_for("technician.account"))
			
			else:
				error = "Invalid credentials, try again."

		return render_template("login.html", error = error)
		
	except Exception as e:
		error = e
		return render_template("login.html", error = error)
	
@mod.route('/register/', methods=['GET','POST'])
def register_page():
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
				return render_template('register.html', form=form)
			elif int(y) > 0:
				flash(u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
				return render_template('register.html', form=form)
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
				msg = Message("Minute.tech - Email Verification", sender = "test@minute.tech", recipients=[techemail])
				link = url_for('technician.email_verify', token=token, _external=True)
				msg.body = render_template('email/verify.txt', link=link, first_name=techfirst_name)
				msg.html = render_template('email/verify.html', link=link, first_name=techfirst_name)
				mail.send(msg)
				return redirect(url_for('account'))

		return render_template("techregister.html", form=form)


	except Exception as e:
		return(str(e))

##############  2nd Layer SECTION  ####################
@mod.route('/answer/', methods=['GET','POST'])
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
			return redirect(url_for('technician.answer'))

		return render_template("answer.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@mod.route('/resolved/', methods=['GET','POST'])
def resolved():
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
			return redirect(url_for('technician.resolved'))

		return render_template("resolved.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)


@mod.route('/techroom/?select_q=<select_q>', methods=['GET','POST'])
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
			return redirect(url_for('main.techroom'))

		return render_template("techroom.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)


@mod.route('/techpending/', methods=['GET','POST'])
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
			return redirect(url_for('main.techpending'))

		return render_template("techpending.html", error = error)

	except Exception as e:
		return render_template("500.html", error = e)

@mod.route('/techaccount/', methods=['GET','POST'])
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

@mod.route('/tech_duties/', methods=['GET','POST'])
def tech_duties():
	return render_template("tech_duties.html")

@mod.route('/tech_signature/', methods=['GET','POST'])
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
@mod.route('/techpassword_confirm/', methods=['GET','POST'])
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

# PASSWORD RESET
@mod.route('/techpassword_reset/', methods=['GET','POST'])
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
@mod.route('/techemail_confirm/', methods=['GET','POST'])
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

# EMAIL RESET
@mod.route('/techemail_reset/', methods=['GET','POST'])
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
			return redirect(url_for('main.homepage'))

	except Exception as e:
		return(str(e))

# PHONE CONFIRM
@mod.route('/techphone_confirm/', methods=['GET','POST'])
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


# PHONE RESET
@mod.route('/techphone_reset/', methods=['GET','POST'])
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
			return redirect(url_for('main.homepage'))

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

# @mod.route('/tech_profile_picture_upload/', methods=['GET','POST'])
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
##############  END TECHNICIAN SECTION  ####################