from wtforms import Form, BooleanField, TextField, PasswordField, SelectField, RadioField, TextAreaField, DateField, DateTimeField, StringField, validators
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename # For secure file uploads
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class

class ContactForm(Form):
	message = TextAreaField('Message', [validators.Length(min=10, max=2000)])
	email = TextField('Email', [validators.Optional()])

class RegistrationForm(Form):
	first_name = TextField('First Name', [validators.Length(min=1, max=50)])
	last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	email = TextField('Email Address', [validators.Length(min=6, max=50)])
	phone = TextField('Phone Number', [validators.Length(min=10, max=20)])
	czip = TextField('ZIP', [validators.Length(min=2, max=16)])
	password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')
	recaptcha = RecaptchaField()

class AskForm(Form):
	body = TextAreaField('Desciption', [validators.Length(min=10, max=2000)])

class EditAccountForm(Form):
	first_name = TextField('First Name', [validators.Length(min=1, max=50)])
	last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	address = TextField('Street Address', [validators.Length(min=6, max=100)])
	city = TextField('City', [validators.Length(min=2, max=50)])
	state = TextField('State', [validators.Length(min=2, max=50)])
	czip = TextField('ZIP', [validators.Length(min=2, max=16)])
	birth_month = TextField('Birthday', [validators.Length(min=2, max=16)])
	birth_day = TextField('&nbsp;', [validators.Length(min=1, max=2)])
	birth_year = TextField('&nbsp;', [validators.Length(min=4, max=4)])
	bio = TextAreaField('Personal Description', [validators.Length(min=1, max=2000)], widget=TextArea())

class PasswordResetForm(Form):
	password = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')


class EmailResetForm(Form):
	email = TextField('Email', [validators.Required(), validators.EqualTo('confirm', message ="Emails must match.")])
	confirm = TextField('Repeat Email')

class PhoneResetForm(Form):
	phone = TextField('Phone', [validators.Required(), validators.EqualTo('confirm', message ="Phone numbers must match.")])
	confirm = TextField('Repeat Phone')

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

class TechEditAccountForm(Form):
	techfirst_name = TextField('First Name', [validators.Length(min=1, max=50)])
	techlast_name = TextField('Last Name', [validators.Length(min=1, max=50)])
	techaddress = TextField('Street Address', [validators.Length(min=6, max=100)])
	techcity = TextField('City', [validators.Length(min=2, max=50)])
	techstate = TextField('State', [validators.Length(min=2, max=50)])
	techzip = TextField('ZIP', [validators.Length(min=2, max=16)])
	techbirth_month = TextField('Birthday', [validators.Length(min=2, max=16)])
	techbirth_day = TextField('&nbsp;', [validators.Length(min=1, max=2)])
	techbirth_year = TextField('&nbsp;', [validators.Length(min=4, max=4)])
	techbio = TextAreaField('Personal Description', [validators.Length(min=1, max=2000)], widget=TextArea())

class TechPhoneResetForm(Form):
	techphone = TextField('Phone', [validators.Required(), validators.EqualTo('confirm', message ="Phone numbers must match.")])
	confirm = TextField('Repeat Phone')

class TechPasswordResetForm(Form):
	techpassword = PasswordField('Password', [validators.Required(), validators.EqualTo('confirm', message ="Passwords must match.")])
	confirm = PasswordField('Repeat Password')

class TechEmailResetForm(Form):
	techemail = TextField('Email', [validators.Required(), validators.EqualTo('confirm', message ="Emails must match.")])
	confirm = TextField('Repeat Email')

class TechSignatureForm(Form):
	signature = TextField('Signature (Please enter your full name)', [validators.Length(min=2, max=100)])