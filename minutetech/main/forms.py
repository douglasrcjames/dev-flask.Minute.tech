import os
from wtforms import (Form, TextField,
                     PasswordField,
                     TextAreaField,
                     validators, ValidationError)
from wtforms.widgets import TextArea
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileAllowed, FileRequired
# from werkzeug.utils import secure_filename  # For secure file uploads
from flask_uploads import (
    UploadSet, IMAGES)  # patch_request_class, configure_uploads

# from minutetech import photos

photos = UploadSet('photos', IMAGES)


class RegistrationForm(Form):
    first_name = TextField('First Name', [validators.Length(min=1, max=50)])
    last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    phone = TextField('Phone Number', [validators.Length(min=10, max=20)])
    czip = TextField('ZIP', [validators.Length(min=2, max=16)])
    password = PasswordField('Password', [validators.Required(
    ), validators.EqualTo('confirm', message="Passwords must match.")])
    confirm = PasswordField('Repeat Password')


class AskForm(Form):
    body = TextAreaField('Desciption', [validators.Length(min=10, max=2000)])


class EditAccountForm(Form):
    prof_pic = FileField(
        validators=[
            FileAllowed(
                ['jpg', 'png'],
                u'Only {} extensions allowed.'.format(', '.join(IMAGES)))
        ])
    first_name = TextField('First Name', [validators.Length(min=1, max=50)])
    last_name = TextField('Last Name', [validators.Length(min=1, max=50)])
    address = TextField('Street Address', [validators.Length(min=6, max=100)])
    city = TextField('City', [validators.Length(min=2, max=50)])
    state = TextField('State', [validators.Length(min=2, max=50)])
    czip = TextField('ZIP', [validators.Length(min=2, max=16)])
    birth_month = TextField('Birthday', [validators.Length(min=2, max=16)])
    birth_day = TextField('&nbsp;', [validators.Length(min=1, max=2)])
    birth_year = TextField('&nbsp;', [validators.Length(min=4, max=4)])
    bio = TextAreaField('Personal Description', [
                        validators.Length(min=1, max=2000)], widget=TextArea())


class PasswordResetForm(Form):
    password = PasswordField('Password', [validators.Required(
    ), validators.EqualTo('confirm', message="Passwords must match.")])
    confirm = PasswordField('Repeat Password')


class EmailResetForm(Form):
    email = TextField('Email', [validators.Required(), validators.EqualTo(
        'confirm', message="Emails must match.")])
    confirm = TextField('Repeat Email')


class PhoneResetForm(Form):
    phone = TextField('Phone', [validators.Required(), validators.EqualTo(
        'confirm', message="Phone numbers must match.")])
    confirm = TextField('Repeat Phone')


class ContactForm(Form):
    message = TextAreaField('Message', [validators.Length(min=10, max=2000)])
    email = TextField('Email', [validators.Optional()])
