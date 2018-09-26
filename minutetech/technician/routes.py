import os
from uuid import uuid4
from flask import (render_template, flash, request,
                   url_for, redirect, session,
                   send_file,
                   Blueprint)
from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt  # To encrypt the password
from sqlalchemy import or_, and_
from sqlalchemy import desc
from flask_mail import Message
# Email confirmation link that has a short lifespan
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from forms import (TechRegistrationForm, TechEditAccountForm,
                   TechPasswordResetForm,
                   TechEmailResetForm, TechPhoneResetForm, TechSignatureForm)
from .models import Technician
from minutetech.config import SECRET_KEY, UPLOAD_FOLDER
from minutetech import mail, db
from minutetech.utils import allowed_file, login_required
from minutetech.main.models import Ticket

technician = Blueprint('technician', __name__, template_folder='templates')
s = URLSafeTimedSerializer(SECRET_KEY)  # For token
count = 1


@technician.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    session.clear()
    flash(u'You have been logged out!', 'danger')
    return redirect(url_for('main.homepage'))


@technician.route('/login/', methods=['GET', 'POST'])
def login():
    global count
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            technician = Technician.query.filter_by(email=email).first()
            if technician:
                pdata = technician.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    session['logged_in'] = 'tech'
                    session['tid'] = technician.id
                    session['email'] = technician.email
                    session['first_name'] = technician.first_name
                    session['rating'] = technician.rating
                    flash(u'You are now logged in.', 'success')
                    return redirect(url_for('technician.account'))
                else:
                    error = "Invalid credentials, try again."
            else:
                error = "Invalid authentication, try again. Tries: {}".format(
                    count)
            count += 1

        return render_template('technician/login.html', error=error)

    except Exception as e:
        error = e
        return render_template('technician/login.html', error=error)


@technician.route('/register/', methods=['GET', 'POST'])
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

            technician = Technician.query.filter(or_(Technician.email == email,
                                                     Technician.phone == phone)).first()

            if technician:
                if technician.email == email:
                    flash(
                        u'That email already has an account, please try a new email or send an email to help@minute.tech', 'danger')
                    return render_template('technician/register.html', form=form)
                if technician.phone == phone:
                    flash(
                        u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
                    return render_template('technician/register.html', form=form)
            else:
                technician = Technician(
                    email=email, phone=phone, password=password, first_name=first_name, last_name=last_name, address=address, city=city, state=state, zip_code=tzip, bio=bio)
                db.session.add(technician)
                db.session.commit()

                flash(u'Thanks for registering!', 'success')

                session['logged_in'] = 'tech'
                # tid will be inputted once generated
                session['tid'] = technician.id
                session['first_name'] = technician.first_name
                session['email'] = technician.email
                session['phone'] = technician.phone
                session['rating'] = technician.rating
                # Send confirmation email
                token = s.dumps(email, salt='email-verify')
                msg = Message("Minute.tech - Email Verification",
                              sender="test@minute.tech", recipients=[email])
                link = url_for('technician.email_verify',
                               token=token, _external=True)
                msg.body = render_template(
                    'technician/email/email_verify.txt', link=link, first_name=first_name)
                msg.html = render_template(
                    'technician/email/email_verify.html', link=link, first_name=first_name)
                mail.send(msg)
                return redirect(url_for('technician.account'))

        return render_template('technician/register.html', form=form)

    except Exception as e:
        return "Error: {}".format(e)


@technician.route('/email_verify/<token>')
def email_verify(token):
    try:
        if 'logged_in' in session:
            email = s.loads(token, salt='email-verify', max_age=3600)

            if session['logged_in'] == 'tech':
                tid = session['tid']
                technician = Technician.query.filter_by(id=tid).first_or_404()
                technician.email_verify = 1
                db.session.commit()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('technician.account'))

            elif session['logged_in'] == 'client':
                flash(
                    u'Log in as a technician first, then click the link again', 'danger')
                return redirect(url_for('technician.login'))

        else:
            flash(u'Log in as a technician first, then click the link again', 'danger')
            return redirect(url_for('technician.login'))

        return render_template("main.html")
    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))

##############  2nd Layer SECTION  ####################


# @technician.route('/account/answer/', methods=['GET', 'POST'])
# def answer():
#     error = ''
#     try:
#         c, conn = connection()
#         if request.method == "POST":
#             tid = session['tid']
#             c.execute(
#                 "UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
#             conn.commit()
#             c.close()
#             conn.close()
#             flash(u'Thanks, we got you down!', 'success')
#             return redirect(url_for('technician.answer'))

#         return render_template('technician/account/answer.html', error=error)

#     except Exception as e:
#         return render_template('500.html', error=e)

@technician.route('/account/answer/', methods=['GET', 'POST'])
def answer():
    try:
        if session['logged_in']:
            result = Ticket.query.filter_by(
                solved=0, pending=0).order_by(desc(Ticket.created_at))
            return render_template("technician/account/answer.html",
                                   result=result)
        else:
            return render_template("404.html")
    except Exception as e:
        return(str(e))


# @technician.route('/account/resolved/', methods=['GET', 'POST'])
# def resolved():
#     error = ''
#     try:
#         c, conn = connection()
#         if request.method == "POST":
#             tid = session['tid']
#             c.execute(
#                 "UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
#             conn.commit()
#             c.close()
#             conn.close()
#             flash(u'Thanks, we got you down!', 'success')
#             return redirect(url_for('technician.resolved'))

# return render_template('technician/account/resolved.html', error=error)

#     except Exception as e:
#         return render_template('500.html', error=e)

@technician.route('/account/resolved/', methods=['GET', 'POST'])
def resolved():
    try:
        if session['logged_in']:
            tech_id = session['tid']
            result = Ticket.query.filter(
                and_(Ticket.technician_id == tech_id,
                     Ticket.solved == 1)).order_by(desc(Ticket.created_at))
            return render_template("technician/account/resolved.html",
                                   result=result)
        else:
            return render_template("404.html")
    except Exception as e:
        return(str(e))


# @technician.route('/account/pending/', methods=['GET', 'POST'])
# def pending():
#     error = ''
#     try:
#         c, conn = connection()
#         if request.method == "POST":
#             tid = session['tid']
#             c.execute(
#                 "UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
#             conn.commit()
#             c.close()
#             conn.close()
#             flash(u'Thanks, we got you down!', 'success')
#             return redirect(url_for('technician.pending'))

# return render_template('technician/account/pending.html', error=error)

#     except Exception as e:
#         return render_template('500.html', error=e)

@technician.route('/account/pending/', methods=['GET', 'POST'])
def pending():
    try:
        if session['logged_in']:
            tech_id = session['tid']
            result = Ticket.query.filter(
                and_(Ticket.technician_id == tech_id,
                     Ticket.solved == 0)).order_by(desc(Ticket.created_at))
            return render_template("technician/account/pending.html",
                                   result=result)
        else:
            return render_template("404.html")
    except Exception as e:
        return(str(e))


@technician.route('/account/room/?select_q=<select_q>', methods=['GET', 'POST'])
def room(select_q):
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            tid = session['tid']
            c.execute(
                "UPDATE tpersonals SET launch_email = 1 WHERE tid = (%s)", (tid,))
            conn.commit()
            c.close()
            conn.close()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.homepage'))

        return render_template('technician/account/room.html', error=error)

    except Exception as e:
        return render_template('500.html', error=e)


@technician.route('/account/', methods=['GET', 'POST'])
def account():
    error = ''
    try:
        # Declare form early on, so the form is referenced before assignment
        form = TechEditAccountForm(request.form)
        if session['logged_in'] == 'tech':
            # grab all the clients info
            email = session['email']
            technician = Technician.query.filter_by(email=email).first_or_404()

            # Get value before placing into textarea-box...
            # had to do this method because value=session.bio wasnt working in
            # jinja
            form.bio.data = technician.bio
            if request.files:
                formdata = request.form.copy()
                formdata.update(request.files)
                form = TechEditAccountForm(formdata)

            if request.method == 'POST' and form.validate():
                if 'prof_pic' in request.files:
                    new_prof_pic = request.files['prof_pic']
                    if allowed_file(new_prof_pic.filename):
                        filename = secure_filename(new_prof_pic.filename)
                        old_prof_pic = os.path.join(
                            UPLOAD_FOLDER,
                            os.path.basename(technician.prof_pic))
                        if os.path.exists(old_prof_pic):
                            os.unlink(old_prof_pic)
                        new_prof_pic.save(os.path.join(
                            UPLOAD_FOLDER, filename))
                        prof_pic = 'user_info/' + filename
                        technician.prof_pic = prof_pic
                technician.first_name = form.first_name.data
                technician.last_name = form.last_name.data
                technician.address = form.address.data
                technician.city = form.city.data
                technician.state = form.state.data
                technician.zip_code = form.czip.data
                technician.birth_year = form.birth_year.data
                technician.birth_day = form.birth_day.data
                technician.birth_month = form.birth_month.data
                technician.bio = form.bio.data
                db.session.commit()
                flash(u'Your account is successfully updated.', 'success')
            # return redirect(url_for('technician.account'))
            return render_template('technician/account/index.html',
                                   form=form, technician=technician,
                                   error=error)
        else:
            flash(u'Try logging out and back in again!', 'secondary')
            return redirect(url_for('main.homepage'))
    except Exception as e:
        return render_template('500.html', error=e)


@technician.route('/account/duties/', methods=['GET', 'POST'])
def duties():
    return render_template('technician/account/duties.html')


@technician.route('/account/signature/', methods=['GET', 'POST'])
def signature():
    form = TechSignatureForm(request.form)
    if request.method == "POST" and form.validate():
        signature = form.signature.data
        tid = session['tid']
        technician = Technician.query.filter_by(id=tid).first_or_404()
        technician.signature = signature
        technician.certified = 1
        db.session.commit()
        c, conn = connection()
        session['certified'] = 1
        flash(u'Submission successful. We will contact you soon.', 'success')
        return redirect(url_for('technician.account'))
    else:
        flash(u"Please enter your name!", 'danger')
    return render_template('technician/account/signature.html', form=form)


@technician.route('/account/password_confirm/', methods=['GET', 'POST'])
def password_confirm():
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            technician = Technician.query.filter_by(email=email).first_or_404()
            # Prevent login to another account from this stage
            if technician and request.form['email'] == session['email']:
                pdata = technician.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    session['pconfirm'] = 1
                    flash(u'Successfully authorized.', 'success')
                    return redirect(url_for('technician.password_reset'))

                else:
                    error = "Invalid credentials, try again."
            else:
                error = "Invalid authentication, try again."
        return render_template('technician/account/password_confirm.html', error=error)

    except Exception as e:
        error = e
        return render_template('technician/account/password_confirm.html', error=error)


@technician.route('/account/password_reset/', methods=['GET', 'POST'])
def password_reset():
    error = ''
    try:
        if session['pconfirm'] == 1:
            form = TechPasswordResetForm(request.form)
            if request.method == "POST" and form.validate():
                tid = session['tid']
                password = sha256_crypt.encrypt((str(form.password.data)))

                technician = Technician.query.filter_by(id=tid).first_or_404()
                technician.password = password
                db.session.commit()
                flash(u'Password successfully changed!', 'success')
                # so they cant get back in!
                session['pconfirm'] = 0
                return redirect(url_for('technician.account'))

            return render_template('technician/account/password_reset.html', form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))


@technician.route('/account/email_confirm/', methods=['GET', 'POST'])
def email_confirm():
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            technician = Technician.query.filter_by(email=email).first()

            # Prevent login to another account from this stage
            if client and request.form['email'] == session['email']:
                pdata = technician.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    # putting these close and commit
                    # functions outside the 'if' will break code
                    session['econfirm'] = 1
                    flash(u'Successfully authorized.', 'success')
                    return redirect(url_for('technician.email_reset'))

                else:
                    error = "Invalid credentials, try again."
            else:
                error = "Invalid authentication, try again."

        return render_template('technician/account/email_confirm.html', error=error)

    except Exception as e:
        error = e
        return render_template('technician/account/email_confirm.html', error=error)


@technician.route('/account/email_reset/', methods=['GET', 'POST'])
def email_reset():
    error = ''
    try:
        if session['econfirm'] == 1:
            form = TechEmailResetForm(request.form)

            if request.method == "POST" and form.validate():
                email = form.email.data
                # check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
                # if form input and the session are the same, we dont care,
                # because nothing will change
                if(email != session["email"]):
                    technician = Technician.query.filter_by(
                        email=email).first_or_404()

                    if technician and technician.id != session['tid']:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That email already has an account, please try a different email.', 'danger')
                        return render_template('technician/account/email_reset.html', form=form)
                    technician = Technician.query.filter_by(
                        id=session['tid']).first()
                    technician.email = email
                    db.session.commit()
                    flash(u'Email successfully changed!', 'success')
                    session['email'] = email
                    # so they cant get back in!
                    session['econfirm'] = 0
                    return redirect(url_for('technician.account'))

            return render_template('technician/account/email_reset.html', form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))


@technician.route('/account/phone_confirm/', methods=['GET', 'POST'])
def phone_confirm():
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            technician = Technician.query.filter_by(email=email).first_or_404()
            # Prevent login to another account from this stage
            if technician and request.form['email'] == session['email']:
                pdata = technician.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    # putting these close and commit
                    # functions outside the 'if' will break code
                    session['phconfirm'] = 1
                    flash(u'Successfully authorized.', 'success')
                    return redirect(url_for('technician.phone_reset'))
                else:
                    error = "Invalid credentials, try again."
            else:
                error = "Invalid authentication, try again."
        return render_template('technician/account/phone_confirm.html', error=error)

    except Exception as e:
        error = e
        return render_template('technician/account/phone_confirm.html', error=error)


@technician.route('/account/phone_reset/', methods=['GET', 'POST'])
def phone_reset():
    error = ''
    try:
        if session['phconfirm'] == 1:
            form = TechPhoneResetForm(request.form)
            if request.method == "POST" and form.validate():
                phone = form.phone.data
                technician = Technician.query.filter_by(
                    phone=phone).first()
                if technician and technician.id != session['tid']:
                    flash(
                        u'That phone already has an account, please try a different phone.', 'danger')
                    return render_template('technician/account/phone_reset.html', form=form)

                technician = Technician.query.filter_by(
                    id=session['tid']).first()
                technician.phone = phone
                db.session.commit()
                flash(u'Phone number successfully changed!', 'success')
                # so they cant get back in!
                session['phconfirm'] = 0
                return redirect(url_for('technician.account'))

            return render_template('technician/account/phone_reset.html', form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))


@technician.route('/email/send_email_verify/', methods=['GET', 'POST'])
def send_email_verify():
    if 'logged_in' in session and request.method == "GET":
        email = session['email']
        first_name = session['first_name']
        # Send confirmation email
        token = s.dumps(email, salt='email-verify')
        msg = Message("Minute.tech - Email Verification",
                      sender="test@minute.tech", recipients=[email])
        link = url_for('technician.email_verify',
                       token=token, _external=True)
        msg.body = render_template(
            'technician/email/send_email_verify.txt', link=link, first_name=first_name)
        msg.html = render_template(
            'technician/email/send_email_verify.html', link=link, first_name=first_name)
        mail.send(msg)
        flash(u'Verification email sent', 'success')
        return redirect(url_for('technician.account'))
    else:
        flash(u'Log in as a technician first, then click the link again', 'danger')
        return redirect(url_for('technician.login'))

# Temporary function


@technician.route('/add_mp/', methods=['GET', 'POST'])
def add_mp():
    technician = Technician.query.filter_by(id=session['tid']).first_or_404()
    rating = int(technician.rating) + 50
    technician.rating = rating
    db.sesison.commit()
    flash(u'50mp added!', 'success')
    return redirect(url_for('technician.account'))
