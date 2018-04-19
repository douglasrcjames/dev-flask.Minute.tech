import os
from flask import (render_template, flash, request,
                   url_for, redirect, session,
                   send_file,
                   Blueprint)
from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt  # To encrypt the password
# from MySQLdb import escape_string as thwart  # To prevent SQL injection
from sqlalchemy import or_
from flask_mail import Message
# Email confirmation link that has a short lifespan
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# Custom f(x)
from .forms import (ContactForm, RegistrationForm, AskForm,
                    EditAccountForm,
                    PasswordResetForm, EmailResetForm, PhoneResetForm)
from .models import Contact, Client, Ticket, Thread
from minutetech.config import SECRET_KEY, UPLOAD_FOLDER
from minutetech import mail, db
from minutetech.utils import allowed_file, login_required

main = Blueprint('main', __name__, template_folder='templates')
s = URLSafeTimedSerializer(SECRET_KEY)  # For token


# 1st Layer Pages (Visible to all visitors)


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
        priority = 0
        cid = session['cid']

        ticket = Ticket(client_id=cid, difficulty=difficulty,
                        priority=priority, title=title, tags=tags)
        db.session.add(ticket)
        db.session.commit()
        thread = Thread(client_id=cid, ticket_id=ticket.id, body=body)
        db.session.add(thread)
        db.session.commit()

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
            feedback = Contact(
                uid=uid,
                email=email,
                message=message
            )
            db.session.add(feedback)
            db.session.commit()
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
        if request.method == "POST":
            email = request.form['email']
            client = Client.query.filter_by(email=email).first()
            # Prevent login to another account from this stage
            if client:
                pdata = client.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    session['logged_in'] = 'client'
                    session['email'] = client.email
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
def register():
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

            client = Client.query.filter(or_(Client.email == email,
                                             Client.phone == phone)).first()

            if client:
                if client.email == email:
                    flash(
                        u'That email already has an account, please try a new email or send an email to help@minute.tech', 'danger')
                    return render_template('register.html', form=form)
                if client.phone == phone:
                    flash(
                        u'That phone already has an account, please try a new phone or send an email to help@minute.tech', 'danger')
                    return render_template('register.html', form=form)
            else:

                client = Client(email=email, phone=phone, password=password,
                                first_name=first_name, last_name=last_name,
                                address=address, city=city, state=state,
                                zip_code=czip, bio=bio)

                db.session.add(client)
                db.session.commit()

                flash(u'Thanks for registering!', 'success')

                session['logged_in'] = 'client'
                # we get the client ID on the first page after it is generated,
                # dont worry
                session['cid'] = client.id
                session['email'] = email
                # Send confirmation email
                token = s.dumps(email, salt='email-verify')
                msg = Message("Minute.tech - Email Verification",
                              sender="test@minute.tech", recipients=[email])
                link = url_for('main.email_verify',
                               token=token, _external=True)
                msg.body = render_template(
                    'email/email_verify.txt', link=link,
                    first_name=first_name)
                msg.html = render_template(
                    'email/email_verify.html', link=link,
                    first_name=first_name)
                mail.send(msg)
                return redirect(url_for('main.account'))

        return render_template("register.html", form=form)

    except Exception as e:
        return "Error: {}".format(e)


@main.route('/email_verify/<token>')
def email_verify(token):
    try:
        if 'logged_in' in session:
            email = s.loads(token, salt='email-verify', max_age=3600)
            if session['logged_in'] == 'client':
                cid = session['cid']
                client = Client.query.filter_by(id=cid).first_or_404()
                client.email_verify = 1
                db.session.commit()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('main.account'))

            elif session['logged_in'] == 'tech':
                flash(u'Log in as a client first, then click the link again',
                      'danger')
                return redirect(url_for('main.login'))

        else:
            flash(u'Log in as a client first, then click the link again',
                  'danger')
            return redirect(url_for('main.login'))

        render_template("main.html")
    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))


@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        form = PasswordResetForm(request.form)
        email = s.loads(token, salt='forgot-password', max_age=3600)
        client = Client.query.filter_by(email=email).first_or_404()
        if client.reset_password_token != token:
            flash(u'Invalid token', 'danger')
            return redirect(url_for('main.login'))

        if request.method == "POST" and form.validate():
            password = sha256_crypt.encrypt((str(form.password.data)))
            client.password = password
            client.reset_password_token = ''
            db.session.commit()
            flash(u'Password successfully changed!', 'success')
            return redirect(url_for('main.login'))
        return render_template("reset_password.html", form=form, token=token)

    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))


@main.route('/forgot_password/', methods=['POST'])
def forgot_password():
    try:
        # Send confirmation email
        f_email = request.form['f_email']
        client = Client.query.filter_by(email=f_email).first()

        if client:
            token = s.dumps(f_email, salt='forgot-password')
            client.reset_password_token = token
            db.session.commit()
            msg = Message("Minute.tech - Forgot Password",
                          sender="test@minute.tech", recipients=[f_email])
            link = url_for('main.reset_password', token=token, _external=True)
            msg.body = render_template(
                'email/forgot_password-email.txt', link=link,
                first_name=client.first_name)
            msg.html = render_template(
                'email/forgot_password-email.html', link=link,
                first_name=client.first_name)
            mail.send(msg)
            flash(u'Password reset link sent to email', 'success')
            return redirect(url_for('main.homepage'))
        else:
            flash(u'The email you entered doesn\'t exists', 'danger')
            return redirect(url_for('main.login'))
    except Exception as e:
        return(str(e))

# END 1st Layer ###############

# 2nd Layer #################


@main.route('/ask/', methods=['GET', 'POST'])
def ask():
    error = ''
    try:
        if request.method == "POST":
            client_id = session['cid']
            client = Client.query.filter_by(id=client_id).first_or_404()
            client.launch_email = 1
            db.session.commit()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.ask'))
        return render_template("account/ask.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)


@main.route('/resolved/', methods=['GET', 'POST'])
def resolved():
    error = ''
    try:
        if request.method == "POST":
            client_id = session['cid']
            client = Client.query.filter_by(id=client_id).first_or_404()
            client.launch_email = 1
            db.session.commit()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.ask'))
        return render_template("account/ask.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)

    except Exception as e:
        return render_template("500.html", error=e)


@main.route('/pending/', methods=['GET', 'POST'])
def pending():
    error = ''
    try:
        if request.method == "POST":
            client_id = session['cid']
            client = Client.query.filter_by(id=client_id).first_or_404()
            client.launch_email = 1
            db.session.commit()
            flash(u'Thanks, we got you down!', 'success')
            return redirect(url_for('main.ask'))
        return render_template("account/ask.html", error=error)

    except Exception as e:
        return render_template("500.html", error=e)


@main.route('/account/', methods=['GET', 'POST'])
def account():
    error = ''
    try:
        form = EditAccountForm(request.form, request.files)
        if session['logged_in'] == 'client':
            # grab all the clients info
            email = session['email']
            client = Client.query.filter_by(email=email).first_or_404()
            # Get value before placing into textarea-box...
            # had to do this method because value=session.bio wasnt working in
            # jinja
            form.bio.data = client.bio
            if request.files:
                formdata = request.form.copy()
                formdata.update(request.files)
                form = EditAccountForm(formdata)

            if request.method == 'POST' and form.validate():
                if 'prof_pic' in request.files:
                    new_prof_pic = request.files['prof_pic']
                    if allowed_file(new_prof_pic.filename):
                        filename = secure_filename(new_prof_pic.filename)
                        old_prof_pic = os.path.join(UPLOAD_FOLDER,
                                                    os.path.basename(client.prof_pic))
                        if os.path.exists(old_prof_pic):
                            os.unlink(old_prof_pic)
                        new_prof_pic.save(os.path.join(
                            UPLOAD_FOLDER, filename))
                        prof_pic = 'user_info/' + filename
                        client.prof_pic = prof_pic

                client.first_name = form.first_name.data
                client.last_name = form.last_name.data
                client.address = form.address.data
                client.city = form.city.data
                client.state = form.state.data
                client.zip_code = form.czip.data
                client.birth_year = form.birth_year.data
                client.birth_day = form.birth_day.data
                client.birth_month = form.birth_month.data
                client.bio = form.bio.data
                db.session.commit()
                flash(u'Your account is successfully updated.', 'success')
            return render_template("account/index.html", form=form,
                                   client=client,
                                   error=error)
        else:
            # this probably isnt necessary since 500 error catches it as no
            # session variable called 'logged_in'
            flash(u'Try logging in as a client', 'secondary')
            return redirect(url_for('main.login'))

    except Exception as e:
        return render_template("500.html", error=e)


@main.route('/password_confirm/', methods=['GET', 'POST'])
def password_confirm():
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            client = Client.query.filter_by(email=email).first_or_404()
            # Prevent login to another account from this stage
            if client and request.form['email'] == session['email']:
                pdata = client.password
                if sha256_crypt.verify(request.form['password'], pdata):
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


@main.route('/password_reset/', methods=['GET', 'POST'])
def password_reset():
    try:
        if session['pconfirm'] == 1:
            form = PasswordResetForm(request.form)
            if request.method == "POST" and form.validate():
                cid = session['cid']
                password = sha256_crypt.encrypt((str(form.password.data)))
                client = Client.query.filter_by(id=cid).first_or_404()
                client.password = password
                db.session.commit()
                flash(u'Password successfully changed!', 'success')
                # so they cant get back in!
                session['pconfirm'] = 0
                return redirect(url_for('main.account'))

            return render_template("account/password_reset.html", form=form)
        else:
            flash(u'Not allowed there!', 'danger')
            return redirect(url_for('main.homepage'))

    except Exception as e:
        return(str(e))


@main.route('/email_confirm/', methods=['GET', 'POST'])
def email_confirm():
    error = ''
    try:
        if request.method == "POST":
            client = Client.query.filter_by(
                email=request.form['email']).first()

            if client and request.form['email'] == session['email']:
                pdata = client.password
                if sha256_crypt.verify(request.form['password'], pdata):
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


@main.route('/email_reset/', methods=['GET', 'POST'])
def email_reset():
    try:
        if session['econfirm'] == 1:
            form = EmailResetForm(request.form)

            if request.method == "POST" and form.validate():
                email = form.email.data
                if(email != session["email"]):
                    client = Client.query.filter_by(email=email).first_or_404()
                    if client:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That email already has an account, please try a different email.', 'danger')
                        return render_template('account/email_reset.html', form=form)
                client.email = email
                db.session.commit()
                flash(u'Email successfully changed!', 'success')
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


@main.route('/phone_confirm/', methods=['GET', 'POST'])
def phone_confirm():
    error = ''
    try:
        if request.method == "POST":
            email = request.form['email']
            client = Client.query.filter_by(email=email).first_or_404()
            # Prevent login to another account from this stage
            if client and request.form['email'] == session['email']:
                pdata = client.password
                if sha256_crypt.verify(request.form['password'], pdata):
                    # putting these close and commit
                    # functions outside the 'if' will break code
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


@main.route('/phone_reset/', methods=['GET', 'POST'])
def phone_reset():
    try:
        if session['phconfirm'] == 1:
            form = PhoneResetForm(request.form)
            if request.method == "POST" and form.validate():
                phone = form.phone.data
                client = Client.query.filter_by(phone=phone).first_or_404()
                # check if phone number exists first
                if(phone != session["phone"]):
                    if client:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That phone already has an account, please try a different phone.', 'danger')
                        return render_template('account/phone_reset.html', form=form)

                client.phone = phone
                db.session.commit()
                flash(u'Phone number successfully changed!', 'success')
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


@main.route('/email/send_email_verify/', methods=['GET', 'POST'])
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

# Temporary function


@main.route('/add_mp/', methods=['GET', 'POST'])
def add_mp():
    rating = session['rating']
    cid = session['cid']
    rating = rating + 50
    client = Client.query.filter_by(id=cid).first_or_404()
    client.rating = rating
    db.session.commit()
    flash(u'50mp added!', 'success')
    return redirect(url_for('main.account'))


# Sending Files (for display on email, probably a better way to do this)

@main.route('/MinutetechLLC_tos/')
def return_tos():
    return send_file('static/legal/MinutetechLLC_tos.pdf',
                     attachment_filename='MinutetechLLC_tos.pdf')


@main.route('/Minutetech_Logo/')
def return_logo():
    return send_file('static/images/Icon_1000x1000px.png',
                     attachment_filename='Icon_1000x1000px.png')


@main.route('/coffee-lady/')
def return_pic1():
    return send_file('static/images/lady-logo-email-banner.png',
                     attachment_filename='lady-logo-email-banner.png')


@main.route('/technician-macbook-watch/')
def return_pic2():
    return send_file('static/images/technician-macbook-watch.png',
                     attachment_filename='technician-macbook-watch.png')


@main.route('/Minutetech_Long_Logo/')
def return_logo_long():
    return send_file('static/images/Secondary_long.png')


@main.route('/Minutetech_rocket_ship/')
def return_rocket_ship():
    return send_file('static/flat-icons/008-startup.png')


@main.route('/Minute_technician/')
def return_technician():
    return send_file('static/flat-icons/support.png')


@main.route('/Minutetech_shield/')
def return_shield():
    return send_file('static/flat-icons/005-shield.png')
