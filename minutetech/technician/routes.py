import os
import os.path
from flask import (render_template, flash, request,
                   url_for, redirect, session,
                   send_file,
                   Blueprint)
from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt  # To encrypt the password
from MySQLdb import escape_string as thwart  # To prevent SQL injection
from flask_mail import Message
# Email confirmation link that has a short lifespan
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from functools import wraps  # For login_required
# Custom f(x)
from minutetech.dbconnect import connection
from forms import (TechRegistrationForm, TechEditAccountForm,
                   TechPasswordResetForm,
                   TechEmailResetForm, TechPhoneResetForm, TechSignatureForm)
from minutetech.config import SECRET_KEY, UPLOAD_FOLDER
from minutetech import mail

technician = Blueprint('technician', __name__, template_folder='templates')
s = URLSafeTimedSerializer(SECRET_KEY)  # For token
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

#  1st Layer SECTION
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
            return redirect(url_for('technician.login'))
    return wrap


@technician.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    session.clear()
    flash(u'You have been logged out!', 'danger')
    return redirect(url_for('main.homepage'))

count = 1
@technician.route('/login/', methods=['GET', 'POST'])
def login():
    global count
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM technicians WHERE email = (%s)",
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
                    session['logged_in'] = 'tech'
                    session['email'] = thwart(email)
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
            c, conn = connection()

            # check if already exists
            x = c.execute(
                "SELECT * FROM technicians WHERE email = (%s)", (thwart(email),))
            y = c.execute(
                "SELECT * FROM technicians WHERE phone = (%s)", (thwart(phone),))

            if int(x) > 0:
                flash(
                    u'That email already has an account, please try a new email or send an email to help@minute.', 'danger')
                return render_template('technician/register.html', form=form)
            elif int(y) > 0:
                flash(
                    u'That phone already has an account, please try a new phone or send an email to help@minute.', 'danger')
                return render_template('technician/register.html', form=form)
            else:
                default_prof_pic = url_for(
                    'static', filename='tech_user_info/prof_pic/default.jpg')
                c.execute("INSERT INTO technicians (email, phone, password) VALUES (%s, %s, %s)", (thwart(
                    email), thwart(phone), thwart(password)))
                c.execute("INSERT INTO tpersonals (first_name, last_name, address, city, state, zip, bio, prof_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (thwart(
                    first_name), thwart(last_name), thwart(address), thwart(city), state, thwart(tzip), bio, default_prof_pic))
                conn.commit()
                flash(u'Thanks for registering!', 'success')
                c.close()
                conn.close()

                session['logged_in'] = 'tech'
                # tid will be inputted once generated
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
                session['certified'] = 0
                session['bio'] = bio
                session['prof_pic'] = default_prof_pic
                # Send confirmation email
                token = s.dumps(email, salt='email-verify')
                msg = Message("Minute. - Email Verification",
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
        return(str(e))


@technician.route('/email_verify/<token>')
def email_verify(token):
    try:
        c, conn = connection()
        if 'logged_in' in session:
            email = s.loads(token, salt='email-verify', max_age=3600)

            if session['logged_in'] == 'tech':
                tid = session['tid']
                c.execute(
                    "UPDATE tpersonals SET email_verify = 1 WHERE tid = (%s)", (tid,))
                conn.commit()
                c.close()
                conn.close()
                flash(u'Email successfully verified!', 'success')
                return redirect(url_for('technician.account'))

            elif session['logged_in'] == 'client':
                flash(
                    u'Log in as a technician first, then click the link again', 'danger')
                return redirect(url_for('technician.login'))

        else:
            flash(u'Log in as a technician first, then click the link again', 'danger')
            return redirect(url_for('technician.login'))

        render_template("main.html")
    except SignatureExpired:
        flash(u'The token has expired', 'danger')
        return redirect(url_for('main.homepage'))

##############  2nd Layer SECTION  ####################

@technician.route('/account/answer/', methods=['GET', 'POST'])
def answer():
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
            return redirect(url_for('technician.answer'))

        return render_template('technician/account/answer.html', error=error)

    except Exception as e:
        return render_template('500.html', error=e)


@technician.route('/account/resolved/', methods=['GET', 'POST'])
def resolved():
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
            return redirect(url_for('technician.resolved'))

        return render_template('technician/account/resolved.html', error=error)

    except Exception as e:
        return render_template('500.html', error=e)


@technician.route('/account/pending/', methods=['GET', 'POST'])
def pending():
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
            return redirect(url_for('technician.pending'))

        return render_template('technician/account/pending.html', error=error)

    except Exception as e:
        return render_template('500.html', error=e)


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
            c, conn = connection()
            email = session['email']
            c.execute("""
                SELECT t.tid, t.phone, t.rating,
                p.first_name, p.last_name, p.address, p.city, p.state,
                p.zip, p.birth_month, p.birth_day, p.birth_year, p.bio,
                p.reg_date, p.prof_pic, p.email_verify, p.certified
                FROM technicians t, tpersonals p
                WHERE t.email = (%s) and t.tid=p.tid
                """,
                      (email,))
            tech = c.fetchone()
            tid = tech[0]
            phone = tech[1]
            rating = tech[2]
            first_name = tech[3]
            last_name = tech[4]
            address = tech[5]
            city = tech[6]
            state = tech[7]
            tzip = tech[8]
            birth_month = tech[9]
            birth_day = tech[10]
            birth_year = tech[11]
            bio = tech[12]
            reg_date = tech[13]
            # For now, just putting the prof_pic url into the BLOB
            prof_pic = tech[14]
            email_verify = tech[15]
            certified = tech[15]
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
            session['certified'] = certified
            session['email_verify'] = email_verify
            # For change of password, phone, or email
            session['pconfirm'] = 0
            session['phconfirm'] = 0
            session['econfirm'] = 0

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
                            UPDATE tpersonals SET prof_pic=%s
                            where tid = (%s)""",
                                  (thwart(prof_pic), tid))
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
                c.execute("UPDATE tpersonals SET first_name = %s, last_name = %s, address = %s, city = %s, state = %s, zip = %s, birth_month = %s, birth_day = %s, birth_year = %s, bio = %s WHERE tid = (%s)", (thwart(
                    first_name), thwart(last_name), thwart(address), thwart(city), thwart(state), thwart(tzip), birth_month, birth_day, birth_year, bio, tid))
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
            return redirect(url_for('main.homepage'))

        return render_template('technician/account/index.html', form=form, error=error)

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
        c, conn = connection()
        c.execute("UPDATE tpersonals SET signature = %s, certified = %s WHERE tid = %s",
                  (thwart(signature), 1, tid))
        conn.commit()
        c.close()
        conn.close()
        session['certified'] = 1
        flash(u'Submission successful. We will contact you soon.', 'success')
        return redirect(url_for('technician.account'))

    else:
        error = "Please enter your name!"
        return render_template('technician/account/signature.html', form=form)

@technician.route('/account/password_confirm/', methods=['GET', 'POST'])
def password_confirm():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM technicians WHERE email = (%s)",
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
                c, conn = connection()
                c.execute(
                    "UPDATE technicians SET password = %s WHERE tid = (%s)", (thwart(password), tid))
                conn.commit()
                flash(u'Password successfully changed!', 'success')
                c.close()
                conn.close()
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
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM technicians WHERE email = (%s)",
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
            c, conn = connection()
            if request.method == "POST" and form.validate():
                tid = session['tid']
                email = form.email.data
                # check if form input is different than whats in session, if so, then we want to make sure the form input isnt in the DB
                # if form input and the session are the same, we dont care,
                # because nothing will change
                if(email != session["email"]):
                    x = c.execute(
                        "SELECT * FROM technicians WHERE email = (%s)", (thwart(email),))
                    conn.commit()
                    if int(x) > 0:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That email already has an account, please try a different email.', 'danger')
                        return render_template('technician/account/email_reset.html', form=form)

                c.execute(
                    "UPDATE technicians SET email = %s WHERE tid = (%s)", (thwart(email), tid))
                conn.commit()
                flash(u'Email successfully changed!', 'success')
                c.close()
                conn.close()
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
        c, conn = connection()
        if request.method == "POST":
            # 'x' To prevent " 'NONETYPE' OBJECT HAS NO ATTRIBUTE '__GETITEM__' " error
            x = c.execute("SELECT * FROM technicians WHERE email = (%s)",
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
                # check if phone number exists first
                tid = session['tid']
                phone = form.phone.data
                c, conn = connection()
                if(phone != session["phone"]):
                    x = c.execute(
                        "SELECT * FROM technicians WHERE phone = (%s)", (thwart(phone),))
                    conn.commit()
                    if int(x) > 0:
                        # redirect them if they need to recover an old email
                        # from and old account
                        flash(
                            u'That phone already has an account, please try a different phone.', 'danger')
                        return render_template('technician/account/phone_reset.html', form=form)

                c.execute(
                    "UPDATE technicians SET phone = %s WHERE tid = (%s)", (thwart(phone), tid))
                conn.commit()
                flash(u'Phone number successfully changed!', 'success')
                c.close()
                conn.close()
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

#Temporary function
@technician.route('/add_mp/', methods=['GET', 'POST'])
def add_mp():
    c, conn = connection()
    rating = session['rating']
    tid = session['tid']
    rating = rating + 50
    c.execute("UPDATE technicians SET rating = %s WHERE tid = (%s)", (rating, tid))
    conn.commit()
    flash(u'50mp added!', 'success')
    c.close()
    conn.close()
    return redirect(url_for('technician.account'))
