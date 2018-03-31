from datetime import datetime
from minutetech import db
from minutetech.technician.models import Technician

default_prof_pic = '/static/user_info/prof_pic/default.jpg'


class Client(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    rating = db.Column(db.Integer, default=500)
    address = db.Column(db.Text, default='Not Provided')
    city = db.Column(db.String(255), default='Not Provided')
    state = db.Column(db.String(255), default='NA')
    zip_code = db.Column(db.String(16))
    birth_year = db.Column(db.Integer, default=1899)
    birth_month = db.Column(db.String(10), default='Junuary')
    birth_day = db.Column(db.Integer, default=1)
    bio = db.Column(db.Text)
    lang_pref = db.Column(db.String(64), default='Not Provided')
    time_zone = db.Column(db.String(64), default='Not Provided')
    launch_email = db.Column(db.Integer, default=0)
    email_verify = db.Column(db.Integer, default=0)
    prof_pic = db.Column(db.String(255), default=default_prof_pic)
    reg_date = db.Column(db.DateTime, nullable=False,
                         default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    ticket = db.relationship('Ticket', backref='client', lazy=True)
    thread = db.relationship('Thread', backref='client', lazy=True)

    def __repr__(self):
        return "{} {}".format(self.first_name, self.last_name)


class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey(
        Client.id), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey(
        Technician.id), nullable=False)
    difficulty = db.Column(db.Integer, default=0)
    priority = db.Column(db.Integer, default=500)
    solved = db.Column(db.Boolean, default=False)
    pending = db.Column(db.Boolean, default=False)
    archived = db.Column(db.Boolean, default=False)
    tite = db.Column(db.String(255))
    tags = db.Column(db.Text)
    answer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    thread = db.relationship('Thread', backref='ticket', lazy=True)


class Thread(db.Model):
    __tablename__ = 'threads'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey(
        Client.id), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey(
        Technician.id), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey(
        Ticket.id), nullable=False)
    body = db.Column(db.Text)
    img = db.Column(db.String(255))
    answered = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)


class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, default=0)
    email = db.Column(db.String(255))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
