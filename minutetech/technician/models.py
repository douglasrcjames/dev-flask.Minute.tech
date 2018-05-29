from datetime import datetime
from minutetech import db

default_prof_pic = 'user_info/prof_pic/default.jpg'


class Technician(db.Model):
    __tablename__ = 'technicians'
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
    linked_in = db.Column(db.String(255))
    tags = db.Column(db.Text)
    signature = db.Column(db.String(255))
    lang_pref = db.Column(db.String(64), default='Not Provided')
    time_zone = db.Column(db.String(64), default='Not Provided')
    launch_email = db.Column(db.Integer, default=0)
    email_verify = db.Column(db.Integer, default=0)
    prof_pic = db.Column(db.String(255), default=default_prof_pic)
    reg_date = db.Column(db.DateTime, nullable=False,
                         default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)
    thread = db.relationship('Thread', backref='technician', lazy=True)
    ticket = db.relationship('Ticket', backref='technician', lazy=True)

    def __repr__(self):
        return "{} {}".format(self.first_name, self.last_name)
