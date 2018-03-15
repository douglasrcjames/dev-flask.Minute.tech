from flask import Blueprint

# charge 'api' to the folder u want (minutetech)
mod = Blueprint('technician', __name__)

@mod.route('/homepage2')
def homepage2():
	return '<h1>You are on the homepage 2</h1>'