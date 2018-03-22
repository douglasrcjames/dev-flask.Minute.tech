#this file is equal to flaskapp.wsgi (I think)
from minutetech import app

if __name__ == '__main__':
    app.run(debug=True)
