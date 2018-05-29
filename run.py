# -*- coding: utf-8 -*-
import logging
from logging.handlers import RotatingFileHandler
# from flask_images import Images
from minutetech import app
from minutetech import socketio
if __name__ == '__main__':
    file_handler = RotatingFileHandler('errors.log',
                                       maxBytes=1024 * 1024 * 100,
                                       backupCount=20)
    file_handler.setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)
    app.logger.addHandler(file_handler)
    app.debug = True
    # app.run(host='0.0.0.0', debug=True)
    socketio.run(app, host='0.0.0.0')
