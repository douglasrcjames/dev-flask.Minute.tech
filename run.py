# -*- coding: utf-8 -*-
import logging
from logging.handlers import RotatingFileHandler
from minutetech import app

if __name__ == '__main__':
    file_handler = RotatingFileHandler('errors.log',
                                       maxBytes=1024 * 1024 * 100,
                                       backupCount=20)
    file_handler.setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)
    app.logger.addHandler(file_handler)
    app.run()
