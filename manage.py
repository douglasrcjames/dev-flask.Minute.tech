#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_script import Manager
from flask_migrate import MigrateCommand, Migrate
from minutetech import app, db

manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

from minutetech.main.models import Client, Ticket, Thread, Contact
from minutetech.technician.models import Technician

if __name__ == "__main__":
    manager.run()
