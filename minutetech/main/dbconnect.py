import MySQLdb

def connection():
    conn = MySQLdb.connect(host="localhost",
                           user = "admin",
                           passwd = "Printerugh!1",
                           db = "minutetech")
    c = conn.cursor()

    return c, conn
