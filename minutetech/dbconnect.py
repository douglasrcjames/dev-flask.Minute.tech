import MySQLdb


def connection():
    conn = MySQLdb.connect(host="localhost",
                           user="test",
                           passwd="welcomeback11",
                           db="minutetech")
    c = conn.cursor()

    return c, conn
