import MySQLdb
import mysql.connector
import pymysql


def sqli1():
    db = MySQLdb.connect(
        host="localhost",
        user="",
        passwd="",
        db=""
    )
    data = input("Enter something: ")
    cur = db.cursor()
    cur.execute("SELECT * from users where id = " + data)


def sqli2():
    con = mysql.connector.connect("blah")
    cur = con.cursor()
    data = input("Enter something: ")
    cur.execute("SELECT * FROM users WHERE id = " + data)


def sqli3():
    con = pymysql.connect()
    cur = con.cursor()
    data = input("Enter something: ")
    cur.execute("SELECT * FROM users WHERE id =" + data)


def sqli4(unused=5, parameter=''):
    con = pymysql.connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id =" + parameter)


def something():
    """
    Test if the taint propagates via call graph
    """
    p = input("in4")
    sqli4(parameter=p)


def query(uid):
    q1 = "SELECT * FROM users WHERE id = 1"
    q2 = "SELECT * FROM users WHERE id = %d" % uid
    q3 = "SELECT * FROM users WHERE id = {}".format(uid)
    q4 = f"SELECT * FROM users WHERE id = {uid}"
    q5 = "SELECT * FROM users where id = " + uid
