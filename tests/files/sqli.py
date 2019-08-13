

def query(uid):
    q1 = "SELECT * FROM users WHERE id = 1"
    q2 = "SELECT * FROM users WHERE id = %d" % uid
    q3 = "SELECT * FROM users WHERE id = {}".format(uid)
    q4 = f"SELECT * FROM users WHERE id = {uid}"
    q5 = "SELECT * FROM users where id = " + uid
