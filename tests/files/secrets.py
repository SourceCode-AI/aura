import requests
from requests.auth import HTTPBasicAuth

requests.get('https://api.github.com/user', auth=HTTPBasicAuth('user1', 'pass1'))
requests.get('https://api.github.com/user?auth_token=RATATATAXXX', auth=('user2', 'pass2'))

super_password = "letmein"


def login(user, password="kw_toor"):
    if password == "cmp_toor":
        return True
    else:
        return False


class Klass():
    def __init__(self, secret_key_var):
        # This should not match
        self.secret_key = secret_key_var


invalid_url = "https://blah@[66:::89]/passwords"
