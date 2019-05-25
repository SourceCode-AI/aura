import requests
from requests.auth import HTTPBasicAuth

requests.get('https://api.github.com/user', auth=HTTPBasicAuth('user1', 'pass1'))
requests.get('https://api.github.com/user', auth=('user2', 'pass2'))

super_password = "letmein"

def login(user, password="toor"):
    if password == "toor":
        return True
    else:
        return False
