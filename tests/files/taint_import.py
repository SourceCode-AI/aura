import flask

def get_username():
    return flask.request.args['username']
