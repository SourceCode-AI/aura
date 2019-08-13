import flask


app = flask.Flask("ratata")


class Unsecure():
    def __init__(self):
        self.code = None

    @classmethod
    def eval_arg(cls):
        eval(flask.request.args.get('src', 'pass'))
        return True

    def run(self):
        if self.code is None:
            return False
        else:
            eval(self.code)
            return True


@app.route("/vuln1")
def xss_arg():
    """
    XSS via URL parameter
    """
    data = flask.request.args.get('data')
    resp = flask.make_response(data, 200)
    resp.headers['Content-Type'] = 'text/html'
    return resp


@app.route("/vuln2")
def xss_form():
    """
    XSS via form parameter
    """
    data = flask.request.form['input_data']
    return data


@app.route('/vuln3')
def drive_by():
    """
    Arbitrary redirect via URL parameter
    """
    return flask.redirect(flask.request.args.get('secret_value'), 302)

@app.route('/vuln4')
def vuln4():
    """
    XSS via string concatenation
    """
    return "<h1>" + flask.request.args.get('name', 'John Doe') + '!</h1>'


@app.route('/vuln5')
def vuln5():
    """
    Tainted input defined at the end of the for-loop
    """
    name = None
    for _ in range(5):
        if name is not None:
            eval(name)
        else:
            name = flask.request.args.get('src', 'pass')


@app.route('/vuln6')
def vuln6():
    obj = Unsecure()
    obj.eval_arg()
    obj.code = flask.request.args.get('src', 'pass')
    obj.run()
    return "Hello world"


app.run()
