# This is an intentionaly vulnerable Flask application
# Vulnerabilites here are used to test the taint analysis sytem

import flask

from . import taint_import

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
    for _ in range(5):  # TODO: handle this case
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


@app.route('/vuln7/<command>')
def vuln7(command):
    eval(command)


@app.route('/vuln8')
def vuln8():
    name = flask.request.args.get('name', 'Spiderman')
    return flask.render_template("main_xss.html", name=name)

@app.route('/vuln9')
def vuln9():
    # Test that the taint is passed from a different module
    name = taint_import.get_username()
    return flask.render_template('main_xss.html', name=name)


@app.route('/not_vuln1/<int:command>')
def not_vuln1(command):
    eval(command)


@app.route('/not_vuln2/<command>')
def not_vuln2(command):
    c = int(command)
    eval(c)


@app.route('/test1')
def test1():
    return flask.render_template('doesn_not_exists.html')


app.run(debug=True)
