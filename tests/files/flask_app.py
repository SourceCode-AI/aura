import flask


app = flask.Flask("ratata")


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


app.run()
