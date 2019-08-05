import flask

app = flask.Flask("ratata")

@app.route("/xss_arg")
def xss_arg():
    data = flask.request.args.get('data')
    resp = flask.make_response(data, 200)
    resp.headers['Content-Type'] = 'text/html'
    return resp


@app.route("/xss_form")
def xss_form():
    data = flask.request.form['input_data']
    return data

app.run()
