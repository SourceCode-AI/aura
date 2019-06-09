import flask

app = flask.Flask("ratata")

@app.route("/xss")
def xss_out():
    data = flask.request.args.get('data')
    resp = flask.make_response(data, 200)
    resp.headers['Content-Type'] = 'text/html'
    return resp


app.run()
