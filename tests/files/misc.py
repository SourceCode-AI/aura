listen_server('0.0.0.0')


with open('/tmp/race_condition') as fd:
    fd.write('Hello world')
