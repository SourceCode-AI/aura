try:
    import requests
    requests.get("Hi there")
    print "Hello world"
except Exception, ValueError:
    pass