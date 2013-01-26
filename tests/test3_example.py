import unittest
import webapp2
import webtest

class HelloWorldHandler(webapp2.RequestHandler):
    def get(self):
        # Create the handler's response "Hello World!" in plain text.
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Hello World!')

class AppTest(unittest.TestCase):
    def setUp(self):
        # Create a WSGI application.
        app = webapp2.WSGIApplication([('/', HelloWorldHandler)])

        self.testapp = webtest.TestApp(app)

    # Test the handler.
    def testHelloWorldHandler(self):
        response = self.testapp.get('/')
#        well, so we can use some actisdsdsdfsdfon
        self.assertEqual(response.status_int, 200)
        self.assertEqual(1,1)
        self.assertEqual(response.normal_body, 'Hello World!')
        self.assertEqual(response.content_type, 'text/plain')