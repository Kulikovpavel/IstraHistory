import unittest
from google.appengine.api import memcache
from google.appengine.ext import testbed
import webapp2
import json
import webtest
from main import PicturesAPI


class AjaxPicturesTest(unittest.TestCase):
    def setUp(self):
        # First, create an instance of the Testbed class.
        app = webapp2.WSGIApplication([('/pictures_api',PicturesAPI)])
        self.testbed = testbed.Testbed()
        self.testapp = webtest.TestApp(app)
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Create a consistency policy that will simulate the High Replication consistency model.
        self.testbed.init_memcache_stub()


    def tearDown(self):
        self.testbed.deactivate()

    def test_ajax(self):
        data = "pictures_data"
        memcache.set("pictures_all", data)
        params = {'key': 11, 'value': 11}
        response = self.testapp.get('/pictures_api', params)
        self.assertEqual(data, json.loads(response.normal_body))





