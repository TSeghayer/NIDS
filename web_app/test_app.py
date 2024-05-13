import unittest
from flask import url_for
from app import app

class FlaskTestCase(unittest.TestCase):

    def setUp(self):
        # Creates a test client for your Flask app.
        # This allows you to send HTTP requests to the application.
        self.app = app.test_client()
        # Propagate the exceptions to the test client
        self.app.testing = True
    
    def test_index_page(self):
        # Tests the index page for a successful HTTP response.
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Network Throughput Chart', response.data.decode('utf-8'))

    def test_about_us_page(self):
        # Tests the about-us page for a successful HTTP response.
        response = self.app.get('/about-us')
        self.assertEqual(response.status_code, 200)
        self.assertIn('About Us', response.data.decode('utf-8'))

if __name__ == '__main__':
    unittest.main()
