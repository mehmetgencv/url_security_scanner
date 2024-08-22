import unittest
from app import app


class BasicAppTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome to the URL Security Scanner!", response.data)


if __name__ == '__main__':
    unittest.main()
