import unittest
from jwt_handler import create_jwt, verify_jwt

class TestJWT(unittest.TestCase):
    def test_token(self):
        t = create_jwt({"user": "admin"})
        self.assertTrue(verify_jwt(t))
        self.assertFalse(verify_jwt(t + "tampered"))

if __name__ == "__main__":
    unittest.main()
