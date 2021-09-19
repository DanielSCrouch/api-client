import unittest

from client import APIClient
from string import printable as AsciiPrintable

from http_exceptions import UnauthorisedError


class TestAPIClient(unittest.TestCase):

  connection_params = {
    "base_url": "https://postman-echo.com",
    "auth_type": "basic-auth",
    "username": "postman",
    "password": "password",
    "insecure": True,
  }

  def test_create_client_missing_url(self):
    self.assertRaises(ValueError, APIClient, {})


  def test_base64_encode(self):
    str1 = AsciiPrintable[:-6]
    str2 = AsciiPrintable[:-6]
    encoded = APIClient.encode_base64(str1, str2)
    self.assertEqual(encoded, b'MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohIiMkJSYnKCkqKywtLi86Ozw9Pj9AW1xdXl9ge3x9fjAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaISIjJCUmJygpKissLS4vOjs8PT4/QFtcXV5fYHt8fX4=')

    str1 = "postman"
    str2 = "password"
    encoded = APIClient.encode_base64(str1, ":", str2)
    self.assertEqual(encoded, b'cG9zdG1hbjpwYXNzd29yZA==')

  def test_basic_auth_success(self):
    client = APIClient(self.connection_params)
    client.basic_auth()
  
  def test_basic_auth_failure(self):
    connection_params = self.connection_params.copy()
    connection_params["password"] = ""
    client = APIClient(connection_params)
    self.assertRaises(UnauthorisedError, client.basic_auth)

  def test_digest_auth_success(self):
    connection_params = self.connection_params.copy() 
    connection_params["auth_type"] = "digest-auth"
    client = APIClient(connection_params)
    client.digest_auth()
  
  def test_get_value(self):
    connection_params = self.connection_params.copy() 
    client = APIClient(connection_params)
    params = {"foo1": "bar1", "foo2": "bar2"}
    _ = client.get_value(params)


if __name__ == "__main__":
  unittest.main()
