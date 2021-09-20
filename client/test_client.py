import unittest

from string import printable as AsciiPrintable

from . import client
from .http_exceptions import http_exceptions


class TestAPIClient(unittest.TestCase):

  connection_params = {
    "base_url": "https://postman-echo.com",
    "auth_type": "basic-auth",
    "username": "postman",
    "password": "password",
    "insecure": True,
  }

  def test_create_client_missing_url(self):
    self.assertRaises(ValueError, client.APIClient, {})


  def test_base64_encode(self):
    str1 = AsciiPrintable[:-6]
    str2 = AsciiPrintable[:-6]
    encoded = client.APIClient.encode_base64(str1, str2)
    self.assertEqual(encoded, b'MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohIiMkJSYnKCkqKywtLi86Ozw9Pj9AW1xdXl9ge3x9fjAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaISIjJCUmJygpKissLS4vOjs8PT4/QFtcXV5fYHt8fX4=')

    str1 = "postman"
    str2 = "password"
    encoded = client.APIClient.encode_base64(str1, ":", str2)
    self.assertEqual(encoded, b'cG9zdG1hbjpwYXNzd29yZA==')

  def test_basic_auth_success(self):
    api_client = client.APIClient(self.connection_params)
    api_client.basic_auth()
  
  def test_basic_auth_failure(self):
    connection_params = self.connection_params.copy()
    connection_params["password"] = ""
    api_client = client.APIClient(connection_params)
    self.assertRaises(http_exceptions.UnauthorisedError, api_client.basic_auth)

  def test_digest_auth_success(self):
    connection_params = self.connection_params.copy() 
    connection_params["auth_type"] = "digest-auth"
    api_client = client.APIClient(connection_params)
    api_client.digest_auth()

  def test_digest_auth_failure(self):
    connection_params = self.connection_params.copy()
    connection_params["password"] = ""
    api_client = client.APIClient(connection_params)
    self.assertRaises(http_exceptions.UnauthorisedError, api_client.digest_auth)
  
  def test_authenticate_success(self):
    connection_params = self.connection_params.copy() 
    connection_params["auth_type"] = "digest-auth"
    api_client = client.APIClient(connection_params)
    api_client.authenticate()

  def test_auth_failure(self):
    connection_params = self.connection_params.copy()
    connection_params["password"] = ""
    connection_params["auth_type"] = "digest-auth"
    api_client = client.APIClient(connection_params)
    self.assertRaises(http_exceptions.UnauthorisedError, api_client.authenticate)
  
  def test_get_value(self):
    connection_params = self.connection_params.copy() 
    api_client = client.APIClient(connection_params)
    params = {"foo1": "bar1", "foo2": "bar2"}
    _ = api_client.get_value(params)
