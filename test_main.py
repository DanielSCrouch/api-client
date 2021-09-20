from unittest import mock
import unittest

from client.client import APIClient
from main import main

class TestVimconn_VMware(unittest.TestCase):

  @mock.patch.object(APIClient, "get_value")
  @mock.patch.object(APIClient, "authenticate")
  def test_main_with_mock(self, authenticate, get_value):
      """
      Testcase for main with APIClient.get_value mock
      """
      connection_params = {
        "base_url": "https://postman-echo.com",
        "auth_type": "basic-auth",
        "username": "postman",
        "password": "",
        "insecure": True,
      }

      # create client
      api_client = APIClient(connection_params)

      # assumed return value from client get_value
      get_value.return_value = {"abc", "123"}

      print(f'returned value: {api_client.get_value({"a": "b"})}')

      main()

if __name__ == "__main__":
  unittest.main()