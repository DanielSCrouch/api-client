import requests
from requests.api import head
from urllib3.exceptions import InsecureRequestWarning
from base64 import b64encode as Base64Encode
from hashlib import md5 as Md5Hash
from requests.auth import HTTPDigestAuth
from datetime import datetime as DateTime
from datetime import timedelta as TimeDelta
from typing import Tuple

from .http_exceptions import http_exceptions

endpoint_extensions = {
    "basic-auth": "/basic-auth",
    "digest-auth": "/digest-auth",
    "get-value": "/get"
}

class APIClient(object):
    """A Generic HTTPx RestAPI Client for sending and receiving JSON data"""

    def __init__(self, connection_params):
        """
        Initialise an API client, connection params is a map containing:
        base_url: base url for server
        auth_type: authentication type, supports "basic-auth", "digest-auth", "oauth", ...
        username: login username (optional) 
        password: login password (optional) 
        insecure: allow communication without TLS (default=False)
        """
        if "base_url" not in connection_params:
            raise ValueError("base-url not provided in connection parameters")
        else:
            self.base_url = connection_params["base_url"]

        self.auth_type = connection_params["auth_type"] if "auth_type" in connection_params else ""
        self.username = connection_params["username"] if "username" in connection_params else ""
        self.password = connection_params["password"] if "password" in connection_params else ""

        if "insecure" in connection_params:
            self.insecure = connection_params["insecure"]
        else:
            self.insecure = False

        self.headers = {"Content-Type": "application/json", "accept": "application/json", "charset": "utf-8"}
        self.token = ""
        self.token_expiration = None

        if self.insecure:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    @staticmethod
    def encode_base64(*args: list[str]) -> bytes:
        """Base64 encode a list of ASCII string representable arguments."""
        collated = "".join([str(word) for word in args])
        encoded = Base64Encode(bytes(collated, "ascii"))
        return encoded

    def basic_auth(self) -> Tuple[str, int]:
        """
        Authenticates with server endpoint using basic username and password,
        return: token, expires_in (seconds)
        """
        url = f'{self.base_url}{endpoint_extensions["basic-auth"]}'
        self.headers["Authorization"] = self.encode_base64(self.username, self.password)
        auth_encoded = "Basic " + str(self.encode_base64(self.username, ":", self.password).decode('utf-8'))
        self.headers = {"Authorization": auth_encoded}

        r = requests.get(url,
                          headers=self.headers,
                          verify= not self.insecure)
        
        if r.status_code != 200:
            raise http_exceptions.error_factory(r.status_code)

        data = r.json() 
        data["token"] = "123" # testing
        data["expires_in"] = "5" # testing
        if "token" in data.keys():
            token = data["token"]
            expires_in = int(data["expires_in"])
            return token, expires_in
        
        raise Exception("basic authentication failed to collect token")
    
    def digest_auth(self) -> Tuple[str, int]:
        """
        Authenticates with server endpoint using digest authentication,
        return: token, expires_in (seconds)
        """
        url = f'{self.base_url}{endpoint_extensions["digest-auth"]}'

        r = requests.get(url, auth=HTTPDigestAuth(self.username, self.password))

        if r.status_code != 200:
            raise http_exceptions.error_factory(r.status_code)

        data = r.json() 
        data["token"] = "123" # testing
        data["expires_in"] = "5" # testing
        if "token" in data.keys():
            token = data["token"]
            expires_in = int(data["expires_in"])
            return token, expires_in
        
        raise Exception("basic authentication failed to collect token")

    def authenticate(self) -> None:
        """Authenticate and set access token from server"""
        
        request_time = DateTime.now()

        # Avoid remote authentication if token has not expired
        if self.token_expiration is not None and request_time < self.token_expiration:
            return

        if self.auth_type == "basic-auth":
            self.token, expires_in = self.basic_auth()
            self.token_expiration = request_time + TimeDelta(seconds = expires_in) 
        elif self.auth_type == "digest-auth":
            self.token, expires_in = self.digest_auth() 
            self.token_expiration = request_time + TimeDelta(seconds = expires_in) 
        else:
            raise ValueError(f'authentication type {self.auth_type} not supported')

        self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
                    
    def get_value(self, key_value_pairs: dict[str, str]) -> dict[str, any]:
        """Get values from API by key, value"""
        self.authenticate()

        url = f'{self.base_url}{endpoint_extensions["get-value"]}'
        query = "?"
        for key, value in key_value_pairs.items():
            if len(query) == 1:
                query += f'{key}={value}'
            else:
                query += f'&{key}={value}'
        url += query

        r = requests.get(url,
                          headers=self.headers,
                          verify= not self.insecure)

        if r.status_code != 200:
            raise http_exceptions.error_factory(r.status_code)

        data = r.json() 
        
        return data["args"]



