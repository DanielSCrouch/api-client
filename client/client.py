import requests
from requests.api import head
from urllib3.exceptions import InsecureRequestWarning
from base64 import b64encode as Base64Encode
from hashlib import md5 as Md5Hash
from requests.auth import HTTPDigestAuth
from datetime import datetime as DateTime
from datetime import timedelta as TimeDelta
from typing import Tuple

import http_exceptions

default_connection_params = {

}

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

    def authenitcate(self) -> None:
        """Authenticate and retrieve access token from server"""

        request_time = DateTime.now()

        # Avoid remote authentication if token has not expired
        if not self.token_expiration or request_time < self.token_expiration:
            return

        if self.auth_type == "basic-auth":
            self.token, expires_in = self.basic_auth()
            self.token_expiration = request_time + TimeDelta(seconds = expires_in) 
        elif self.auth_type == "digest_auth":
            self.token, expires_in = self.digest_auth() 
            self.token_expiration = request_time + TimeDelta(seconds = expires_in) 

        self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
                    
    def get_value(self, key_value_pairs: dict[str, str]) -> dict[str, any]:
        """Get values from API by key, value"""
        self.authenitcate()

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



            
            
        
        print(url)

    


#     def get_vims(self):
#         """Get VIM instances from OSM"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s" % (self.addr, self.port, '/osm/admin/v1/vim_accounts')
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
        
#         r = requests.get(url, 
#                          headers=self.headers, 
#                          verify=False)
        
#         # Check for error status 
#         if r.status_code != 200:
#             raise AuthError("Failed to get VIMs") 

#         # Store token in object
#         data = r.content
#         data = data.decode("utf-8")

#         instances = yaml.safe_load(data)

#         return instances

#     def get_vim(self, name):
#         """Get VIM instance from OSM by name"""
#         self.authenticate()
#         instances = self.get_vims()
#         for vim in instances:
#             if vim["name"] == name:
#                 return vim
#         raise  VIMError("VIM with name %s not found" % name)

#     def get_vim_name(self, id):
#         """Get VIM instance name from ID from OSM"""
#         self.authenticate()
#         instances = self.get_vims()
#         for vim in instances:
#             if vim["_id"] == id:
#                 return vim["name"]
#         raise  VIMError("VIM with id %s not found" % id)

#     def get_vnf_instances(self):
#         """Get VNF instances from OSM"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s" % (self.addr, self.port, '/osm/nslcm/v1/vnf_instances')
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
        
#         r = requests.get(url, 
#                          headers=self.headers, 
#                          verify=False)
        
#         # Check for error status 
#         if r.status_code != 200:
#             raise AuthError("Failed to get VNF instances") 

#         # Store token in object
#         data = r.content
#         data = data.decode("utf-8")

#         instances = yaml.safe_load(data)

#         return instances

#     def get_vnf_instance(self, id):
#         """Get VNF instance from OSM"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s/%s" % (self.addr, self.port, '/osm/nslcm/v1/vnf_instances', id)
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
        
#         r = requests.get(url, 
#                          headers=self.headers, 
#                          verify=False)

#         # Check for error status 
#         if r.status_code != 200:
#             raise AuthError("Failed to get VNF instance %s" % id) 

#         # Store token in object
#         data = r.content
#         data = data.decode("utf-8")

#         instances = yaml.safe_load(data)

#         return instances

#     def get_ns_instances(self):
#         """Get NS instances from OSM"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s" % (self.addr, self.port, '/osm/nslcm/v1/ns_instances')
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
        
#         r = requests.get(url, 
#                          headers=self.headers, 
#                          verify=False)
        
#         # Check for error status 
#         if r.status_code != 200:
#             raise AuthError("Failed to get NS instances") 

#         # Store token in object
#         data = r.content
#         data = data.decode("utf-8")

#         instances = yaml.safe_load(data)

#         return instances

#     def get_ns_instance(self, id):
#         """Get VNF instance from OSM"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s/%s" % (self.addr, self.port, '/osm/nslcm/v1/ns_instances', id)
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
        
#         r = requests.get(url, 
#                          headers=self.headers, 
#                          verify=False)
        
#         # Check for error status 
#         if r.status_code != 200:
#             raise AuthError("Failed to get NS instance %s" % id) 

#         # Store token in object
#         data = r.content
#         data = data.decode("utf-8")

#         instances = yaml.safe_load(data)

#         return instances

#     def get_ns_instance_vim(self, id):
#         """Get NS instances assigned VIM from OSM"""
#         response = self.get_ns_instance(id) 
#         return response["instantiate_params"]["vimAccountId"]

#     def deploy_vm(self, ns_name, nsd_id, vim_id, new_vnf_def):
#         """Deploy virtual machine with OpenStack""" 
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         # url = "https://%s:%s%s" % (self.addr, self.port, '/osm/nslcm/v1/ns_instances/')
#         url = "https://%s:%s%s" % (self.addr, self.port, '/osm/nslcm/v1/ns_instances_content/')
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
#         lcmOperationType = "string"
#         nsDescription = "Azure site"
#         payload = {"nsName": ns_name, "nsdId": nsd_id, "vimAccountId": vim_id, "lcmOperationType": lcmOperationType, "nsInstanceId": nsd_id, "nsDescription": nsDescription}
#         if new_vnf_def != None:
#             payload["vnf"] = new_vnf_def
#         else:
#             print("Failed to load vnf definition", file=sys.stderr)

#         payload_str = json.dumps(payload)

#         r = requests.post(url,
#                         #   json=payload,
#                           data=payload_str,
#                           headers=self.headers,
#                           verify=False)

#         # Check for error status 
#         if r.status_code != 201:
#             print(r.content, file=sys.stderr)
#             raise VMError("Failed to deploy VM " + str(r.status_code))

#         # Retrieve VM (NS instance) ID
#         data = r.content
#         data = data.decode("utf-8")

#         self.ns_id = json.loads(data)["id"]      
#         return self.ns_id

#     def start_vm(self, ns_id, ns_name, vim_id): 
#         """Start previously created virtual machine"""
#         self.authenticate()
#         requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#         url = "https://%s:%s%s" % (self.addr, self.port, '/osm/nslcm/v1/ns_instances/{}/instantiate'.format(ns_id))
#         self.headers["Authorization"] = "Bearer {token}".format(token = self.token)
#         payload = {"nsName": ns_name, "nsdId": ns_id, "vimAccountId": vim_id}

#         r = requests.post(url,
#                           json=payload,
#                           headers=self.headers,
#                           verify=False)

#         # Check for error status 
#         if r.status_code != 202:
#             print(r.content) 
#             raise VMError("Failed to start VM " + str(r.status_code))

#         # Retrieve VM (NS instance) ID
#         data = r.content
#         data = data.decode("utf-8")

#         self.occurrence_id = json.loads(data)["id"]      

#         return self.occurrence_id


# # Resources
# # https://osm.etsi.org/docs/user-guide/12-osm-nbi.html
# # https://forge.etsi.org/swagger/ui/?url=https%3A%2F%2Fosm.etsi.org%2Fgitweb%2F%3Fp%3Dosm%2FSOL005.git%3Ba%3Dblob_plain%3Bf%3Dosm-openapi.yaml%3Bhb%3DHEAD#/NS_instances/addNSinstance