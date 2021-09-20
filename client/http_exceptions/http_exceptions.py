"""Collection of HTTP error Exceptions"""

class BaseHTTPError(Exception):
    def __init__(self, message=None, payload=None):
        Exception.__init__(self)
        if message is not None:
            self.message = message
        else:
            self.message = self.default_message

        self.payload = payload

    def to_dict(self):
        """Returns JSON-encoded representation of the error"""
        payload = dict(self.payload or ()) 
        payload["message"] = self.message
        payload["code"] = self.code
        return payload

class BadRequestError(BaseHTTPError):
    code = 400 
    default_message = 'Bad Request'

class UnauthorisedError(BaseHTTPError):
    code = 401
    default_message = 'Access unauthorised'

class NotFoundError(BaseHTTPError):
    code = 404 
    default_message = 'Resource not found'

class NotFoundError(BaseHTTPError):
    code = 500 
    default_message = 'Internal Server Error'

def error_factory(error_code):
    """Returns a HTTP error corresponding to the error code."""
    if type(error_code) != int:
        raise Exception(f'invalid HTTP error code type {type(error_code)}')

    if error_code == 400:
        return BadRequestError
    elif error_code == 401:
        return UnauthorisedError
    elif error_code == 404:
        return NotFoundError
    elif error_code == 500:
        return NotFoundError
    else:
        raise Exception(f'error code {error_code} not implemented')


