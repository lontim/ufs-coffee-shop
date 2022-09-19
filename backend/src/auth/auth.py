import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'tim-eu.eu.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'latte'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError(
            {
                "code": "authorization_header_missing",
                "description": "Authorisation header is missing"
            }, 401)
    auth_section = auth.split()
    if auth_section[0] != "Bearer": # auth header has no Bearer prefix
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Authorisation header needs to include Bearer prefix"
            }, 401)
    elif len(auth_section) == 1:   # auth header has only one section
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Token missing in authorisation header"
            }, 401)
    elif len(auth_section) > 2:   # auth header has too many sections
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Authorisation header has too many sections"
            }, 401)

    token = auth_section[1]
    return token

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    permissions = payload.get('permissions')
    if (permission in permissions):
        print (str(permission) + " in " + str(permissions))
        return True
    else:
        raise AuthError(
                {
                    'code': 'invalid_permissions',
                    'description': 'User doesn\'t have permission.'
                }, 401)

'''
implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    jsonURL = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jsonWebKeySet = json.loads(jsonURL.read())
    unverified_token_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_token_header:
        raise AuthError(
            {
                'code': 'invalid_token',
                'description': 'Token does not contain a Key ID (kid) and so cannot be verified.'
            }, 401)
    for key in jsonWebKeySet['keys']:
        if key['kid'] == unverified_token_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n':   key['n'],
                'e':   key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(token,
                                 rsa_key,
                                 algorithms=ALGORITHMS,
                                 audience=API_AUDIENCE,
                                 issuer='https://' + AUTH0_DOMAIN + '/')

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError(
                {
                    'code': 'token_expired',
                    'description': 'The token has expired and can no longer be used.'
                }, 401)

        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    'code': 'invalid_token',
                    'description': 'There is a problem with the claims.'
                }, 401)
        except Exception:
            raise AuthError(
                {
                    'code': 'invalid_token',
                    'description': 'Unable to parse authentication token.'
                }, 400)

'''
implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decorator