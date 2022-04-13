import base64
from hashlib import sha256
from settings import settings
import os
import logging
import urllib
import jwt
import time
import uuid
import requests
import json
import collections
import sys
from datetime import datetime, timedelta
import webbrowser
import http.server
import socketserver
import threading

# Enable logging
logger = logging.getLogger(__name__)
if (settings.log_level == "DEBUG"):
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.setLevel(logging.DEBUG)
elif (settings.log_level == "INFO"):
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.setLevel(logging.INFO)
else:
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.setLevel(logging.WARNING)

class Stitch:
    def __init__(self, client_id, redirect_uri):
        self.client_id = client_id
        self.scope = "openid offline_access accounts transactions balances"
        self.response_type = "code"
        self.state = self.generate_random_string(32).decode("utf-8") 
        self.code_challenge_method="S256"
        self.redirect_uri = redirect_uri
        self.nonce = self.generate_random_string(32).decode("utf-8") 
        self.auth_url = "https://secure.stitch.money/connect/authorize"
        self.token_url = "https://secure.stitch.money/connect/token"
        self.code_challenge = None
        self.code_verifier = None
        self.access_token = None
        self.id_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.scope_granted = None

    def generate_verifier_challenge_pair(self):
        verifier = self.generate_random_string(32)
        logger.debug("Verifier: " + verifier.decode("utf-8"))
        code_challenge = base64.urlsafe_b64encode(sha256(verifier).digest()).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")
        logger.debug("Code challenge: " + code_challenge.decode("utf-8"))
        return verifier.decode("utf-8") , code_challenge.decode("utf-8") 

    def generate_random_string(self, length):
        randomBytes = os.urandom(length)
        return base64.urlsafe_b64encode(randomBytes).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")

    def get_auth_url(self):
        logger.debug("Generating auth URL")
        self.code_verifier, self.code_challenge = self.generate_verifier_challenge_pair()
        full_auth_url = self.auth_url + "?client_id=" + self.client_id + "&scope=" + \
            urllib.parse.quote(self.scope) + "&response_type=" + self.response_type + \
                "&redirect_uri=" + urllib.parse.quote_plus(self.redirect_uri) + "&state=" + self.state + \
                    "&nonce=" + self.nonce + "&code_challenge=" + self.code_challenge + \
                    "&code_challenge_method=" + self.code_challenge_method 
        logger.debug("Auth URL: " + full_auth_url)
        return full_auth_url, self.code_verifier
    
    # Generate a JWT token from the client certificate
    def generate_jwt(self, client_certificate):
        # Generate a JWT token
        logger.debug("Generating JWT token")
        secret = open(client_certificate,"r").read()
        now = int(time.time())
        one_hour_from_now = now + 3600

        jwt_token = jwt.encode(payload={
            'iss': self.client_id,
            'sub': self.client_id,
            'aud': self.token_url,
            'exp': one_hour_from_now,
            'iat': now,
            'nbf': now,
            'jti': str(uuid.uuid4())
        }, key=secret, algorithm='RS256')
        logger.debug("JWT token: " + jwt_token)
        return jwt_token
    
    def decode_jwt(self, jwt_token):
        # Decode the JWT token
        logger.debug("Decoding JWT token")
        secret = open(settings.client_certificate,"r").read()
        decoded_token = jwt.decode(jwt_token, secret, algorithms=['RS256'])
        logger.debug("Decoded JWT token: " + str(decoded_token))
        return decoded_token

    def get_access_token(self, client_certificate, auth_code):
        # Generate a JWT token
        jwt_token = self.generate_jwt(client_certificate)

        # Get the token
        logger.debug("Getting token")
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': self.code_verifier,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': jwt_token
        }
        response = requests.post(self.token_url, headers=headers, data=data)
        logger.debug("Token response: " + response.text)
        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
            self.refresh_token = response.json()["refresh_token"]
            self.id_token = response.json()["id_token"]
            # Calculate the actual token expiration time
            self.token_expires_at = datetime.now() + timedelta(seconds=int(response.json()["expires_in"]))
            self.scope_granted = response.json()["scope"]
            logger.debug("Token: " + self.access_token)
            return self.access_token
        else:
            logger.error("Error getting token: " + response.text)
            return None

    def get_accounts_balances(self, access_token=None):
        query =  """query ListBankAccounts {
                        user {
                            bankAccounts {
                                user {
                                    bankAccounts {
                                        name
                                        bankId
                                        accountType
                                        accountNumber
                                        currency
                                        currentBalance
                                        availableBalance
                                    }
                                }
                            }
                        }
                    }"""
        return self.run_graphQL_query(query, access_token=None)

    def run_graphQL_query(self, query, access_token=None):
        if self.access_token is None:
            logger.debug("No topen provided, checking if one was fetched already.")
            access_token = self.access_token
            if (access_token is None):
                logger.error("No access token available")
                return None
        logging.debug("Access token available, getting bank accounts")
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        # Call graphql endpoint
        response = requests.post("https://api.stitch.money/graphql", headers=headers, json={"query": query})
        if response.status_code == 200:
            return response.json()
        else:
            logging.error("Error getting bank accounts: " + response.text)
            return None
       
def main():
    arg_names = ['command','token']
    args = dict(zip(arg_names, sys.argv))
    Arg_list = collections.namedtuple('Arg_list', arg_names)
    args = Arg_list(*(args.get(arg, None) for arg in arg_names))
    
    #Run a local callback webserver in its own thread
    PORT = 9000
    Handler = http.server.SimpleHTTPRequestHandler
    # Keep the web server quiet - comment out if you want to see the requests
    Handler.log_message = lambda a, b, c, d, e: None
    httpd = socketserver.TCPServer(("", PORT), Handler)
    logger.info("serving at port", PORT)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    #Initialise a stitch client
    stitch = Stitch(settings.stitch_client_id, settings.stitch_redirect_uri)
    if args.token is None:
        url, verifier = stitch.get_auth_url()
        print("You will be directed to the following URL to get the auth code: " + url)
        webbrowser.open(url, new=0, autoraise=True)
        code = input("Code:")
        token = stitch.get_access_token(settings.stitch_client_certificate, code)
    else:
        token = args.token
        stitch.setToken(token)
        logger.debug("Token: " + token)
        logger.debug("JWT unpacked:" + stitch.decode_jwt(stitch.id_token))
    accounts = stitch.get_accounts_balances()
    logger.info("Accounts: " + str(accounts))

if __name__ == "__main__":
    main()
