import base64
from hashlib import sha256
from settings import settings
import os
import logging
import urllib
#import jwt
from authlib.jose import jwt
import time
import uuid
import requests
import json

# Enable logging
if (settings.log_level == "DEBUG"):
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=logging.DEBUG)
elif (settings.log_level == "INFO"):
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=logging.INFO)
else:
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=logging.WARN)

logger = logging.getLogger(__name__)

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
        self.token = None
    
    def getState(self):
        return self.state
    
    def getNonce(self):
        return self.nonce

    def getVerifier(self):
        return self.code_verifier
    
    def setToken(self, token):
        self.token = token

    def generateVerifierChallengePair(self):
        verifier = self.generate_random_string(32)
        logging.debug("Verifier: " + verifier.decode("utf-8"))
        code_challenge = base64.urlsafe_b64encode(sha256(verifier).digest()).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")
        logging.debug("Code challenge: " + code_challenge.decode("utf-8"))
        return verifier.decode("utf-8") , code_challenge.decode("utf-8") 

    def generate_random_string(self, length):
        randomBytes = os.urandom(length)
        return base64.urlsafe_b64encode(randomBytes).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")

    def get_auth_url(self):
        logging.debug("Generating auth URL")
        self.code_verifier, self.code_challenge = self.generateVerifierChallengePair()
        full_auth_url = self.auth_url + "?client_id=" + self.client_id + "&scope=" + \
            urllib.parse.quote(self.scope) + "&response_type=" + self.response_type + \
                "&redirect_uri=" + urllib.parse.quote_plus(self.redirect_uri) + "&state=" + self.state + \
                    "&nonce=" + self.nonce + "&code_challenge=" + self.code_challenge + \
                    "&code_challenge_method=" + self.code_challenge_method 
        logging.debug("Auth URL: " + full_auth_url)
        return full_auth_url, self.code_verifier
    
    # Generate a JWT token from the client certificate
    def generate_jwt(self, client_certificate):
        # Generate a JWT token
        logging.debug("Generating JWT token")
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
        }, key=secret, header = {'alg': 'RS256'})#algorithm='HS256')
        logging.debug("JWT token: " + jwt_token.decode("utf-8"))
        return jwt_token

    def get_token(self, client_certificate, code):
        # Generate a JWT token
        jwt_token = self.generate_jwt(client_certificate)

        # Get the token
        logging.debug("Getting token")
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': self.code_verifier,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': jwt_token.decode("utf-8")
        }
        response = requests.post(self.token_url, headers=headers, data=data)
        if response.status_code == 200:
            self.token = response.json()
            logging.debug("Token: " + self.token["access_token"])
            return self.token
        else:
            logging.error("Error getting token: " + response.text)
            return None

    def getAccountsAndBalances(self):
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
        return self.runGraphQLQuery(query)

    def runGraphQLQuery(self, query):
        if self.token is None:
            logging.error("No token available")
            return None
        else:
            logging.debug("Getting bank accounts")
            headers = {
                'Authorization': 'Bearer ' + self.token,
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
    stitch = Stitch(settings.stitch_client_id, settings.stitch_redirect_uri)
    url, verifier = stitch.get_auth_url()
    code = input("Code:")
    token = stitch.get_token(settings.stitch_client_certificate, code)
    accounts = stitch.getAccountsAndBalances
    logger.info("Accounts: " + str(accounts))

if __name__ == "__main__":
    main()