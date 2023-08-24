import requests
import json
import os

import pdb

from modules.filter import Filter
from datetime import datetime, timedelta


class OpenVulnClient:
    def __init__(self, client_args):
        self.base_url = 'https://apix.cisco.com/security/advisories/v2/'
        self.auth_token = None
        self.last_authenticated = None
        self.client_args = client_args
        self.authorization_token = {
            'token_type' : None,
            'expires_at' : None,
            'access_token' : None,
            'scope' : None
        }
        self.proxies = None
    
    def send_request(request):
        def send(self, uri, headers=None, params=None):
            if request.__name__ == 'post':
                response = request(self, uri, headers, params)
            elif self.authorization_token['access_token'] is None or datetime.now() > self.authorization_token['expires_at']:
                self.authenticate()
            if headers is None:
                headers = {'Accept' : 'application/json', 'Authorization' : f'Bearer {self.authorization_token["access_token"]}'}
            response = request(self, uri, headers, params)
            if int(response.status_code) == 200:
                return response
            elif int(response.status_code) == 429:
                # Rate Limiting
                # time.sleep(int(response.headers["Retry-After"]))
                print('Exceeded rate limit')
            elif int(response.status_code) > 500:
                print(f'Status Code : {response.status_code}\nMessage: {response.text}')
                print('Quitting...')
                quit()
            else:
                print(f'Status Code : {response.status_code}\nMessage: {response.text}')
        return send

    @send_request
    def post(self, uri, headers, params):
        return requests.post(uri, headers=headers, params=params, proxies=self.proxies, cookies=None)

    @send_request
    def get(self, uri, headers, params):
        print(f'Get uri {uri}')
        return requests.get(uri, headers=headers, params=params, proxies=self.proxies, cookies=None)

    def authenticate(self, *args, **kwargs):
        uri = 'https://id.cisco.com/oauth2/default/v1/token'
        headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
        params = {'client_id' : os.environ.get('CLIENT_ID'), 'client_secret' : os.environ.get('SECRET_KEY'), 'grant_type' : 'client_credentials'}
        response = self.post(uri, headers, params)
        try:
            response_token = json.loads(response.text)
        except Exception:
            pdb.set_trace()
        self.authorization_token['token_type'] = response_token['token_type']
        self.authorization_token['expires_at'] = datetime.now() + timedelta(seconds=response_token['expires_in'])
        self.authorization_token['access_token'] = response_token['access_token']
        self.authorization_token['scope'] = response_token['scope']
        print('End of authenticate method')
        print(self.authorization_token['access_token'])

    def construct_filter(self, parameters):
        filter = Filter(self.base_url)
        uri = filter.make_filter(parameters)
        return uri

    def retrieve_advisories(self, filter):
        uri = self.construct_filter(filter)
        response = self.get(uri)
        return response
