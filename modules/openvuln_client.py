import requests
import json
import os

import pdb

from modules.filter import Filter
from datetime import datetime,timedelta

class OpenVulnClient():
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
            elif self.authorization_token['access_token'] == None or datetime.now() > self.authorization_token['expires_at']:
                self.authenticate()
            if headers == None:
                headers = {'Accept' : 'application/json', 'Authorization' : f'Bearer {self.authorization_token["access_token"]}'}
            response = request(self, uri, headers, params)
            if int(response.status_code) == 200:
                return response
            elif int(response.status_code) == 429:
                #Rate Limiting
                #time.sleep(int(response.headers["Retry-After"]))
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
        params = {'client_id':os.environ.get('CLIENT_ID'), 'client_secret' : os.environ.get('SECRET_KEY'), 'grant_type' : 'client_credentials'}
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
        filter = Filter(parameters)
        return filter

    def retrieve_advisories(self, filter):
        response = self.get(uri)
        return
        
    def retrieve_all_advisories(self, filter):
        #Handle Filter
        
        #All advisories
        ##uri = https://apix.cisco.com/security/advisories/v2/all
        #All within Date Range
        ##query string: firstpublished?startDate=2023-01-01&endDate=2023-02-02
        #Last updated within Date Range
        ##query string: lastpublished?startDate=2023-01-01&endDate=2023-02-02
        #All advisories within a given year
        ##https://apix.cisco.com/security/advisories/v2/year/2023
        #Advisories with a given SIR rating
        ##https://apix.cisco.com/security/advisories/v2/severity/Critical
        #Combining impact score and date range
        ##https://apix.cisco.com/security/advisories/v2/severity/Critical/firstpublished?startDate=2023-01-01&endDate=2023-03-03
        #Latest x advisories
        ##https://apix.cisco.com/security/advisories/v2/latest/5
        
        if filter == None:
            uri = 'https://apix.cisco.com/security/advisories/v2/all'
        
        response = self.get(uri)        
        return

    def retrieve_advisory_by_identifiers(self, advisory_identifier=None, cve_identifier=None, bug_identifier=None):
        #Retrieve advisory by advisory identifier
        ##uri = https://apix.cisco.com/security/advisories/v2/advisory/cisco-sa-ipp-oobwrite-8cMF5r7U
        #Retrieve based on CVE identifier
        ##https://apix.cisco.com/security/advisories/v2/cve/CVE-2022-20968
        #Retrieve based on bug identifier
        ##https://apix.cisco.com/security/advisories/v2/bugid/CSCwb28354
        return

    def retrieve_advisory_by_product(self, filter):
        #Retrieve based on Cisco product names used with Security Advisory publication
        ##https://sec.cloudapps.cisco.com/security/center/productBoxData.x?prodType=CISCO
        #Retrieve via product
        ##https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20IOS%20XR
        return

    def retrieve_advisory_by_software(self, filter):
        #Retrieve the versions of software which exist in 'Cisco Software Checker'
        ##https://apix.cisco.com/security/advisories/v2/OS_version/OS_data?OSType=ios
        #Retrieve the platform names that exist in Cisco Software Checker
        ##https://apix.cisco.com/security/advisories/v2/platforms?OSType=nxos
        #Retrieve all advisories impacting a specific version of IOS
        ##https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.2.1
        ##https://apix.cisco.com/security/advisories/v2/OSType/asa?version=9.16.1
        #Target a specific platform
        ##https://apix.cisco.com/security/advisories/v2/OSType/asa?version=9.16.1&platformAlias=ASAV
        #specific platform and specific advisory ID
        ##https://apix.cisco.com/security/advisories/v2/OSType/asa?version=9.16.1&platformAlias=ASAV&advisoryId=cisco-sa-asaftdios-dhcpv6-cli-Zf3zTv
        return