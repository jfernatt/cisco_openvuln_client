import requests
import json
import os

from datetime import datetime,timedelta

class OpenVulnClient():
    def __init__(self, client_args):
        self.name = 'test'
        self.base_url = None
        self.auth_token = None
        self.last_authenticated = None
        self.client_args = client_args
        self.authorization_token = {
            'token_type' : None,
            'expires_at' : None,
            'access_token' : None,
            'scope' : None
        }
    
    def api_post(target_uri, headers=None, params=None):
        def wrap(wrapped_post):
            def send_request(*args):
                print(f'My args: {target_uri}')
                response = requests.post(target_uri, headers=headers, params=params)
                if int(response.status_code) == 200:
                    print(response.status_code)
                    print(response.text)
                    wrapped_post(*args, response=response)
                elif int(response.status_code) == 429:
                    #Rate Limit Stuff
                    print('rate limit stuff')
                else:
                    print(f'Status Code: {response.status_code}\nMessage: {response.text}')
            return send_request
        return wrap

    def api_get(target_uri, headers=None, params=None):
        def wrap(wrapped_get):
            def send_request(*args):
                '''
                #if authz token age > maxage
                    re-authenticate
                #if response = 4xx
                    authenticate
                #if response = 429
                    handle rate limit
                #if response = anything else
                    throw error
                    
                #429 = rate limit exceeded (includes 'Retry-After' key in seconds)
                
                response = requests.request("GET", url, headers=headers)

                if response.status_code == 200:
                    # Success logic
                elif response.status_code == 429:
                    time.sleep(int(response.headers["Retry-After"]))
                else:
                    # Handle other response codes

                200 = OK
                400 = Bad Request
                401 = Unauthorized
                403 = Forbidden
                404 = Not Found
                406 = Not Acceptable
                429 = Rate Limit Exceeded
                500 = Internal Server Error
                503 = Service Unavailable
                
                headers = {
                    'Accept' : 'application/json',
                    'Authorization' : f'Bearer {self.authorization_token["access_token"]}'
                }
                '''
        return send_request

    @api_post(target_uri='https://id.cisco.com/oauth2/default/v1/token', headers={'Content-Type' : 'application/x-www-form-urlencoded'}, params={'client_id':os.environ.get('CLIENT_ID'), 'client_secret' : os.environ.get('SECRET_KEY'), 'grant_type' : 'client_credentials'})
    def authenticate(self, *args, **kwargs):
        #send credentials
        ##curl -s -k -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "client_id=deadbabebeef" -d "client_secret=deadbabebeef" -d "grant_type=client_credentials" https://id.cisco.com/oauth2/default/v1/token
        #Parse response
        #Set access token in client
        authentication_url = 'https://id.cisco.com/oauth2/default/v1/token'
        parameters = {
            'client_id' : os.environ.get('CLIENT_ID'),
            'client_secret' : os.environ.get('SECRET_KEY'),
            'grant_type' : 'client_credentials',
        }
        headers = {'Content-Type' : 'application/x-www-form-urlencoded'
        }

        #response = requests.post('https://id.cisco.com/oauth2/default/v1/token', params=parameters, headers=headers)
        #response = self.api_post('https://id.cisco.com/oauth2/default/v1/token', params=parameters, headers=headers)
        # response = self.api_post()
        '''
        if not int(response.status_code) == 200:
            print(f'Error: {response.status_code}\nMessage: {response.text}')
            self.authenticate()
        else:
            json_response = json.loads(response.text)
            self.authorization_token 
        '''
        
    # @app_get()
    def retrieve_all_advisories(self, filter):
        #uri = https://apix.cisco.com/security/advisories/v2/all
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
        return

    # @app.get()
    def retrieve_advisory_by_identifiers(self, advisory_identifier=None, cve_identifier=None, bug_identifier=None):
        #Retrieve advisory by advisory identifier
        ##uri = https://apix.cisco.com/security/advisories/v2/advisory/cisco-sa-ipp-oobwrite-8cMF5r7U
        #Retrieve based on CVE identifier
        ##https://apix.cisco.com/security/advisories/v2/cve/CVE-2022-20968
        #Retrieve based on bug identifier
        ##https://apix.cisco.com/security/advisories/v2/bugid/CSCwb28354
        return

    # @app.get()
    def retrieve_advisory_by_product(self, filter):
        #Retrieve based on Cisco product names used with Security Advisory publication
        ##https://sec.cloudapps.cisco.com/security/center/productBoxData.x?prodType=CISCO
        #Retrieve via product
        ##https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20IOS%20XR
        return

    # @app.get()
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

    # @app.get()
    def handle_error(self, response_code):
        #uri = 
        return