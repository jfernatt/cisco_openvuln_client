import requests
import argparse
import json

from modules.openvuln_client import OpenVulnClient

def get_client_args():
    parser = argparse.ArgumentParser(
        prog = 'Cisco OpenVuln API Client',
        description = 'Queries Cisco OpenVuln API to generate a report of published vulnerabilities affecting software and hardware')
    parser.add_argument('--dotenv_file', help = 'Location of .env file with client_id and client_secret')
    parser.add_argument('--inventory_filename', help = 'Location of input file with each OS and Harware to check against OpenVuln API')
    parser.add_argument('--wait_on_ratelimit', help = 'True: wait for "Retry-After" Value when rate limited by API. False: exit program when rate limited', default=False)
    parser.add_argument('--verbose')
    parser.add_argument('--output_filename')
    return parser.parse_args()

def main():
    #handle arguments and options
    client_args = get_client_args()
    #instantiate client
    oclient = OpenVulnClient(client_args)
    #handle user input
    #query client
    #format data / generate report
    #return data to user
    #errors
    #logging
    
    
    #Testing
    oclient.authenticate()
    return

if __name__ == '__main__':
    main()