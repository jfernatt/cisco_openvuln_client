import requests
import argparse
import json

import pdb

from modules.openvuln_client import OpenVulnClient
from modules.filter import Filter

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
    filter = Filter(client_args)
    #handle user input
        #single query
        #read report and query against contents
    #query client
    #format data / generate report
    #return data to user
    #errors
    #logging
    
    
    #Testing
    #oclient.authenticate()
    #oclient.retrieve_all_advisories(None)
    test_query_1 = {'scope': 'all'}
    # filter = oclient.construct_filter(test_query_1)
    filter1 = Filter(test_query_1)
    query_string1 = filter1.make_filter()
    print(query_string1)


    test_query_2 = {'scope': 'all', 'params' : {'severity' : 'high'}}
    # filter = oclient.construct_filter(test_query_1)
    filter2 = Filter(test_query_2)
    query_string2 = filter2.make_filter()
    print(query_string2)

    test_query_3 = {'scope': 'all', 'params' : {'severity' : 'high', 'firstpublished' : {'startDate' : '2020-12-03', 'endDate' : '2022-12-03'}}}
    # filter = oclient.construct_filter(test_query_1)
    filter3 = Filter(test_query_3)
    query_string3 = filter3.make_filter()
    print(query_string3)


    return

if __name__ == '__main__':
    main()