import requests
import argparse
import json
import csv

import pdb

from modules.openvuln_client import OpenVulnClient
from modules.filter import Filter
from modules.tests import tests

base_url = 'https://apix.cisco.com/security/advisories/v2'

def interactive_query(oclient):
    filter = Filter(base_url)
    while True:
        selection = input(
            '1: Get all Product IDs\n'\
            '2: Query by product\n'\
            '3: Query Platforms by NOS\n'\
            '4: Query by software ID\n'\
            '5: Query by severity\n'\
            '6: Query by year\n'\
            '7: Query by latest {x}\n'\
            '8: Query by identifier\n'\
            '9: Query specific vulnerability\n'\
            'Type \'exit\' to quit\n'
        )
        if selection == 'exit':
            quit()
        elif selection == '1':
            query_params = {'scope': 'by_product', 'params': {'product_ids': 'all'}}
            response = json.loads(oclient.retrieve_advisories(query_params).text)
        elif selection == '2':
            nos = input('Enter network operating system to query\n')
        else:
            continue
        print(json.dumps(response, indent=2))
        pdb.set_trace()

def get_client_args():
    parser = argparse.ArgumentParser(
        prog='Cisco OpenVuln API Client',
        description='Queries Cisco OpenVuln API to generate a report of published vulnerabilities affecting software '
                    'and hardware')
    parser.add_argument('--dotenv_file', help='Location of .env file with client_id and client_secret')
    parser.add_argument('--inventory_filename', help='Location of input file with each OS and Hardware to check '
                                                     'against OpenVuln API')
    parser.add_argument('--wait_on_ratelimit', help='True: wait for "Retry-After" Value when rate limited by API. '
                                                    'False: exit program when rate limited', default=False)
    parser.add_argument('--verbose')
    parser.add_argument('--output_filename')
    return parser.parse_args()


def query_by_inventory_file():
    global csv_file
    csv_file = parse_inventory()
    [print(i) for i in csv_file]
    vuln_queries = sort_vuln_queries(csv_file)
    print(json.dumps(vuln_queries, indent=2))
    filter = Filter(base_url)

    vuln_query_results = {}

    oclient = OpenVulnClient(client_args)
    oclient.authenticate()

    for nos in vuln_queries.keys():
        vuln_query_results[nos] = {'versions' : {}}
        try:
            [vuln_query_results[nos]['versions'].update({i: j}) for i,j in vuln_queries[nos].items()]
        except Exception as e:
            print(e)
            print('ERROR APPENDING NOS VERSIONS TO vuln_query_results')
            pdb.set_trace()
        vuln_query_results[nos]['invalid_nos'] = False
        if nos in filter.nos_w_platform_types:
            vuln_query_results[nos]['queriable_by_platform'] = True
            query_params = {'scope': 'by_software', 'params': {'platforms': nos}}
            response = oclient.retrieve_advisories(query_params)
            if response.status_code is not 200:
                print('Error retrieving platforms')
                pdb.set_trace()
            valid_platform_names = json.loads(response.text)
            vuln_query_results[nos]['valid_platform_names'] = valid_platform_names
            vuln_query_results[nos]['valid_platform_aliases'] = [i['platformAlias'] for i in valid_platform_names]
        elif nos in filter.nos_types:
            vuln_query_results[nos]['queriable_by_platform'] = False
        else:
            vuln_query_results[nos]['invalid_nos'] = True

    #pdb.set_trace()
    for nos in vuln_query_results:
        for version in vuln_query_results[nos]['versions']:
            if vuln_query_results[nos]['invalid_nos']:
                vuln_query_results[nos][version]['all_platforms'] = f'Invalid NOS, Valid Queriable NOS Options: {[i for i in vuln_query_results[nos]["versions"]]}'
            elif vuln_query_results[nos]['queriable_by_platform'] == False:
                query_params = {'scope': 'by_software', 'params': {'nos' : nos, 'version' : version}}
                try:
                    vuln_query_results[nos]['versions'][version].append({'all_platforms' : json.loads(oclient.retrieve_advisories(query_params).text)})
                except Exception as e:
                    print(e)
                    print(f'Failed to query nos {nos} version {version}')
                    pdb.set_trace()
            else:
                print(f'Ready to query platforms running {nos} version {version}')
                platforms = [i for i in vuln_query_results[nos]['versions'][version]]
                for platform in platforms:
                    if platform in vuln_query_results[nos]['valid_platform_aliases']:
                        print(f'Run query for {nos}, {version}, {platform}')
                        query_params = {'scope': 'by_software', 'params': {'nos' : nos, 'version' : version, 'platform' : platform}}
                        response = oclient.retrieve_advisories(query_params)
                        if response.status_code == 200:
                            print('Query done')
                            findings = json.loads(response.text)
                            vuln_query_results[nos]['versions'][version].remove(platform)
                            vuln_query_results[nos]['versions'][version].append({platform: findings})
                        else:
                            print(f'Query Error: {response.status_code}')
                            print(f'{response.text}')
                            vuln_query_results[nos]['versions'][version].remove(platform)
                            vuln_query_results[nos]['versions'][version].append({platform: f'Unable to complete query: {response.text}'})
                    else:
                        vuln_query_results[nos]['versions'][version].remove(platform)
                        vuln_query_results[nos]['versions'][version].append({platform: f'Invalid Platform Name {platform}. Valid platform names: {[i for i in vuln_query_results[nos]["valid_platform_aliases"]]}'})
    print(json.dumps(vuln_query_results,indent=2))
    with open('output.json', 'w') as file:
        file.write(json.dumps(vuln_query_results,indent=2))


    '''
    for nos, items in query_w_platform.items():
        for version, platforms in items.items():
            for platform in platforms:
                if platform in [i['platformAlias'] for i in valid_platform_names[nos]]:
                    query_params = {'scope': 'by_software',
                                    'params': {'nos': nos, 'version': version, 'platform': platform}}
                    findings = json.loads(oclient.retrieve_advisories(query_params).text)
                    ###CANT JUST APPEND TEXT, NEED TO TIE TO NOS, VERSION, PLATFORM
                    #results.update({nos : {'version' : version, 'platform' : platform, 'findings' : findings}})
                    #Update dict in this format:
                    # {"asa": {"9.12.4.41": ["ASA5500X"], "9.12.4.52": ["ASA 5545"]}, "ftd": {"7.2.4": ["Firepower 4100"], "6.4.0.14": ["Firepower 8140"]}, "fxos": {"2.12.1.129.": ["FCM"], "2.12.0.450.": ["FCM"]}}
                    pdb.set_trace()
                    print('break here')
                else:
                    query_wout_platform.update({nos : vuln_queries[nos]})
                    print(f'{platform} is not a valid platform for NOS: \'{nos}\'...\nValid platforms follow: ')
                    print(json.dumps(valid_platform_names[nos], indent=2))
                    pdb.set_trace()

    # each OS, determine if queriable with platform
    # query each OS / version that can't be queried with platform
    # Query each OS / version / platform that can be
    # Compare each line in csv_file with query_results to build report
    # write report
    '''
    return vuln_query_results

def parse_version(version):
    return version.replace('(', '.').replace(')', '.').strip('.')

def parse_inventory():
    inventory_contents = []
    required_fields = set(['Site', 'Location', 'Name', 'Platform', 'NOS', 'Version'])
    with open(client_args.inventory_filename, 'r') as f:
        csv_file = csv.DictReader(f, delimiter=',', dialect='unix')
        contained_fields = set([i.strip() for i in csv_file.fieldnames])
        if len(required_fields - contained_fields) == 0:
            for line in csv_file:
                new_Version = parse_version(line['Version'])
                line['Version'] = new_Version
                inventory_contents.append(line)
        else:
            print('Error parsing CSV file')
            print(f'CSV requires fields: {required_fields}')
            quit()
    return inventory_contents


def sort_vuln_queries(csv_file):
    # Minimize queries to REST API
    # Sort by NOS > Version > Platform
    vuln_queries = {}
    for row in csv_file:
        try:
            if row['NOS'] not in vuln_queries.keys():
                vuln_queries[row['NOS'].strip()] = {row['Version'].strip() : []}
            if row['Version'].strip() not in vuln_queries[row['NOS']].keys():
                vuln_queries[row['NOS']].update({row['Version'].strip() : [row['Platform'].strip()]})
            if row['Platform'].strip() not in vuln_queries[row['NOS']][row['Version']]:
                vuln_queries[row['NOS']][row['Version']].append(row['Platform'].strip())
        except Exception as e:
            print(e)
            print('Error sorting vuln queries')
    return vuln_queries

def output_csv(vuln_query_results):
    print('Writing file...')
    csv_header = [i for i in csv_file[0].keys()]
    csv_header.extend(['advisoryTitle','cves','cvssBaseScore','lastUpdated','publicationUrl'])
    csv_header = ','.join(csv_header)
    output_csv_rows = []
    output_csv_rows.append(csv_header)
    for row in csv_file:
        print(f' {row}')
        if vuln_query_results[row['NOS']]['versions'].get(row['Version']):
            version_platforms = []
            for platform in vuln_query_results[row['NOS']]['versions'].get(row['Version']):
                try:
                    for key,value in platform.items():
                        version_platforms.append(key)
                except Exception as e:
                    continue
            if row['Platform'] in version_platforms:
                print('row Platform found')
                platforms = vuln_query_results[row['NOS']]['versions'][row['Version']]
                for platform in platforms:
                    if row['Platform'] in platform.keys():
                        if 'Unable to complete query' in platform[row['Platform']]:
                            error_dict = json.loads(platform[row['Platform']].replace('Unable to complete query: ', ''))
                            advisories = [{'advisoryTitle' : error_dict['errorMessage'], 'cves' : ' ', 'cvssBaseScore': ' ', 'lastUpdated' : ' ', 'publicationUrl' : ' '}]
                        elif 'Invalid Platform Name' in platform[row['Platform']]:
                            error = platform[row['Platform']].replace(',', ' ')
                            advisories = [{'advisoryTitle': error, 'cves': ' ', 'cvssBaseScore': ' ', 'lastUpdated': ' ', 'publicationUrl': ' '}]
                        elif type(platform[row['Platform']]) == dict and platform[row['Platform']].get('advisories'):
                            advisories = platform[row['Platform']]['advisories']
                        else:
                            pdb.set_trace()

                        for advisory in advisories:
                            new_row = [i for i in row.values()]
                            new_row.extend([advisory['advisoryTitle'].replace(',',''),' '.join([i for i in advisory['cves']]),advisory['cvssBaseScore'],advisory['lastUpdated'],advisory['publicationUrl']])
                            new_row = ','.join(new_row)
                            output_csv_rows.append(new_row)
            else:
                print('row Platform not found')
                try:
                    platforms = vuln_query_results[row['NOS']]['versions'][row['Version']]
                except Exception as e:
                    print('Can\'t get platforms')
                    print(e)
                    pdb.set_trace()
                for platform in platforms:
                    if type(platform) is dict:
                        if 'all_platforms' in platform.keys():
                            if 'Unable to complete query' in platform['all_platforms']:
                                error_dict = json.loads(platform['all_platforms'].replace('Unable to complete query: ', ''))
                                advisories = [{'advisoryTitle' : error_dict['errorMessage'], 'cves' : ' ', 'cvssBaseScore': ' ', 'lastUpdated' : ' ', 'publicationUrl' : ' '}]
                            elif 'Invalid Platform Name' in platform['all_platforms']:
                                error = platform['all_platforms'].replace(',', ' ')
                                advisories = [{'advisoryTitle': error, 'cves': ' ', 'cvssBaseScore': ' ', 'lastUpdated': ' ', 'publicationUrl': ' '}]
                            elif type(platform['all_platforms']) == dict and platform['all_platforms'].get('advisories'):
                                advisories = platform['all_platforms']['advisories']
                            elif type(platform['all_platforms']) == dict:
                                advisories = [{'advisoryTitle': platform['all_platforms'].get('errorMessage'), 'cves': ' ', 'cvssBaseScore': ' ', 'lastUpdated': ' ','publicationUrl': ' '}]
                            else:
                                print('Error getting advisories')
                                pdb.set_trace()

                        for advisory in advisories:
                            new_row = [i for i in row.values()]
                            new_row.extend([advisory['advisoryTitle'].replace(',',''),' '.join([i for i in advisory['cves']]),advisory['cvssBaseScore'],advisory['lastUpdated'],advisory['publicationUrl']])
                            new_row = ','.join(new_row)
                            output_csv_rows.append(new_row)
        else:
            print('row Version not found in vuln_query_results')
            pdb.set_trace()
    #pdb.set_trace()
    with open('output.csv', 'w') as file:
        file.write('\r\n'.join(output_csv_rows))
    pdb.set_trace()


def main():
    global client_args
    client_args = get_client_args()
    
    #all_versions_of_fxos
    query_params = {'scope': 'by_software', 'params': {'sw_versions' : 'fxos'}}
    oclient = OpenVulnClient(client_args)
    oclient.authenticate()
    versions = oclient.retrieve_advisories(query_params)

    if client_args.inventory_filename:
        vuln_query_results = query_by_inventory_file()

    if client_args.output_filename:
        output_csv(vuln_query_results)

    oclient = OpenVulnClient(client_args)
    #interactive_query(oclient)
    # handle user input
    # single query
    # read report and query against contents
    # query client
    # format data / generate report
    # return data to user
    # errors
    # logging
    # Testing
    # oclient.authenticate()
    # oclient.retrieve_all_advisories(None)
    tests()
    pdb.set_trace()
    oclient.authenticate()
    asa_platforms = oclient.retrieve_advisories({'scope': 'by_software', 'params': {'platforms' : 'asa'}})
    test_asa_advisories = oclient.retrieve_advisories({'scope': 'by_software', 'params': {'nos' : 'asa', 'version' : '9.16.1'}})
    test_ftd_advisories = oclient.retrieve_advisories({'scope': 'by_software', 'params': {'nos': 'ftd', 'version': '7.0.4'}})
    all_product_ids = oclient.retrieve_advisories({'scope': 'by_product', 'params': {'product_ids' : 'all'}})
    pdb.set_trace()
    asa_platforms_json = json.loads(asa_platforms.text)
    asa_advisories_json = json.loads(test_asa_advisories.text)
    ftd_advisories_json = json.loads(test_ftd_advisories.text)
    product_ids_json = json.loads(all_product_ids.text)
    pdb.set_trace()


if __name__ == '__main__':
    main()
