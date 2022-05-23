import argparse
from argparse import RawTextHelpFormatter
import requests
import urllib3
import json
import configparser
import pandas as pd
from tabulate import tabulate
import getpass

"""
FortiGate Device List Report Creator.
Written 23rd May 2022.

This tool was written to produce a CSV output of devices identified by a FortiGate.

The tool relies on manual input of FortiGate details.

It will prompt for the following credentials:
    address=<FortiGate address>
    api_key=<FortiGate API key>
    port=<FortiGate HTTPS port>

It will use a series of API calls to each FortiGate to gather the necessary information, which can be a very large amount on larger installations.

Once completed it will output the results of the analysis to the screen, and save the results to a CSV file: fgt_device_list.csv
"""

urllib3.disable_warnings()
payload={}
headers = {}
fortigates = []
csv_name = 'fgt_device_list.csv'

def get_fortigate_details():
    """
    This function is used to prompt the user for the FortiGate details.
    """
    print('')
    print('-----------------------------------------')
    print('| Please provide FortiGate credentials. |')
    print('-----------------------------------------')
    fortigate_input = input('Enter FortiGate IP/FQDN address: ')
    api_input = getpass.getpass('Enter FortiGate API key: ')
    port_input = input('Enter FortiGate HTTPS port: ')
    fortigates.append({'address': fortigate_input, 'api_key': api_input, 'port': port_input})
    print('-----------------------------------------')
    print('')

def get_device_list(address, token, port):
    """
    This function is used to pull the device list from the FortiGate. The list is then returned.
    """
    device_url = 'https://' + address + ':' + port + '/api/v2/monitor/user/device/query?access_token=' + token
    try:
        device_response = json.loads(requests.request("GET", device_url, headers=headers, data=payload, verify=False).text)['results']
    except Exception as e:
        print(e)
    return device_response

def collect_config():
    """
    This function calls the FortiGate and returns the device list.
    """
    fgt_device_output = []
    for x in fortigates:
        try:
            fgt_device_details = get_device_list(x['address'], x['api_key'], port=x['port'])
        except Exception as e:
            print(e)
    return fgt_device_details

def create_output(fgt_device_output):
    """
    This function takes the results of all the FortiGates from collect_config, and converts the output to a dataframe so it can be exported to a CSV file.

    It then outputs a table for each FortiGate whether the feature is enabled or not, and the same table in a CSV file called 'fgt_device_list.csv'.
    """
    print('-----------------------------------')
    print('|     FortiGate Device Report     |')
    print('-----------------------------------')
    print('')
    print('Number of devices identified by FortiGate: ' + str(len(fgt_device_output)))
    print('')
    fg_df = pd.DataFrame(fgt_device_output).fillna('')
    print(tabulate((fg_df.iloc[:,0:9]), showindex=False, headers=fg_df.columns[:10]))
    fg_df.to_csv(csv_name, index=False)
    print('')
    print('Device list saved to ' + csv_name)
    print('')

def main():
    """
    The main function that calls all the functions.
    """
    parser = argparse.ArgumentParser(description='\033[1;37;40mFortiGate Device List Report Creator.\n\033[1;34;40mWritten 23rd May 2022.\n\n\033[1;36;40mThis tool was written to produce a CSV output of devices identified by a FortiGate.\n\nThe tool relies on manual input of FortiGate details.\n\nIt will prompt for the following credentials:\n\033[1;33;40m    address=<FortiGate address>\n    api_key=<FortiGate API key>\n    port=<FortiGate HTTPS port>\033[1;36;40m\n\nIt will use a series of API calls to each FortiGate to gather the necessary information, which can be a very large amount on larger installations.\n\nOnce completed it will output the results of the analysis to the screen, and save the results to a CSV file: fgt_device_list.csv \033[0;0m', formatter_class=RawTextHelpFormatter)
    args = parser.parse_args()
    get_fortigate_details()
    fgt_devices = collect_config()
    create_output(fgt_devices)

if __name__=="__main__":
    main()
