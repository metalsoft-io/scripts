#!/bin/python
#Generates the capacity reports
#
#

import requests
import os
import sys
import csv
from datetime import datetime


METALSOFT_API_ENDPOINT = os.environ.get("METALSOFT_API_ENDPOINT")
METALSOFT_USERNAME = os.environ.get("METALSOFT_USERNAME")
METALSOFT_PASSWORD = os.environ.get("METALSOFT_PASSWORD")

if METALSOFT_USERNAME==None or METALSOFT_PASSWORD==None:
    sys.exit("Empty username or password. Set METALSOFT_USERNAME and METALSOFT_PASSWORD environment variables and try again. Note using {} as default endpoint. Use METALSOFT_API_ENDPOINT environment variable to configure another endpoint.".format(METALSOFT_API_ENDPOINT))
  

def make_api_call(method, params=[]):
    call_params = {"id": None, "jsonrpc": "2.0", "method": method, "params": params}
    r = requests.post(METALSOFT_API_ENDPOINT,auth=(METALSOFT_USERNAME, METALSOFT_PASSWORD), json = call_params, verify=False)
    if r.status_code!=200:
        raise Exception("API call failed:"+r.text)
    return r.json()['result']

def get_datacenters():
    datacenters =  make_api_call("datacenters")
    return list(datacenters.keys())

def get_storage_pools():
    return make_api_call("storage_pools") 

def get_server_type_utilization_report(datacenter):
    results =  make_api_call("servers_type_utilization_report",["server_type_name",datacenter])
    report={}
    for k,entry in results.items():
        report[k]={
            "available" : sum([ entry[s]['server_count'] for s in ['available','cleaning','cleaning_required']]),
            "used" :  sum([ entry[s]['server_count'] for s in ['used','used_registering']]),
            "defective" :sum([ entry[s]['server_count'] for s in ['defective','removed_from_rack']]),
            "other_states" : sum([ entry[s]['server_count'] for s in ['registering','unavailable','updating_firmware','used_diagnostics','available_reserved']]),
        }
    return report

def get_servers_report():
    report=[]
    for dc in get_datacenters():
        for k,st in get_server_type_utilization_report(dc).items():
            report.append({
                'datacenter':dc,
                'server_type':k,
                'available':st['available'],
                'used':st['used'],
                'defective':st['defective'],
                'other_states':st['other_states']
            })
    return report

def get_storage_report():
    report = []
    for k,s in get_storage_pools().items():
        report.append({
            'datacenter':s['datacenter_name'],
            'storage_pool_id':s['storage_pool_id'],
            'storage_pool_name':s['storage_pool_name'],
            'storage_pool_iscsi_host':s['storage_pool_iscsi_host'],
            'total_gbytes':s['storage_pool_capacity_total_cached_real_mbytes']/1000,
            'usable_gbytes':s['storage_pool_capacity_usable_cached_real_mbytes']/1000,
            'free_gbytes':s['storage_pool_capacity_free_cached_real_mbytes']/1000,
            'used_virtual_gbytes':s['storage_pool_capacity_used_cached_virtual_mbytes']/1000,
        })
    return report

def generate_report_csv(report, fname):
    with open(fname, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, fieldnames=report[0].keys())
        writer.writeheader()
        for row in report:
            writer.writerow(row)


def generate_all_reports():

    today =  datetime.now().strftime("%Y-%m-%d")
    
    generate_report_csv(get_servers_report(),"servers-{}.csv".format(today))
    generate_report_csv(get_storage_report(),"storage-{}.csv".format(today))

generate_all_reports()
