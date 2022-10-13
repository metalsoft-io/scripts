#!/bin/python

import requests
import os
import sys
import hmac
import hashlib
import json


METALCLOUD_ENDPOINT = os.environ.get("METALCLOUD_ENDPOINT")
METALCLOUD_VERIFY_SSL = os.environ.get("METALCLOUD_VERIFY_SSL", True)
METALCLOUD_API_KEY = os.environ.get("METALCLOUD_API_KEY")


if METALCLOUD_ENDPOINT==None or METALCLOUD_ENDPOINT=="": 
    sys.exit("METALCLOUD_ENDPOINT environment variable not set. The format should not include the /api/developer/developer and only the prefix, same as the CLI.")

if METALCLOUD_API_KEY==None or METALCLOUD_API_KEY=="": 
    sys.exit("METALCLOUD_API_KEY environment variable not set.")


def make_api_call(method, params=[], endpoint=METALCLOUD_ENDPOINT, api_key=METALCLOUD_API_KEY, verify_ssl=METALCLOUD_VERIFY_SSL):
    if endpoint==None or api_key==None:
        raise "endpoint or api_key parameters are required"
    call_params_bytes = json.dumps({"id": 0, "jsonrpc": "2.0", "method": method, "params": params}).encode()
    url = "{}/{}?verify={}:{}".format(endpoint,"/api/developer/developer", api_key.split(":")[0], hmac.new(api_key.encode(), call_params_bytes, hashlib.md5).hexdigest())
    r = requests.post(url, data = call_params_bytes, verify=verify_ssl)
    if r.status_code!=200:
        raise Exception("API call failed:"+r.text)
    return r.json()['result']

USER_ID = METALCLOUD_API_KEY.split(":")[0]


def infrastructures(user_id):
    ret = make_api_call("infrastructures",[user_id])
    return ret

print(json.dumps(infrastructures(USER_ID)))