#!/bin/python
#Generates the capacity reports
#
#

from re import sub
import requests
import os
import sys
import hmac
import hashlib
import json
import smtplib, ssl

METALCLOUD_ENDPOINT = os.environ.get("METALCLOUD_ENDPOINT")
METALCLOUD_VERIFY_SSL = os.environ.get("METALCLOUD_VERIFY_SSL", True)
METALCLOUD_API_KEY = os.environ.get("METALCLOUD_API_KEY")

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = os.environ.get("SMTP_PORT", 465)
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

SMTP_SENDER_EMAIL = os.environ.get("SMTP_SENDER_EMAIL", "do-not-reply@metalsoft.io")
SMTP_RECEIVER_EMAIL = os.environ.get("SMTP_RECEIVER_EMAIL")
SMTP_SUBJECT="Issues detected"

if METALCLOUD_ENDPOINT==None or METALCLOUD_ENDPOINT=="": 
    sys.exit("METALCLOUD_ENDPOINT environment variable not set. The format should not include the /api/developer/developer and only the prefix, same as the CLI.")

if METALCLOUD_API_KEY==None or METALCLOUD_API_KEY=="": 
    sys.exit("METALCLOUD_API_KEY environment variable not set.")

if SMTP_USER==None or SMTP_USER=="": 
    sys.exit("SMTP_USER environment variable not set.")

if SMTP_PASSWORD==None or SMTP_PASSWORD=="": 
    sys.exit("SMTP_PASSWORD environment variable not set.")

if SMTP_RECEIVER_EMAIL==None or SMTP_RECEIVER_EMAIL=="": 
    sys.exit("SMTP_RECEIVER_EMAIL environment variable not set.")

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

def drives():
    ret = make_api_call("search",[
        USER_ID, 
        "*",
        ["_drives"],
        {"_drives":["drive_id","drive_array_id"]},
        "array_row_span",
        [["drive_id","DESC"]]
    ])
    return ret["_drives"]["rows"]

def drive_array_get(id):
    ret = make_api_call("drive_array_get",[id])
    return ret

def send_email(sender_email, receiver_email,subject, body):
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=ssl.create_default_context()) as server:
        server.login(SMTP_USER, SMTP_PASSWORD)
        message="From: {}\n".format(sender_email)
        message+="Subject: {}".format(subject)
        message+="\n{}\n".format(body)
        server.sendmail(sender_email, receiver_email, message)

def check_drive_array_io_limits():
    errors=[]
    for drive in drives():
            drive_array = drive_array_get(drive["drive_array_id"])
            if drive_array["drive_array_io_limit_policy"]==None:
                errors.append("Drive_array {} from infrastructure {} has no io_limit_policy configured!".format(drive_array["drive_array_id"], drive_array["infrastructure_id"]))
    return errors
            

def perform_checks_and_alert():
    errors=[]
    errors.extend(check_drive_array_io_limits())
    if len(errors)>0:
        
        message= "THIS IS AN AUTOMATED MESSAGE, DO NOT REPLY\n\n"
        message+="The following issues have been detected in environment {}:\n\n".format(METALCLOUD_ENDPOINT)
        message+="{}\n\n".format("\n".join(errors))

        send_email(SMTP_SENDER_EMAIL, SMTP_RECEIVER_EMAIL, SMTP_SUBJECT, message)

perform_checks_and_alert()