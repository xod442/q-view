import os
from werkzeug import secure_filename
from mongoengine import Q
import json
import requests
from main.models import Creds
import time
from collections import OrderedDict
from qumulo.rest_client import RestClient
requests.packages.urllib3.disable_warnings()

ipaddress='172.18.28.114'
root_url='https://'+ipaddress+':8000'
user='admin'
password='plexxi'
nodes_url=root_url+'/v1/cluster/nodes/'
login_url=root_url+'/v1/session/login'
version_url=root_url+'/v1/version'
default_header = {'content-type': 'application/json'}
# Authenticate to controller
post_data = {'username': user, 'password': password}

resp = requests.post(login_url,
              data=json.dumps(post_data),
              headers=default_header,
              verify=False)

resp_data = json.loads(resp.text)
# Get the bearer token
default_header['Authorization'] = 'Bearer ' + resp_data['bearer_token']
print 'hello'
# Get cluster nodes
resp = requests.get(nodes_url,
              headers=default_header,
              verify=False)

nodes=(json.loads(resp.text))

print nodes
