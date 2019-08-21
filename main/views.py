# (C) Copyright 2019 Hewlett Packard Enterprise Development LP.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#  http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# __author__ = "@netwookie"
# __credits__ = ["Rick Kauffman"]
# __license__ = "Apache2.0"
# __version__ = "1.0.0"
# __maintainer__ = "Rick Kauffman"
# __email__ = "rick.a.kauffman@hpe.com"

from flask import Blueprint, render_template, request, redirect, session, url_for, abort
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



main_app = Blueprint('main_app', __name__)

@main_app.route('/main', methods=('GET', 'POST'))
@main_app.route('/', methods=('GET', 'POST'))
@main_app.route('/index', methods=('GET', 'POST'))
def main():
    ''' Display login screen
    '''

    return render_template('main/login.html')

@main_app.route('/help', methods=('GET', 'POST'))
def help():

    return render_template('main/help.html')

@main_app.route('/main_select', methods=('GET', 'POST'))
def main_select():
    '''
    read creds
    '''

    #import cfm_api_utils as c
    ipaddress = request.form['ipaddress']
    user = request.form['user']
    password = request.form['password']

    ipaddress=ipaddress.encode('utf-8')
    user=user.encode('utf-8')
    password=password.encode('utf-8')

    # Build database entry to save creds
    creds = Creds(user=user,password=password,ipaddress=ipaddress)
    # Save the record
    try:
        creds.save()
    except:
        error="ERR001 - Failed to save login credentials"
        return render_template('main/dberror.html', error=error)

    # Setting up URLs and default header parameters
    root_url='https://'+ipaddress+':8000'
    login_url=root_url+'/v1/session/login'
    who_am_i_url=root_url+'/v1/session/who-am-i'
    version_url=root_url+'/v1/version'
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


    # Authenticate to controller
    post_data = {'username': user, 'password': password}

    resp = requests.post(login_url,
                  data=json.dumps(post_data),
                  headers=default_header,
                  verify=False)

    resp_data = json.loads(resp.text)
    # Get the bearer token
    default_header['Authorization'] = 'Bearer ' + resp_data['bearer_token']

    # Get Identity
    resp = requests.get(who_am_i_url,
                  headers=default_header,
                  verify=False)

    identity=(json.loads(resp.text))

    # Get VErsion
    resp = requests.get(version_url,
                  headers=default_header,
                  verify=False)

    version=(json.loads(resp.text))

    # Get cluster nodes
    resp = requests.get(nodes_url,
                  headers=default_header,
                  verify=False)

    nodes=(json.loads(resp.text))


    #  TODO  replace with proper rest calls
    rc = RestClient(ipaddress,8000)
    rc.login(user,password)
    #
    stats=rc.fs.read_fs_stats()
    total_bytes=stats['total_size_bytes']
    free_size=stats['free_size_bytes']
    block_size_bytes=stats['block_size_bytes']


    return render_template('main/index.html', total_bytes=total_bytes,
                                              free_size=free_size,
                                              block_size_bytes=block_size_bytes,
                                              identity=identity,
                                              version=version,
                                              nodes=nodes)

@main_app.route('/main_return', methods=('GET', 'POST'))
def main_return():
    # Get user informaation
    creds = Creds.objects.first()
    user = creds.user
    password = creds.password
    ipaddress= creds.ipaddress

    # Setting up URLs and default header parameters
    root_url='https://'+ipaddress+':8000'
    login_url=root_url+'/v1/session/login'
    who_am_i_url=root_url+'/v1/session/who-am-i'
    version_url=root_url+'/v1/version'
    nodes_url=root_url+'/v1/cluster/nodes/'
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

    # Get Identity
    resp = requests.get(who_am_i_url,
                  headers=default_header,
                  verify=False)

    identity=(json.loads(resp.text))

    # Get VErsion
    resp = requests.get(version_url,
                  headers=default_header,
                  verify=False)

    version=(json.loads(resp.text))

    # Get cluster nodes
    resp = requests.get(nodes_url,
                  headers=default_header,
                  verify=False)

    nodes=(json.loads(resp.text))


    #  TODO  replace with proper rest calls
    rc = RestClient(ipaddress,8000)
    rc.login(user,password)
    #
    stats=rc.fs.read_fs_stats()
    total_bytes=stats['total_size_bytes']
    free_size=stats['free_size_bytes']
    block_size_bytes=stats['block_size_bytes']


    return render_template('main/index.html', total_bytes=total_bytes,
                                              free_size=free_size,
                                              block_size_bytes=block_size_bytes,
                                              identity=identity,
                                              version=version,
                                              nodes=nodes)


@main_app.route('/charts', methods=('GET', 'POST'))
def charts():
    '''
    Display Charts
    '''
    return render_template('main/charts.html')

@main_app.route('/maps', methods=('GET', 'POST'))
def maps():
    '''
    Display Maps
    '''
    return render_template('main/maps.html')

@main_app.route('/users', methods=('GET', 'POST'))
def users():
    '''
    Manage Users
    '''
    return render_template('main/manage-users.html')

@main_app.route('/preferences', methods=('GET', 'POST'))
def preferences():
    '''
    Manage Preferences
    '''
    return render_template('main/preferences.html')

@main_app.route('/logout', methods=('GET', 'POST'))
def logout():
    '''
    Logout of system
    '''
    return render_template('main/logout.html')

@main_app.route('/timestamps', methods=('GET', 'POST'))
def timestamps():
    '''
    Get Qumulo Timestamps
    '''

    # Get user informaation
    creds = Creds.objects.first()
    user = creds.user
    password = creds.password
    ipaddress= creds.ipaddress

    columns = ["iops.read.rate", "iops.write.rate",
               "throughput.read.rate", "throughput.write.rate",
               "reclaim.deferred.rate", "reclaim.snapshot.rate"]

    #
    feed = []
    rc = RestClient(ipaddress,8000)
    rc.login(user,password)
    #
    begin_time = int(time.time()) - 60 * 60 * 24
    results = rc.analytics.time_series_get(begin_time = begin_time)
    data = {}
    #
    for i in range(0,len(results[0]['times'])-1):
        ts = results[0]['times'][i]
        data[ts] = [None] * len(columns)

    for series in results:
        if series['id'] not in columns:
            continue
        for i in range(0,len(series['values'])):
            ts = series['times'][i]
            data[ts][columns.index(series['id'])] = series['values'][i]

    for key in data.items():
        tmp=[key[0],key[1][0],key[1][1],key[1][2],key[1][3],key[1][4],key[1][5]]
        if key[1][0] == 0.0 and key[1][1] == 0.0 and key[1][2] == 0.0 and key[1][3] == 0.0 and key[1][4] == 0.0 and key[1][5] == 0.0:
            continue
        feed.append(tmp)



    return render_template('main/index.sm.html', feed=feed)
