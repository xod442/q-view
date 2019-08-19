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
import pygal
import json

# Place to stach the user temporarily
from database.temp import Temp
from database.sidekick import Sidekick
from database.number import Number
from database.switches import Switches
from pygal.style import LightGreenStyle
from pyhpecfm.auth import CFMClient
from pyhpecfm import fabric

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
    #import cfm_api_utils as c
    ipaddress = request.form['ipaddress']
    user = request.form['user']
    passwd = request.form['passwd']


    return render_template('main/index.html')

@main_app.route('/charts', methods=('GET', 'POST'))
def charts():



    return render_template('main/charts.html')




@main_app.route('/main_return', methods=('GET', 'POST'))
def main_return():
    # Get user informaation
    creds = Sidekick.objects.first()
    user = creds.user
    ipaddress= creds.ipaddress

    # Insert chart data

    try:
        from pygal.style import DarkSolarizedStyle
        g1 = pygal.StackedLine(fill=True, interpolate='cubic', style=DarkSolarizedStyle)
        g1.add('A', [1, 3,  5, 16, 13, 3,  7])
        g1.add('B', [5, 2,  3,  2,  5, 7, 17])
        g1.add('C', [6, 10, 9,  7,  3, 1,  0])
        g1.add('D', [2,  3, 5,  9, 12, 9,  5])
        g1.add('E', [7,  4, 2,  1,  2, 10, 0])
        g1_data = g1.render_data_uri()
    except Exception, e:
		return(str(e))

    try:
        line_chart = pygal.HorizontalBar()
        line_chart.title = 'Browser usage in February 2012 (in %)'
        line_chart.add('IE', 19.5)
        line_chart.add('Firefox', 36.6)
        line_chart.add('Chrome', 36.3)
        line_chart.add('Safari', 4.5)
        line_chart.add('Opera', 2.3)
        line_chart.render()
        g2_data = line_chart.render_data_uri()
    except Exception, e:
		return(str(e))

    # Get switch information switch database
    switch_array = []
    for s in Switches.objects():
        # assigne local variables
        health = s.health
        ip_address = s.ip_address
        mac_address = s.mac_address
        name = s.name
        sw_version = s.sw_version
        # Creat a list for the record entry
        out=[health, ip_address, mac_address, name, sw_version]
        # Make a list of Lists
        switch_array.append(out)

    return render_template('main/sidekick1.html', u=user, i=ipaddress, g1_data=g1_data, g2_data=g2_data, s = switch_array)

@main_app.route('/main_logout', methods=('GET', 'POST'))
def main_logout():
    # Clear sidekick creds database for log information.
    Sidekick.objects().delete()
    # Dump the switches database
    Switches.objects().delete()


    return render_template('main/logout.html')

@main_app.route('/main_tdb', methods=('GET', 'POST'))
def main_tdb():

    # Get switch information switch database
    switch_array = []
    for s in Switches.objects():
        # assigne local variables
        health = s.health
        ip_address = s.ip_address
        mac_address = s.mac_address
        name = s.name
        sw_version = s.sw_version
        # Creat a list for the record entry
        out=[health, ip_address, mac_address, name, sw_version]
        # Make a list of Lists
        switch_array.append(out)

    return render_template('main/tdb.html', s=switch_array)
