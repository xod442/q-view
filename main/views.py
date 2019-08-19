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
    # ipaddress = request.form['ipaddress']
    # user = request.form['user']
    # password = request.form['password']


    return render_template('main/index.html')

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
    Manage Preferences
    '''
    return render_template('main/logout.html')
