import time
from flask import current_app
import datetime


def utc_now_ts():
    return int(time.time())
