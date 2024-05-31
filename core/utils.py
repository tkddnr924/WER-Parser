import os
from glob import glob
from typing import List
import datetime
from tzlocal import get_localzone

def get_report_file(file_path: str) -> List:
    result = []
    for root, dirs, files in os.walk(file_path):
        result.extend(glob(os.path.join(root, '*.wer')))
    
    return result

def date_from_webkit(webkit_timestamp):
    epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    delta = datetime.timedelta(microseconds=int(webkit_timestamp) / 10)
    time = (epoch_start + delta).astimezone(get_localzone())

    return time.strftime("%Y-%m-%d %H:%M:%S.%f %Z")

def sort_event_time(obj):
    return obj.event_time_readable

def sort_program_name(obj):
    return obj.program_name