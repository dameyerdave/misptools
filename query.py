#! /usr/bin/env python3

import pymisp
import logging
import json
import warnings
import argparse
import configparser
from datetime import datetime as dt, timedelta as td

warnings.filterwarnings("ignore")

config = configparser.ConfigParser()
config.read('config.ini')

def datebefore(days):
    now = dt.now()
    return (now - td(days=days)).replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%d')

def yesterday():
    return datebefore(1)

def today():
    return datebefore(0)

parser = argparse.ArgumentParser(description='Query the MISP plattform.')
parser.add_argument('-c', '--controller', dest='controller', type=str, default='attributes', help='The controller to use', choices=['attributes', 'events'])
parser.add_argument('-t', '--type', dest='type', type=str, default=None, help='The attribute type to query', choices=['ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256'])
parser.add_argument('-o', '--org', dest='org', type=str, default=None, help='The organization to query')
parser.add_argument('-l', '--last', dest='last', type=str, default=None, help='Only show events publishe in the last n<timeinterval>') 
parser.add_argument('--day-range', dest='day_range', type=int, default=None, help='Sets date-from to now - n days') 
parser.add_argument('--date-from', dest='date_from', type=str, default=yesterday(), help='From this date on, only if --day-range is not set') 
parser.add_argument('--date-to', dest='date_to', type=str, default=today(), help='Up to this date, only if --day-range is not set') 
parser.add_argument('--out-key', dest='out_keys', type=str, nargs='+', default=config['output']['keys'].split(','), help='The keys to output') 
parser.add_argument('--out-sep', dest='out_sep', type=str, default=config['output']['separator'], help='The separator for the output of multiple keys') 
args = parser.parse_args()

if args.day_range:
    args.date_from = datebefore(args.day_range)
    args.date_to = today()

logger = logging.getLogger('pymisp')
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)

def extract_value(_value, _key, _default=None):
    if _key == '':
        return ''
    subkeys = _key.split('.')
    value = _value[subkeys[0]]
    if not value is None:
        try:
            value = json.loads(value)
            for i in range(1, len(subkeys)):
                if subkeys[i] in value:
                    value = value[subkeys[i]]
                else:
                    break
        except ValueError as e:
            pass
    if value is None:
        value = _default if not _default is None else ''
    return value

misp = pymisp.api.PyMISP(url=config['MISP']['proto'] + '://' + config['MISP']['host'] + ':' + config['MISP']['port'], key=config['MISP']['token'], ssl=False)
resp = misp.search(controller=args.controller, type_attribute=args.type, org=args.org, last=args.last, date_from=args.date_from, date_to=args.date_to)

if args.controller == 'attributes':
    if 'response' in resp and 'Attribute' in resp['response']:
        scores = {}
        rows = {}
        for attr in resp['response']['Attribute']:
            columns = []
            for _key in args.out_keys:
                value = ''
                for _subkey in _key.split('+'):
                    if value != '':
                       value += ' ' 
                    value += str(extract_value(attr, _subkey, 'N/A'))
                columns.append(str(value))
            if columns[0] in scores:
                scores[columns[0]] += int(extract_value(attr, config['scoring']['key'], 1))
            else:
                scores[columns[0]] = int(extract_value(attr, config['scoring']['key'], 1))
                rows[columns[0]] = columns[1:]
        for key, row in rows.items():
            print(key + args.out_sep + str(scores[key]) + args.out_sep + args.out_sep.join(row))
