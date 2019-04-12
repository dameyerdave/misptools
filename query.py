#! /usr/bin/env python3

import pymisp
import logging
import json
import warnings
import argparse
import configparser
import re, math
from datetime import datetime as dt, timedelta as td
import pprint
import traceback


warnings.filterwarnings("ignore")

config = configparser.ConfigParser()
config.read('config.ini')

SEP = '|'
SEVERITY=['n/a','informational','low','medium','high','critical']

def datebefore(days):
    now = dt.now()
    return (now - td(days=days)).replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%d')

def yesterday():
    return datebefore(1)

def today():
    return datebefore(0)

parser = argparse.ArgumentParser(description='Query the MISP plattform.')
parser.add_argument('-c', '--controller', dest='controller', type=str, default='attributes', help='The controller to use', choices=['attributes', 'events'])
parser.add_argument('-t', '--type', dest='type', type=str, default=None, help='The attribute type to query', choices=['ip-src', 'ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256', 'link'])
parser.add_argument('-o', '--org', dest='org', type=str, default=None, help='The organization to query')
parser.add_argument('-l', '--last', dest='last', type=str, default=None, help='Only show events publishe in the last n<timeinterval>')
parser.add_argument('--day-range', dest='day_range', type=int, default=None, help='Sets date-from to now - n days')
parser.add_argument('--date-from', dest='date_from', type=str, default=yesterday(), help='From this date on, only if --day-range is not set')
parser.add_argument('--date-to', dest='date_to', type=str, default=today(), help='Up to this date, only if --day-range is not set')
parser.add_argument('--tags', dest='tags', type=str, default=None, help='Tags to search for')
parser.add_argument('--not-tags', dest='not_tags', type=str, default=None, help='Tags not to search for')
parser.add_argument('--eventid', dest='eventid', type=str, default=None, help='The eventid to search for')
parser.add_argument('--out-key', dest='out_keys', type=str, nargs='+', default=config['output']['keys'].split(','), help='The keys to output')
parser.add_argument('--out-sep', dest='out_sep', type=str, default=config['output']['separator'], help='The separator for the output of multiple keys')
parser.add_argument('--idx-col', dest='idx_col', type=str, default=config['output']['idxcol'], help='The index column (should be value)')
parser.add_argument('--max-cols', dest='max_cols', type=str, default=config['output']['maxcols'].split(','), help='Cols where we store the max value')
parser.add_argument('--mv-cols', dest='mv_cols', type=str, default=config['output']['mvcols'].split(','), help='Cols where we store multi values separated by ' + SEP)
parser.add_argument('--mv-dist-cols', dest='mv_dist_cols', type=str, default=config['output']['mvdistcols'].split(','), help='Cols where we store distinct multi values separated by ' + SEP)
parser.add_argument('--comment-fields', dest='comment_fields', type=str, default=config['output']['commentfields'].split(','), help='Fields to extract from key-value paires in the comment field')
parser.add_argument('--severity-boost-tags', dest='severity_boost_tags', type=str, default=config['output']['severityboosttags'].split(','), help='Tags to boost severity')
parser.add_argument('--tags-field', dest='tags_field', type=str, default=config['output']['tagsfield'], help='The field where tags as stored')
parser.add_argument('--tags-to-category', dest='tags_to_category', type=str, default=config['output']['tagstocategory'].split(','), help='List of regular expressions in tags to match a category')
parser.add_argument('--tags-to-severity', dest='tags_to_severity', type=str, default=config['output']['tagstoseverity'].split(','), help='List of regular expressions in tags to match a severity')
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

try:
    misp = pymisp.PyMISP(url=config['MISP']['proto'] + '://' + config['MISP']['host'] + ':' + config['MISP']['port'], key=config['MISP']['token'], ssl=False)
    resp = misp.search(controller=args.controller, type_attribute=args.type, org=args.org, last=args.last, date_from=args.date_from, date_to=args.date_to, tags=args.tags, not_tags=args.not_tags, eventid=args.eventid)
    idxcol = args.idx_col

    events = {}

    if args.controller == 'attributes':
        if 'response' in resp and 'Attribute' in resp['response']:
            scores = {}
            rows = {}
            for attr in resp['response']['Attribute']:
                if not attr['event_id'] in events:
                    event = misp.get_event(attr['event_id'])
                    event = event['Event']
                    del event['Attribute']
                    del event['ShadowAttribute']
                    del event['RelatedEvent']
                    del event['Galaxy']
                    del event['Object']
                    events[attr['event_id']] = event
                attr['Event'] = events[attr['event_id']]
                obj = {}
                if args.out_keys[0] == '*':
                    obj = attr
                else:
                    for _key in args.out_keys:
                        if 'AS' in _key:
                            parts = _key.split(' AS ')
                            _key = parts[0]
                            _keyname = parts[1]
                        else:
                            _keyname = _key.replace('.', '_')
                        if '.' in _key:
                            _subkeys = _key.split('.')
                            _attr=attr[_subkeys[0]]
                            for _subkey in _subkeys[1:]:
                                if _subkey in _attr:
                                    if isinstance(_attr[_subkey], list):
                                        val = ''
                                        for elt in _attr[_subkey]:
                                            if val:
                                                val += SEP
                                            val += elt[_subkeys[-1]]
                                        _attr = val
                                        break
                                    else:
                                        _attr=_attr[_subkey]
                                else:
                                    # if key is not part of attribute
                                    _attr = ''
                                    break
                            obj[_keyname] = _attr
                        else:
                            obj[_keyname] = attr[_key]
                if 'comment' in attr:
                    for field in args.comment_fields:
                        if 'AS' in field:
                            parts = field.split(' AS ')
                            field = parts[0]
                            fieldname = parts[1]
                        else:
                            fieldname = field
                        match = re.search(field + r'=(.+?)(\t|$)', attr['comment'])
                        if match:
                            obj[fieldname] = match.group(1)
                if not obj[idxcol] in rows:
                    obj['_count'] = 1
                    rows[obj[idxcol]] = obj
                else:
                    for maxcol in args.max_cols:
                        if maxcol in obj:
                            if maxcol in rows[obj[idxcol]]:
                                rows[obj[idxcol]][maxcol] = max(rows[obj[idxcol]][maxcol], obj[maxcol])
                    for mvcol in args.mv_cols:
                        if mvcol in obj:
                            if mvcol in rows[obj[idxcol]]:
                                rows[obj[idxcol]][mvcol] += SEP + obj[mvcol]
                            else:
                                rows[obj[idxcol]][mvcol] = obj[mvcol]
                    for mvdistcol in args.mv_dist_cols:
                        if mvdistcol in obj:
                            if mvdistcol in rows[obj[idxcol]]:
                                vals = rows[obj[idxcol]][mvdistcol].split(SEP)
                                if not obj[mvdistcol] in vals:
                                    if rows[obj[idxcol]][mvdistcol]:
                                        rows[obj[idxcol]][mvdistcol] += SEP + obj[mvdistcol]
                                    else:
                                        rows[obj[idxcol]][mvdistcol] = obj[mvdistcol]
                    rows[obj[idxcol]]['_count'] = rows[obj[idxcol]]['_count'] + 1
            for _,row in rows.items():
                # tags to category
                for regex in args.tags_to_category:
                    if args.tags_field in row:
                        if isinstance(row[args.tags_field], str):
                            match = re.search(regex, row[args.tags_field])
                            if match:
                                row['category'] = match.group(1)
                                break
                # Severity
                for regex in args.tags_to_severity:
                    if args.tags_field in row:
                        if isinstance(row[args.tags_field], str):
                            match = re.search(regex, str(row[args.tags_field]))
                            if match:
                                row['severity'] = match.group(1)
                                break
                if not 'severity' in row:
                    ind1 = int(row['_count'] / 10 * 5 + 1)
                    # remove _count key because its only used for severity calculation
                    del row['_count']
                    if 'popularity' in row:
                        ind2 = int(row['popularity'])
                    else:
                        ind2 = 3
                    boost = 1
                    if args.tags_field in row:
                        for tag in args.severity_boost_tags:
                            if tag in row[args.tags_field]:
                                boost += 0.2
                    row['severity'] = SEVERITY[min(math.ceil((ind1 + ind2) / 2 * boost), 5)]
                # Harmonizing
                if 'category' in row:
                    row['category'] = row['category'].lower()
                if 'severity' in row:
                    row['severity'] = row['severity'].lower()
                # Lookup
                for section in config.sections():
                    if section.startswith('lookup:'):
                        parts = section.split(':')
                        field = parts[1]
                        if field in row:
                            lookup = dict(config.items(section))
                            for key in lookup:
                                if key == row[field]:
                                    row[field] = lookup[key]
                # Output
                print(json.dumps(row))
except Exception as e:
    print(str(e))
    print(traceback.format_exc())
    with open('log.txt', 'a') as f:
        f.write(str(e))
        f.write(traceback.format_exc())
