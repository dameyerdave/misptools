#!/usr/bin/env python3

import yaml
import requests
import uuid
import csv
import json
from datetime import datetime as dt
from pymongo import MongoClient
from pymongo.errors import BulkWriteError


class IOCReader:
    CONFIG_FILE = "config.yml"
    def __init__(self):
        self.read_config()
        mongo = MongoClient(self.config['mongo']['host'], self.config['mongo']['port'])
        self.db = mongo[self.config['mongo']['db']]
        self.col = self.db.iocs
    
    def read_config(self):
        with open(self.CONFIG_FILE) as cf:
           self.config = yaml.safe_load(cf)
    
    def create_ioc(self, feed, value, info, _type, timestamp, category, comment, _uuid, tags=[], to_ids=False):
        obj = {}
        obj['value'] = value
        obj['info'] = info
        obj['timestamp'] = dt.fromtimestamp(timestamp)
        obj['category'] = category
        obj['comment'] = comment
        obj['type'] = _type
        obj['uuid'] = _uuid
        obj['to_ids'] = to_ids
        obj['url'] = feed['url']
        obj['provider'] = feed['provider']
        obj['tags'] = tags
        return obj

    def process_feeds(self):
        for feed in self.config['feeds']:
            if 'disabled' in feed and feed['disabled'] == True:
                continue
            print("Processing feed '" + feed['name'] + "'...")
            if feed['format'] == 'misp':
                resp = requests.get(feed['url'] + '/manifest.json')
                self.process_misp_feed(resp, feed)
            elif feed['format'] == 'csv':
                resp = requests.get(feed['url'], stream=True)
                self.process_csv_feed(resp, feed)
   
    def process_misp_feed(self, resp, feed):
        iocs = []
        manifest = json.loads(resp.text)
        for key in manifest:
            evt_resp = requests.get(feed['url'] + '/' + key  + '.json')
            event = json.loads(evt_resp.text) 
            if 'Attribute' in event['Event']:
                for attr in event['Event']['Attribute']:
                    value = attr['value']
                    info = event['Event']['info']
                    tags = []
                    for tag in event['Event']['Tag']:
                        tags.append(tag['name'])
                    _type = attr['type']
                    timestamp = attr['timestamp']
                    timestamp = self.convert_timestamp(timestamp, feed)
                    category = attr['category']
                    comment = attr['comment']
                    _uuid = attr['uuid']
                    to_ids = attr['to_ids']
                    ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags, to_ids)
                    iocs.append(ioc)
        self.load_to_mongo(iocs)

    def process_csv_feed(self, resp, feed):
        delimiter = feed['delimiter'] if 'delimiter' in feed else ','
        iocs = []
        for line in resp.text.splitlines():
            if line:
                if not line.startswith("#"):
                    fields = list(csv.reader([line], delimiter=delimiter))[0]
                    value = fields[feed['valuefield']] if 'valuefield' in feed else fields[0]
                    info = fields[feed['infofield']] if 'infofield' in feed else feed['info'] if 'info' in feed else feed['name']
                    _type = fields[feed['typefield']] if 'typefield' in feed else feed['type'] if 'type' in feed else 'unknown'
                    timestamp = fields[feed['timestampfield']] if 'timestampfield' in feed else dt.now().strftime('%s')
                    timestamp = self.convert_timestamp(timestamp, feed)
                    category = fields[feed['categoryfield']] if 'categoryfield' in feed else feed['category'] if 'category' in feed else 'unknown'
                    comment = fields[feed['commentfield']] if 'commentfield' in feed else feed['comment'] if 'comment' in feed else 'unknown'
                    _uuid = str(uuid.uuid4())
                    tags = feed['tags'] if 'tags' in feed else []
                    ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags)
                    iocs.append(ioc)
        self.load_to_mongo(iocs)
    
    def convert_timestamp(self, timestamp, feed):
        if 'timestampformat' in feed:
            if feed['timestampformat'] == '%sN':
                timestamp = timestamp.split('.')[0]
            else:
                timestamp = dt.strftime(dt.strptime(timestamp, feed['timestampformat']), '%s')
        return int(timestamp)

    def load_to_mongo(self, iocs):
        bulk = self.col.initialize_ordered_bulk_op()
        for ioc in iocs:
            bulk.find({'value': ioc['value']}).upsert().replace_one(ioc)
        try:
            bulk.execute()
        except BulkWriteError as e:
            print(e)
            pass
         
def main():
    iocreader = IOCReader()
    iocreader.process_feeds()

if __name__ == "__main__":
    main()
