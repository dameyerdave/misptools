#!/usr/bin/env python3

import sys
import os
import yaml
import requests
import uuid
import csv
import json
import dateparser
import urllib.request
import re
import zipfile
from datetime import datetime as dt
from pymongo import MongoClient
from pymongo.errors import BulkWriteError
from contextlib import closing
from multiprocessing.dummy import Pool as ThreadPool

class KasperskyReader:
    def __init__(self, config):
        self.config = config
        if sys.version_info >= (2, 7, 9):
            # since 2.7.9 version Python perform certificate and hostname checks by default
            import ssl
            ctx = ssl._create_unverified_context()
            ctx.load_cert_chain(certfile=self.config['pemfile'])
            https_handler = urllib.request.HTTPSHandler(context=ctx)
        else:
            https_handler = urllib.request.HTTPSHandler()

        self.opener = urllib.request.build_opener(https_handler)

    def parse_filename(self, headers):
        if not 'content-disposition' in headers:
            filename = str(uuid.uuid4()) + ".zip"
            return filename
        return re.findall("filename=(\S+)", headers['content-disposition'])[0]

    def download_feed(self, feed_url):
        with closing(self.opener.open(feed_url)) as resp:
            if resp.getcode() != 200:
                raise Exception("Failed to download feed '{0}'".format(feed_url))

            result = json.loads(resp.read())
            package_url = result['updates'][0]['packages'][0]['link']

        with closing(self.opener.open(package_url)) as resp:
            if resp.getcode() != 200:
                raise Exception("Failed to download package from '{0}'".format(package_url))

            package_name = self.parse_filename(resp.headers)

            temp_file = os.path.join(self.config['tempdir'], package_name)
            with open(temp_file, 'wb') as feed_archive:
                feed_archive.write(resp.read())

            with closing(zipfile.ZipFile(temp_file, 'r')) as feed_zip:
                feed_zip.extractall(self.config['tempdir'])
                filename = os.path.join(self.config['tempdir'], feed_zip.namelist()[0])
            os.remove(temp_file)
            with open(filename) as f_in:
                ret = json.load(f_in)
            #os.remove(filename)
            return ret

class IOCReader:
    CONFIG_FILE = "config.yml"
    kasp_type_lookup = {
            1: 'domain', 
            2: 'ip-dst', 
            3: 'filename',
            4: 'url',
            19: 'url',
            20: 'url',
            21: 'url',
            22: 'url' 
    }
    def __init__(self):
        self.read_config()
        mongo = MongoClient(self.config['mongo']['host'], self.config['mongo']['port'])
        self.db = mongo[self.config['mongo']['db']]
        self.col = self.db.iocs
        self.kaspersky_reader = KasperskyReader(self.config['kaspersky'])
    
    def log(self, msg, feed, sev='INFO'):
        timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
        print(timestamp + ' ' + sev +  ' [' + feed['name'] + ']:', msg)

    def read_config(self):
        with open(self.CONFIG_FILE) as cf:
           self.config = yaml.safe_load(cf)
   
    def create_ioc(self, feed, value, info, _type, timestamp, category, comment, _uuid, tags=[], link=None, to_ids=False):
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
        obj['link'] = link if link is not None else ''
        obj['provider'] = feed['provider']
        obj['tags'] = tags
        return obj

    def process_feed(self, feed):
        self.log("Processing feed ...", feed)
        if feed['format'] == 'kaspersky':
            self.process_kaspersky_feed(feed)
        if feed['format'] == 'misp':
            resp = requests.get(feed['url'] + '/manifest.json')
            self.process_misp_feed(resp, feed)
        elif feed['format'] == 'csv':
            resp = requests.get(feed['url'], stream=True)
            self.process_csv_feed(resp, feed)
        self.log("Feed finished.", feed)

    def process_feeds(self):
        feeds = []
        for feed in self.config['feeds']:
            if 'disabled' in feed and feed['disabled'] == True:
                continue
            feeds.append(feed)
        if len(feeds) > 0:
            pool = ThreadPool(self.config['general']['threads'])
            pool.map(self.process_feed, feeds)
            pool.close() 
            pool.join()
   
    def process_kaspersky_feed(self, feed):
        iocs = []
        attrs = self.kaspersky_reader.download_feed(feed['url'])
        for attr in attrs:
            if 'mask' in attr:
                value = attr['mask']
                _type = self.kasp_type_lookup[attr['type']]
                _uuid = str(uuid.uuid4())
            info = feed['name']
            timestamp = attr['last_seen'] if 'last_seen' in attr else attr['first_seen'] if 'first_seen' in attr else dt.now().strftime('%s')
            timestamp = self.convert_timestamp(timestamp, feed)
            category = attr['category'].lower() if 'category' in attr else 'unknown'
            comment = attr['threat'] if 'threat' in attr else attr['id']
            tags = []
            tags.append(category)
            if 'mask' in attr:
                ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags)
                iocs.append(ioc)
            else:
                for key in ['MD5', 'SHA1', 'SHA256']:
                    if key in attr:
                        value = attr[key]
                        _type = key.lower()
                        _uuid = str(uuid.uuid4())
                        ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags)
                        iocs.append(ioc)
        self.load_to_mongo(iocs, feed)

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
                    link = ''
                    _uuid = attr['uuid']
                    to_ids = attr['to_ids']
                    ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags, link, to_ids)
                    iocs.append(ioc)
        self.load_to_mongo(iocs, feed)

    def process_csv_feed(self, resp, feed):
        delimiter = feed['delimiter'] if 'delimiter' in feed else ','
        iocs = []
        for line in resp.text.splitlines():
            if line:
                if 'ignorecsvheader' in feed and feed['ignorecsvheader'] == True:
                    feed['ignorecsvheader'] = False
                    continue
                if not line.startswith("#"):
                    fields = list(csv.reader([line], delimiter=delimiter))[0]
                    value = fields[feed['valuefield']] if 'valuefield' in feed else fields[0]
                    info = fields[feed['infofield']] if 'infofield' in feed else feed['info'] if 'info' in feed else feed['name']
                    _type = fields[feed['typefield']] if 'typefield' in feed else feed['type'] if 'type' in feed else 'unknown'
                    timestamp = fields[feed['timestampfield']] if 'timestampfield' in feed else dt.now().strftime('%s')
                    timestamp = self.convert_timestamp(timestamp, feed)
                    category = fields[feed['categoryfield']] if 'categoryfield' in feed else feed['category'] if 'category' in feed else 'unknown'
                    comment = fields[feed['commentfield']] if 'commentfield' in feed else feed['comment'] if 'comment' in feed else 'unknown'
                    link = fields[feed['linkfield']] if 'linkfield' in feed else feed['link'] if 'link' in feed else ''
                    _uuid = str(uuid.uuid4())
                    tags = feed['tags'] if 'tags' in feed else []
                    ioc = self.create_ioc(feed, value, info, _type, timestamp, category, comment, _uuid, tags, link)
                    iocs.append(ioc)
        self.load_to_mongo(iocs, feed)
    
    def convert_timestamp(self, timestamp, feed):
        if 'timestampformat' in feed:
            if feed['timestampformat'] == '%sN':
                timestamp = timestamp.split('.')[0]
            else:
                try: 
                   timestamp = dt.strftime(dt.strptime(timestamp, feed['timestampformat']), '%s')
                except ValueError as e:
                    timestamp = dt.strftime(dateparser.parse(timestamp), '%s')
        return int(timestamp)

    def load_to_mongo(self, iocs, feed):
        if len(iocs) > 0:
            self.log("Loading to mongodb...", feed)
            bulk = self.col.initialize_ordered_bulk_op()
            for ioc in iocs:
                bulk.find({'value': ioc['value']}).upsert().replace_one(ioc)
            try:
                bulk.execute()
            except BulkWriteError as e:
                self.log(e, feed, 'ERROR')
                pass
        else:
            self.log("Nothing to load to mongodb!", feed, 'ERROR')
         
def main():
    iocreader = IOCReader()
    iocreader.process_feeds()

if __name__ == "__main__":
    main()
