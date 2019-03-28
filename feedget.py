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
import fcntl
import threading
from timeout import timeout
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
            os.remove(filename)
            return ret

class FeedStats:
    lock = threading.Lock()
    feed_stats = {}
    def __init__(self):
        self.start = dt.now()

    def set(self, feed, key, value):
        self.lock.acquire()
        try:
            if not feed['name'] in self.feed_stats:
                self.feed_stats[feed['name']] = {}
            self.feed_stats[feed['name']][key] = value
        finally:
            self.lock.release()

    def get(self, feed, key):
        self.lock.acquire()
        try:
            if feed['name'] in self.feed_stats:
                if key in self.feed_stats[feed['name']]:
                    return self.feed_stats[key]
            return None
        finally:
            self.lock.release()
    
    def out(self):
        self.lock.acquire()
        try:
            os.system('clear')
            sum_iocs = 0
            for key, stats in self.feed_stats.items():
                if 'start' in stats and 'end' in stats and 'status' in stats and 'count' in stats and 'error' in stats:
                    runtime = str(stats['end'] - stats['start']).split('.')[0]
                    print('%-80s : %-10s : %10d : %10s : %s' % (key, stats['status'], stats['count'], runtime, stats['error']))
                    sum_iocs = sum_iocs + stats['count']
            total_runtime = str(dt.now()- self.start).split('.')[0]
            print('%-80s : %-10s : %10d : %10s : %s' % ('Total', '', sum_iocs, total_runtime, ''))
        finally:
            self.lock.release()

class IOCReader:
    CONFIG_FILE = os.path.dirname(os.path.realpath(__file__)) + '/config.yml'
    kasp_type_lookup = {
            1: 'domain', 
            2: 'domain', 
            3: 'url',
            4: 'url',
            19: 'url',
            20: 'url',
            21: 'url',
            22: 'url' 
    }
    re_ip = re.compile(r'\d+\.\d+\.\d+\.\d+')


    def __init__(self):
        self.read_config()
        mongo = MongoClient(self.config['mongo']['host'], self.config['mongo']['port'])
        self.db = mongo[self.config['mongo']['db']]
        self.col = self.db.iocs
        self.kaspersky_reader = KasperskyReader(self.config['kaspersky'])
        self.feed_stats = FeedStats()
   
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
        #self.log('Found IOC: ' + obj['value'], feed)
        return obj

    def process_feed(self, feed):
        #self.log("Processing feed ...", feed)
        self.feed_stats.set(feed, 'start', dt.now())
        self.feed_stats.set(feed, 'end', dt.now())
        self.feed_stats.set(feed, 'status', 'Running')
        self.feed_stats.set(feed, 'error', '')
        self.feed_stats.set(feed, 'count', 0)
        self.feed_stats.out()
        if feed['format'] == 'kaspersky':
            self.process_kaspersky_feed(feed)
        elif feed['format'] == 'misp':
            resp = requests.get(feed['url'] + '/manifest.json')
            self.process_misp_feed(resp, feed)
        elif feed['format'] == 'csv':
            resp = requests.get(feed['url'], stream=True)
            self.process_csv_feed(resp, feed)
        #self.log("Feed finished.", feed)
        self.feed_stats.set(feed, 'status', 'Finished')
        self.feed_stats.set(feed, 'end', dt.now())
        self.feed_stats.out()

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
        self.feed_stats.out()
  
    def process_kaspersky_feed(self, feed):
        iocs = []
        attrs = self.kaspersky_reader.download_feed(feed['url'])
        for attr in attrs:
            if 'mask' in attr:
                value = attr['mask']
                _type = self.kasp_type_lookup[attr['type']]
                _uuid = str(uuid.uuid4())
                if _type == 'domain':
                    if self.re_ip.match(value):
                        _type = 'ip-dst'
            info = feed['name']
            timestamp = attr['last_seen'] if 'last_seen' in attr else attr['first_seen'] if 'first_seen' in attr else int(dt.now().strftime('%s'))
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
                    line = re.sub(r'[\s]+', ' ', line) 
                    fields = list(csv.reader([line], delimiter=delimiter))[0]
                    value = fields[feed['valuefield']] if 'valuefield' in feed and len(fields) > feed['valuefield'] else fields[0]
                    info = fields[feed['infofield']] if 'infofield' in feed and len(fields) > feed['infofield'] else feed['info'] if 'info' in feed else feed['name']
                    _type = fields[feed['typefield']] if 'typefield' in feed and len(fields) > feed['typefield'] else feed['type'] if 'type' in feed else 'unknown'
                    timestamp = fields[feed['timestampfield']] if 'timestampfield' in feed and len(fields) > feed['timestampfield'] else dt.now().strftime('%s')
                    timestamp = self.convert_timestamp(timestamp, feed)
                    category = fields[feed['categoryfield']] if 'categoryfield' in feed and len(fields) > feed['categoryfield'] else feed['category'] if 'category' in feed else 'unknown'
                    comment = fields[feed['commentfield']] if 'commentfield' in feed and len(fields) > feed['commentfield'] else feed['comment'] if 'comment' in feed else 'unknown'
                    link = fields[feed['linkfield']] if 'linkfield' in feed and len(fields) > feed['linkfield'] else feed['link'] if 'link' in feed else ''
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
            #self.log("Loading to mongodb (" + str(len(iocs)) + " iocs)...", feed)
            self.feed_stats.set(feed, 'status', 'Loading')
            self.feed_stats.set(feed, 'count', len(iocs))
            self.feed_stats.set(feed, 'end', dt.now())
            self.feed_stats.out()
            bulk = self.col.initialize_ordered_bulk_op()
            now = dt.now()
            for ioc in iocs:
                obj = {}
                obj['$setOnInsert'] = {}
                obj['$setOnInsert']['createDate'] = now
                ioc['modifyDate'] = now
                obj['$set'] = ioc
                bulk.find({'value': ioc['value']}).upsert().update_one(obj)
            try:
                bulk.execute()
            except BulkWriteError as e:
                self.feed_stats.set(feed, 'error', 'Errors while loading to mongodb')
                self.feed_stats.out()
                #self.log(e, feed, 'ERROR')
                pass
        else:
            self.feed_stats.set(feed, 'error', 'No IOCs found')
            self.feed_stats.out()
            #self.log("Nothing to load to mongodb!", feed, 'ERROR')
         
@timeout(1200)
def main():
    iocreader = IOCReader()
    iocreader.process_feeds()

if __name__ == "__main__":
    pid_file = os.path.dirname(os.path.realpath(__file__)) + '.pid'
    fp = open(pid_file, 'w')
    try:
        fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        main()
    except IOError:
        print('Already running!')
        sys.exit(0)
    except TimeoutError:
        print('Script used too much time. Aborting!')
        sys.exit(0)
