#! /usr/bin/env python3.6

import pymisp
import logging
import json
import warnings

warnings.filterwarnings("ignore")

logger = logging.getLogger('pymisp')
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)

misp = pymisp.api.PyMISP(url="https://127.0.0.1:443", key="w1KV8vumXow2C0u8zquWt0k3pUsObXJEDjQaTafT", ssl=False)
resp = misp.search(controller='attributes', type_attribute='ip-dst')

for attr in resp['response']['Attribute']:
    print(attr['value'])
