#!/usr/bin/python3

import requests
import urllib3
urllib3.disable_warnings()
response = requests.get('https://freeaeskey.xyz', verify=False)
data = response.text.encode('utf-8')
key = data[data.index(b'<b>')+3:data.index(b'</b>')]
print(key.decode('ascii'))

