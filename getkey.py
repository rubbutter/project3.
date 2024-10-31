#!/usr/bin/python3

import urllib.request
with urllib.request.urlopen('http://freeaeskey.xyz') as response:
    data = response.read()
    key = data[data.index(b'<b>')+3:data.index(b'</b>')]
    print(key.decode('ascii'))

