import sys
import subprocess
import sys
import time
import urllib.request

#original_response = urllib.request.urlopen('http://freeaeskey.xyz/')
#o_resp = original_response.read()
#o_decoded = o_resp.decode("utf-8").partition("key:")[2]

try:
    proc = subprocess.Popen(['python3', 'attack.py'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(3)

    response = urllib.request.urlopen('http://freeaeskey.xyz/')

    resp = response.read()

    if b'4d6167696320576f7264733a2053717565616d697368204f7373696672616765' in resp:
        print('Pass')
    else:
        print('Did not inject key:')
        print(resp)
except Exception as e:
    print('Exception:', e)

proc.terminate()
sys.exit(0)
