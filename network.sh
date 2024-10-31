#!/bin/bash

# Run attack.py
sudo python3 attack.py > /dev/null 2>&1 &

# Kill it after 8 seconds
sleep 8 && sudo kill -9 $! &

# Wait
sleep 3

# Load freeaeskey.xyz
out=`curl -v http://freeaeskey.xyz/ 2> /dev/null`
echo $out | grep 4d6167696320576f7264733a2053717565616d697368204f7373696672616765 > /dev/null
res=$?

if [[ $res -eq 0 ]];
then
    echo "Pass"
else
    echo "Did not see key in output:"
    echo $out
fi



