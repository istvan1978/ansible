#!/bin/bash

date
echo "Installing OpsRamp Agent"
rpm -qa | grep -q ^opsramp-agent
if [ $? -ne 0 ]
then
  sudo python ./deployAgent_gpo-css-pt-ct-isat.py --installtype silent
  sleep 30
  echo '--------------------------------------'
else
  echo "OpsRamp Agent already present"
fi

sleep 20
echo '--------------------------------------'

echo "Recently installed RPMs"
rpm -qa --last | head -5