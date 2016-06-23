#!/bin/bash
#
# Author: Vladimir Antonovich
# This script avoid few issues with Cloudify Manager when Ravello application stops
# This script should be run from cloudify cli folder before Ravello application will stop. 
#

cd ~/cfy
CLOUDIFY=$(awk 'match($0, /_management_ip:/){print $3}' .cloudify/context | tr -d \')
USER=$(awk 'match($0, /_management_user:/){print $3}' .cloudify/context | tr -d \')
KEY=$(awk 'match($0, /_management_key:/){print $3}' .cloudify/context | tr -d \'~)

ssh_command="sudo systemctl stop cloudify-mgmtworker.service;sudo systemctl stop cloudify-influxdb.service"

ssh -i $HOME$KEY $USER@$CLOUDIFY $ssh_command
