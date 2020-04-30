#!/bin/bash
mkdir -p /apps/backup/usagelogs; find "/apps/logs/usagelogs" -iname "*.gz.gz*" -exec mv {} /apps/backup/usagelogs/ \;
