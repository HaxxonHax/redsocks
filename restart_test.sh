#!/bin/bash
sudo pkill --full /usr/sbin/redsocks
sudo cp ./redsocks /usr/sbin/redsocks
sudo /usr/sbin/redsocks -c /usr/local/etc/redsocks.conf -p /run/redsocks/redsocks.pid
date
ps -eaf | grep redsocks
