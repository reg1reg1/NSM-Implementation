#!/bin/bash
# Commands to start yaf and rwflowpack on the sensor periodically
# must be called every minute by cron

#Checking and starting the flowcollector rwflowpack


pidrw=$(pidof rwflowpack)
if [ -z "$pidrw" ]; then
	sudo pidof rwflowpack | tr ' ' '\n' | xargs -i sudo kill -9 {}
	echo "Rwflowpack was not running, restarting"
	sudo service rwflowpack restart
fi



function SiLKSTART {
sudo /etc/init.d/yaf start
}
function watchdog
{
 pidyaf=$(pidof yaf)
 if [ -z "$pidyaf" ]; then
	echo "Yaf is not running,starting yaf......"
	SiLKSTART
 fi
 
}
sleep 2m
watchdog
