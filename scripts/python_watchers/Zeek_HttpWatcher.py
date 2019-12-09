import os
import sys
import time
import subprocess
import re
from datetime import datetime

#Base metric. Error codes must be 0.01% of the response codes for any given IP
ALLOWED_CONN_RATIO=0.01
LOGPATH= "/usr/local/zeek/logs/current/http.log"
MONPATH = "MonitoredControllers.txt"
ACTIONLOG="actions_taken.log"


#global set of monitored controllers
monitored=set()
#global set of blocked Ip
preBlocked=set()



ip_monitoring=dict()

#x is valid
#y is invalid
def conn_ratio(x,y):
    if y==0:
        return True
    else:
        value = float(y/(y+x))
        #print("DEBUG: Value calculated as ",value)
        if ALLOWED_CONN_RATIO < value:
            return False
        



#initial read on the file
#If file does not exist , catch exception
def initLoad():
    try:
        newfile = open(LOGPATH,"r")
        for lines in newfile: 
            blockLogic(lines)
        return True
    except FileNotFoundError:
        print("File Not present, moving to tailing it")
        return False  
	
def uncommentedLine(line):
    matchCheck= re.search("^#.*", line)
    if matchCheck is None:
        return True
    return False

#read monitoredhosts, change every 5 min
def loadMonitoredHosts():
    global monitored
    hostfile = open(MONPATH,"r")
    for lines in  hostfile:
        line = lines.replace("\n","")
        print(line)
        monitored.add(line)

#Log Actions taken
def logAction(actionString):
    global ACTIONLOG
    if os.path.exists(ACTIONLOG):
        append_write = 'a' # append if already exists
    else:
        append_write = 'w' # make a new file if not
    actionFile = open(ACTIONLOG,append_write)
    actionFile.write(str(datetime.now()) + actionString  + '\n')
    actionFile.close()


class ipobject():
    def __init__(self):
        self.conn_count=1
        self.respOk=0
        self.respInvalid=0

#function that defines block logic
#block actions violating connection ration
#block actions with suspicious user-agents
#if current IP is already blocked ignore
#else -> check if the source IP has made 50+ requests atleast
#if not -> ignore
#else -> calculate connection ratio and decide block
#there will be some ip's which will get blocked on the initial run of the file, if file empty all entries will be tail mode
def blockLogic(logLine):
    global preBlocked
    if not uncommentedLine(logLine):
        return 
    elements = logLine.split("\t")
    #print(elements)
    srcIp = elements[2]
    srcPort = elements[3]
    dstIp = elements[4]
    dstPort = elements[5]
    responseCode = elements[16]
    if srcIp in preBlocked:
        print("Already blocked , should not appear in line by line log",srcIp)
    else:
        #check count , update count, if count > 50 check connection ratio
        if srcIp not in ip_monitoring:
            ip_monitoring[srcIp]=ipobject()
        else:
            ip_monitoring[srcIp].conn_count+=1
            if int(responseCode) == 200:
                ip_monitoring[srcIp].respOk+=1
            else:
                ip_monitoring[srcIp].respInvalid+=1
            
            #print("Recurring Ip check")
            if ip_monitoring[srcIp].conn_count>=50:
                #calculate connection ratio, add other factors here (this is the meat of flagging the IP)
                if conn_ratio(ip_monitoring[srcIp].respOk,ip_monitoring[srcIp].respInvalid):
                    #print("DEBUG: good to go ",srcIp)
                    pass
                else:
                    #Take action , block the IP
                    x=blockInputAction(srcIp) and blockForwardAction(srcIp)
                    if x:
                        logAction("DEBUG:Successfully blocked ",srcIp)
                        preBlocked.add(srcIp)
                    else:
                        logAction("ERROR: Could not block ",srcIp)
                    #Update the blockedIp set

def loadBlocked():
    #fetch blocked ip's. Filter table chain drop
    global preBlocked
    args = ("ansible","-m","command","router-1","-a","iptables -L -n -t filter -v")
    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        #print(output)
        #print(type(output))
        #output=output.decode().replace("\n","")
        #print("Command Output")
        #print(output)
        outputLines = output.decode().split("\n")
        count=0
        #print("CHECKING OUTPUT")
        print()
        print()
        for lines in outputLines:
            matchCheck= re.search("^[\ ]*[0-9].*", lines)
            #print(matchCheck)
            if matchCheck is None:
                continue
            else:
                if count==0:
                    count+=1
                    continue
                elements=lines.split()
                ipaddr= elements[7]
                if "DROP" in lines or "REJECT" in lines:
                    logAction("DEBUG: "+ipaddr+" is already Blocked")
                    preBlocked.add(ipaddr)
    except subprocess.CalledProcessError as e:
        logAction("Error :"+str(e))





#function that defines block action
#check if current IP is already blocked by fetching iptables
#if not block , else ignore
def blockInputAction(srcIP):
    #ansible -m command router-1 -a "iptables -L -n -t filter -v"
    args = ("ansible","-m","command","router-1","-a","iptables -I INPUT -s %s -j DROP" % (srcIP))
    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        #print(output)
        #print(type(output))
        output=output.decode().replace("\n",",")
        #print("Command Output ",output)
        return True 
    except subprocess.CalledProcessError as e:
        logAction("Error :"+str(e))
        return False

def blockForwardAction(srcIP):
    args = ("ansible","-m","command","router-1","-a","iptables -I FORWARD -s %s -j DROP" % (srcIP))
    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        #print(output)
        #print(type(output))
        output=output.decode().replace("\n",",")
        #print("Command Output ",output)
        return True
    except subprocess.CalledProcessError as e:
        logAction("Error :"+str(e))
        return False

#neat generator based-technique to continuously read the file on tail Mode
def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(1)
            continue
        yield line

if __name__ == '__main__':
    #1. load the already blocked Ip's into set
    loadBlocked()
    #2. Read the whole log file once if present, if not continue here , sleep 1m
    while True:
        try:
            x=initLoad()
            if not x:
                time.sleep(1)
                continue
            logfile = open(LOGPATH,"r")
            loglines = follow(logfile)
            for line in loglines:
                print(line)
                blockLogic(line)
        except FileNotFoundError:
            print("No file to tail yet")
            time.sleep(1)
            continue
