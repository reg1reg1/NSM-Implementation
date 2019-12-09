
# Introduction to Zeek

1995- Zeek Invented as a solution to Berkley Labs packet analysis problem
Has seen a lot of development since then.

Zeek is a sophesticated network traffic analyzer.

The original paper vern paxon
Zeek-Threat hunting SIEM with Zeek. Kafka, elastic.
NSM is a complicated challenge requiring both human and machine effort



Offers 3 nw sec capabilities:
* Traffic logging
* File Extraction
* Custom traffic analysis

## Some features are
- Captures traffic out of band.
Done on most sensors by default to not interfere
with operations. Management and sniffing interfaces are kept separate.

Outputs?
1. Zeek Logs
2. Script Outputs (You can write custom scripts)
3. Extracted files 

Extracted files should be sent off to file analysis framework while the logs can be sent to the SIEM or log management interface.

Gist: **It is easy to hide or delete application/server logs, while It is impossible to mask presence in a network(if logs are comprehensive)**.

-  Zeek organizes traffic by protocol (Like Snort)
- Much richer than traditional application or server logs as it is out of band, so more power at disposal.
- Logs are interlinked. (querying is hence fast). The zeek logs are also designed to be queried within and by zeek fw.
- Corelight creates an enterprise version of Zeek (Similar to xen project)
- Swiss army knife of threat hunting
- Zeek logs can be shipped to Kibana using Logstash
- Kibana helps view anomalies in visualization lot faster



**At the end of the day, in the network it comes down to human vs human conflict**

Identifying the lowest hanging fruit is key to analyst and extracting information from visualization.  Whenever an attacker is using a protocol to exfiltrate data out of network , it has to be one of the protocol that is allowed to go in and out of the network. It could be http, icmp payloads etc.

## Zeek structural overview

![image-20191118214258906](D:\Github Repositories\NSM-Implementation\image-20191118214258906.png)

The first layer is the Network or Tap layer where bro ingests packets (Using span or Tap ports)

The second layer is the Platform layer of Zeek. 

The last layer is the analysis layer where we decide what to do with zeek

## Zeek Clustered architecture

![image-20191121001338551](D:\Github Repositories\NSM-Implementation\image-20191121001338551.png)

### Components of Zeek architecture

1. **Tap**: A mechanism similar to network port mirroring for traffic sniffing.
2. **Frontend:** Splitting traffic into many streams or flows (has to be done outside the zeek scope). This acts like a flow based load balancer and distributor . It is responsible for load balancing amongst the workers by splitting traffic into flows and distributing them to the workers.
3. **Manager:** 2 main jobs: It receives log messages and notices from the rest of the nodes in cluster using the Zeek communications protocols. The result is a single log instead of multiple logs.
4. **Logger:** Receives the log messages from the rest of the nodes in the cluster using Zeek communications protocol. Main purpos is to reduce the load on the manager.
5. **Proxy:** Offload data storage or some other arbitary workload. Default scripts that come with zeek make minimal use of proxies.
6. **Worker:** A worker is a zeek process that sniffs network traffic and does protocol analysis on the reassembled traffic streams. Most of the work of an active cluster takes place on the workers and consume most memories. 



### Zeek Config and Settings

/usr/local/zeek/etc/node.cfg : This has most of the configurations. For the barebones getting it to run, the interface needs to be changed.



/usr/local/zeek/etc/network.cfg: 



zeekctl to enter the CLI control mode for zeek

Initial config: Enter zeekctl cli 
zeekctl
[ZeekControl] > install

[ZeekControl] > start (starts a Zeek instance)

[ZeekControl]> diag (to diagnose errors with the cli)

### Browsing Log files

/usr/logs/current/ (different log files)

**Some Interesting Log files**:

conn.log: Contains an entry for every connection seen on the wire (similar to flow record)

notice.log: Identifies activities that zeek identifies as interesting . 

 By default, `ZeekControl` regularly takes all the logs from `$PREFIX/logs/current` and archives/compresses them to a directory named by date, e.g. `$PREFIX/logs/2011-10-06`. The frequency at which this is done can be configured via the `LogRotationInterval` option in `$PREFIX/etc/zeekctl.cfg`. 





## Zeek Scripts

Log file location defines events occurring which are detected, segregated and logged by zeek. The events are known, next step is to figure out what needs to be done with these logs.



## Logging

Once zeek has been deployed in an environment and monitoring traffic, it can produce organized human readable logs. Types of logs zeek generates:

- dpd Summary of protocols encountered on non-standard ports
- dns
- ftp
- files
- http
- known_certs
- smtp
- ssl
- weird: Logs unexpected protocol activity, RFC violation,

**Zeek-cut:** Using this utility (much like rwcut) we can query the existing logs. A easier more readable substitute for awk 

```bash
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h duration
```

It can query filter and be used like any other bash utility as shown below. The following is an example taken from the docs which sorts connections based on no of bytes from the responder.

```bash
cat conn.log | zeek-cut uid resp_bytes | sort -nrk2 | head -5
CwjjYJ2WqgTbAqiHl6        734
CtxTCR2Yer0FR1tIBg        734
Ck51lg1bScffFj34Ri        734
CLNN1k2QMum1aexUK7        734
CykQaM33ztNt0csB9a        733
```



### Zeek Plugins

Zeek plugin is a container for independently compiled components . wrapped into a shared library and loaded at startup. Detaching core functionality from the system.





## Zeek Acting as IDS:

Zeek is a network protocol analyzer, but using the power of scripting it can scan traffic for complex pattern detection and hence act as an Intrusion detection system.

One of the example presented in the documentation is detecting bruteforce FTP

```zeek
module FTP;

export {
    redef enum Notice::Type += {
        ## Indicates a host bruteforcing FTP logins by watching for too
        ## many rejected usernames or failed passwords.
        Bruteforcing
    };

    ## How many rejected usernames or passwords are required before being
    ## considered to be bruteforcing.
    const bruteforce_threshold: double = 20 &redef;

    ## The time period in which the threshold needs to be crossed before
    ## being reset.
    const bruteforce_measurement_interval = 15mins &redef;
}
```





# Zeek Scripting

Zeek includes an event driven scripting language. All of output generated by zeek is generated by zeek scripts. 

**What do zeek scripts do?**: Hey zeek if there is a type of event that occurs that matches our definition, let us know the details about the connection so we can perform a function on it.

SSL.log file is generated by a zeek script that walks the entire certificate chain, and issues notifications if it discovers any anomaly or invalid , out of place step.



## Zeek scripting basics

3 distinct sections of the script exist.

The first section is the export section. Here the variables are defined in a somewhat confusing syntax. The constants are variables which cannot change once zeek has started up.

The second section where we define our custom utility functions which might be called by the event function /logic. These are custom functions which have variable names , definitions, for loops , if conditions and are usually called from within event handlers as helper functions.

```c++
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module TeamCymruMalwareHashRegistry;

export {
    redef enum Notice::Type += {
        ## The hash value of a file transferred over HTTP matched in the
        ## malware hash registry.
        Match
    };

    ## File types to attempt matching against the Malware Hash Registry.
    option match_file_types = /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/;

    ## The Match notice has a sub message with a URL where you can get more
    ## information about the file. The %s will be replaced with the SHA-1
    ## hash of the file.
    option match_sub_url = "https://www.virustotal.com/en/search/?query=%s";

    ## The malware hash registry runs each malware sample through several
    ## A/V engines.  Team Cymru returns a percentage to indicate how
    ## many A/V engines flagged the sample as malicious. This threshold
    ## allows you to require a minimum detection rate.
    option notice_threshold = 10;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
    {
    local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

    when ( local MHR_result = lookup_hostname_txt(hash_domain) )
        {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1(MHR_result, / /);

        if ( |MHR_answer| == 2 )
            {
            local mhr_detect_rate = to_count(MHR_answer[1]);

            if ( mhr_detect_rate >= notice_threshold )
                {
                local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
                local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
                local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
                local virustotal_url = fmt(match_sub_url, hash);
                # We don't have the full fa_file record here in order to
                # avoid the "when" statement cloning it (expensive!).
                local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
                Notice::populate_file_info2(fi, n);
                NOTICE(n);
                }
            }
        }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind == "sha1" && f?$info && f$info?$mime_type &&
         match_file_types in f$info$mime_type )
        do_mhr_lookup(hash, Notice::create_file_info(f));
    }
```



The third section is where the event handler is defined. The event handlers are asynchronous in nature and those familiar with javascript can relate their behaviour to callbacks. Depending upon the type of event handler, the function code within it is called every time the event is triggered. Eg the above code uses the file_hash is an event which is triggered whenever a file is hashed by zeek. 

The most common type of event is "connection_state_remove" which is called by connection oriented events which happen.

### Zeek variables 

**Scope and Declaration**

2 ways to declare a variable:( this is very important to remember as can be very offputting and takes a lot getting used to)

1.  `SCOPE name: TYPE`  
2.   ``` SCOPE name = EXPRESSION``` 

Expression in point 2 must resolve to a type. Very offputting syntax again for variable declaration.

**Global Variables :**

The module keyword is used to give namespace to the script. The global variables may be defined and declared in 2 ways. When these variables are defined inside an ***export*** keyword, these are accessible to other scripts.  global variable declared within a module must be exported and then accessed via `< module_name>::<name>`. When declared outside export, these are inaccessible to outside current script. 

**Constants**:

Constants are variables which have fixed values. Except those which have the redef attribute set. These constants can have different values assigned to them (redifinition) but this must be done before zeek starts. 

One excerpt taken from the pre-existing zeek files used to log http traffic is shown below. Note that the default_capture_password has been redefined to a value F.

```javascript
module HTTP;

export {
	## This setting changes if passwords used in Basic-Auth are captured or
	## not.
	const default_capture_password = F &redef;
}
```

**Data Structures**

Data types behave differently when used with different data structures. Data structures are made up of variables though.
The overhead, bird's eye of variables in zeek look like below.

- int	64 bit signed integer

- count	64 bit unsigned integer

- double	double precision floating precision

- bool	boolean (T/F)

- addr	IP address, IPv4 and IPv6

- port	transport layer port

- subnet	CIDR subnet mask

- time	absolute epoch time

- interval	a time interval

- pattern	regular expression

**Sets:**

 Sets in Zeek are used to store unique elements of the **same data type.** Remember in zeek name of variable precedes the type definition.  

```javascript
event zeek_init()
    {
    local ssl_ports: set[port];
    local non_ssl_ports = set( 23/tcp, 80/tcp, 143/tcp, 25/tcp );
    }
```

**Vectors:**

These are again same as from other programming languages such as C++. Declaration is again odd. Notice the **off ** keyword to denote the vector object type.

```
    event zeek_init()
    {
    local v1: vector of count;
    local v2 = vector(1, 2, 3, 4);
    
    v1 += 1;
    v1 += 2;
    v1 += 3;
    v1 += 4;
    
    print fmt("contents of v1: %s", v1);
    print fmt("length of v1: %d", |v1|);
    print fmt("contents of v2: %s", v2);
    print fmt("length of v2: %d", |v2|);
    }
```

### A deeper look into data types

Some interesting data types , unique to zeek . 

port variables are declared like: 0/udp or 80/tcp or 53/udp
**Addresses and subnets**

This example shows the variables completely

```python
event zeek_init()
    {
    local subnets = vector(172.16.0.0/20, 172.16.16.0/20, 172.16.32.0/20, 172.16.48.0/20);
    local addresses = vector(172.16.4.56, 172.16.47.254, 172.16.22.45, 172.16.1.1);
    
    for ( a in addresses )
        {
        for ( s in subnets )
            {
            if ( addresses[a] in subnets[s] )
                print fmt("%s belongs to subnet %s", addresses[a], subnets[s]);
            }
        }

    }
```

The more interesting variables are time and interval, very useful in the bruteforce attempt detection

**time and interval**

Both [`network_time`](https://docs.zeek.org/en/stable/scripts/base/bif/zeek.bif.zeek.html#id-network_time) and [`current_time`](https://docs.zeek.org/en/stable/scripts/base/bif/zeek.bif.zeek.html#id-current_time) return a `time` data type but they each return a time based on different criteria. The `current_time` function returns what is called the wall-clock time as defined by the operating system. However, `network_time` returns the timestamp of the last packet processed be it from a live data stream or saved packet capture.   

```python
global last_connection_time: time;

# boolean value to indicate whether we have seen a previous connection.
global connection_seen: bool = F;

event connection_established(c: connection)
    {
    local net_time: time  = network_time();

    print fmt("%s:  New connection established from %s to %s", strftime("%Y/%M/%d %H:%m:%S", net_time), c$id$orig_h, c$id$resp_h);
    
    if ( connection_seen )
        print fmt("     Time since last connection: %s", net_time - last_connection_time);
    
    last_connection_time = net_time;
    connection_seen = T;
    }
```

The last data type worth looking into is equivalent to **struct** in C language. It is called **record**.

**Record and type:**

The record data type == struct keyword

the type word == typedef keyword 

wrt C language syntax. Example shown below.

```python
type Service: record {
    name: string;
    ports: set[port];
    rfc: count;
    };

type System: record {
    name: string;
    services: set[Service];
    };

function print_service(serv: Service)
    {
    print fmt("  Service: %s(RFC%d)",serv$name, serv$rfc);
    
    for ( p in serv$ports )
        print fmt("    port: %s", p);
    }

function print_system(sys: System)
    {
    print fmt("System: %s", sys$name);
    
    for ( s in sys$services )
        print_service(s);
    }

event zeek_init()
    {
    local server01: System;
    server01$name = "morlock";
    add server01$services[[ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035]];
    add server01$services[[ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616]];
    print_system(server01);
    
    
    # local dns: Service = [ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035];
    # local http: Service = [ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616];
    # print_service(dns);
    # print_service(http);
    }
```

## Some useful things to note

* Once the sections are clearly defined, there is one other oddity with the zeek language which can throw you off. That is zeek dereference operator> which is dollar **$**.
  * file.type is written as file$type
* This is similar to the bash syntax

 Module keyword is used to give namespace 



## Custom Logging

Sometimes logs aren't enough. Logs generated by zeek are comprehensive, but may need scenario, context , or logic based customization.  With the knowledge of zeek, the logging framework can now be engaged.

## Event handlers and queues





