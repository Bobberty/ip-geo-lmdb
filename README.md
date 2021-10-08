# GeoIP.py
This is a script provides local access to the IPDeny.com ip database.  Further, it will update as necessary by depending on the MD5 list downloaded.  If a country has changed their IP Address allocation, this system will only download the specific country.  The first run on a new database will always download the full list. The database is reboot resistant and very fast.

This is a python script that will do four thinge:
+ Setup the LMDB Database
+ Update the LMDB Database
+ Query the Database for a specific IP address
+ Dump a specific country code assigned IP Networks



## Setup the LMDB Database
On initial startup, the system will establish the LMDB at the specific location in the script file.  It will establish a 3 Databases:  IPv4s, IPv6s, and Countries.
The schema of the IPv4s and IPv6s are the same:
- (IP Network)->(Country Code)

Countries schema:
- (Country Code):ipv4_addr:IPs->(IPv4 network list)
- (Country Code):ipv4_addr:MD5->(MD5 of IPv4 network list)
- (Country Code):ipv6_addr:IPs->(IPv6 network list)
- (Country Code):ipv6_addr:MD5->(MD5 of IPv6 network list)
 
 ```
 user@dummy:~$ ./GeoIP.py
 user@dummy:~$
```

## Update the Database
On update, the system will reach out to ipdeny.com and download the MD5 file for both the IPv4 and IPv6 networks. Next, the MD5 file will be ripped apart and each line (Country) will be compared to the same country MD5 in the Countries DB.  If they are the same, move on to the next country.  Else, put the country into a list for updating.
The system will next parse the list and downlaod each countries IP list and replace the current entry in the Countries DB.
Once all of the countries are downloaded, the system will simply purge the IPv4s and IPv6s database and reload each database from the Countries DB.
This means that a full download is required once.  Each update requires the minimum of two MD5 files.  And then the required update files.
 
```
user@dummy:~$ ./GeoIP.py -u
No Updates for  ipv4_addr
No Updates for  ipv6_addr
Done!
user@dummy:~$ 
```

## Query the Database for a specific IP address
On the request, the system will test for IPv4 or IPv6 and set the specific database. Next it will use the netmask process to find a match.  The netmask range {24-2} for IPv4 and {64-4} for IPv6.  The starts at the high netmask range and counds down until a match is found or the lower number is reached.

```
user@dummy:~$ ./GeoIP.py -l 1.1.1.1
AU
user@dummy:~$ ./GeoIP.py -l 2001:4860:4860::8888
US
user@dummy:~$ 
```

## Dump a specific country code assigned IP Networks
This simply dumps the ip4_addr and IP6_addr for a specific country code.

```
user@dummy:~$ ./GeoIP.py -d ag
{'ipv4_addr': ['23.132.144.0/24', '69.50.64.0/20', '69.57.224.0/19', '76.76.160.0/19', '162.210.156.0/22', '162.222.84.0/22', '162.252.188.0/22', '192.64.120.0/22', '199.16.56.0/22', '199.48.204.0/22', '199.189.112.0/22', '204.16.112.0/22', '205.217.224.0/19', '206.83.13.0/24', '206.214.0.0/19', '208.83.80.0/21', '209.59.64.0/18', '216.48.96.0/22'], 'ipv6_addr': ['2620:6f:2000::/48']}
user@dummy:~$
```

## Requirements
+ Python 3+
+ urllib.request
+ re
+ hashlib
+ lmdb
+ argparse
+ ipaddress

## Setup
Please change the file name in the script from "*** BADLMDB NAME ****" to a filename and location that has read/write access to the script.


# geoip.lua
This script polls the LMDB database that was setup with the GeoIP.py script for a specific IP address.  It is very fast and compact.  The Lua function should work on any Lua 5.2+ scripting system.

## Query the Database for a specific IP address
On the request, the system will test for common non-global addresses and quickly return if solved.  Otherwise it will use the netmask process to find a match.  The netmask range {31-2} for IPv4 and {64-2} for IPv6.  The starts at the high netmask range and counds down until a match is found or the lower number is reached.
```
user@dummy:~$ ./geoip.lua 2001:4860:4860::8888 iplist.lmdb
us
user@dummy:~$
```

## Requirements:
- lua (5.2+)
- inet
- lightningmdb


# Notes:
- The Python script works for establishing the Database and doing some very complex queries.  On a 10 year old system, it takes about .5 seconds per IP query. And each update a minimum of about 20K (10K per IP type). 
- The lua script was written to integrate into other applications such as lighttpd.  Such that specific countries could be redirected or blocked.
- IPDeny.com has a licence requirement.  I strongly encourage all users of this script to abide by the usage conditions of the data. IPDeny.com is an amazing service that I wish to thrive.

