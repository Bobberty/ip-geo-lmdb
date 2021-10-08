#!/usr/bin/python3

# This script is desighed to load IP addresses assigned to each country from the
# IPDeny.com website into a LMDB database.  The LMDB database would be available
# as required to any application that can read an LMDB database.
#
# The LMDB schema is setup as follows:
#	ipv4_addr:
#		(ipv4 network ip)->(iso country code)
#
#	ipv6_addr:
#		(ipv6 network ip)->(iso country code)
#
#	Countries:
#		{iso country code}:ipv4_addr:IPs-> (List of IPv4 networks)
#		(iso country code):ipv4_addr:MD5-> (MD5 sum of the IPv4 list)
#		(iso country code):ipv6_addr:IPs-> (List of IPv6 networks)
#		(iso country code):ipv6_addr:MD5-> (MD5 sum of the IPv6 list)
#
#	The class IPCountry requires the location of the LMDB as an option.  If
#	this location doesn't exist, the system will attempt to create a new LMDB
#	database.  The database will be empty until updated.
#


import urllib.request
import re
import hashlib
import lmdb
import argparse
import ipaddress


class IPCountry:
	# This establishes the class.  On initializaion, it will set the defaults
	# for downloading the ip dataset and setup the LMDB enviornment for
	# the selected LMDB location.

	DENY_URL = 'http://www.ipdeny.com/'
	IPDENY_TYPE = {'ipv4_addr':'ipblocks/data/countries/','ipv6_addr':'ipv6/ipaddresses/blocks/'}
	IPDENY_URL = {'ipv4_addr':DENY_URL+IPDENY_TYPE['ipv4_addr']+'{}.zone','ipv6_addr':DENY_URL+IPDENY_TYPE['ipv6_addr']+'{}.zone'}
	IPTYPES = ('ipv4_addr','ipv6_addr')

	def __init__(self, LMDBLocation):
		try:
			self.env = lmdb.open(LMDBLocation, max_dbs=3, map_size=1024*1024*1024)
		except Exception as e:
			print(e)

		self.ipv4s_db = self.env.open_db(b'IPv4s')
		self.ipv6s_db = self.env.open_db(b'IPv6s')
		self.countries_db = self.env.open_db(b'Countries')

	def parse_md5_line(self,line):
		# This function will take the submitted MD5 line and disect and return
		# the MD5 value with the country or a False, None.  This is for
		# lines that may have been ingested that was not properly formatted.
		m = re.match(r"^(?P<md5>[0-9a-zA-Z]{32})\s+(?P<country>[a-z]{2}).+zone$", line)
		if m:
			return m.group("md5"), m.group("country")
		return False, None


	def loadMD5(self,fileURL):
		# Reach out the website and download the MD5 file and start digesting
		# the data.  A dictionary will be returned: country: md5sum.
		try:
			MD5SUM_DOWNLOAD = urllib.request.urlopen(fileURL)
			MD5SUM_DATA = MD5SUM_DOWNLOAD.read().decode('utf-8')
		except:
			return False
		MD5SUM_DICT = dict()
		for line in MD5SUM_DATA.split("\n"):
			MD5Sum, countrycode = self.parse_md5_line(line)
			if MD5Sum:
				MD5SUM_DICT[countrycode] = MD5Sum
		return MD5SUM_DICT

	def RequiredUpdates(self,MD5SUM_DICT, IPV_TYPE):
		# This function will take a Country:MD5 sum dictionary and compare with
		# the LMDB countries:(IP Type):MD5 value.  IF they different,
		# the country is added to the UpdateList.  The UpdateList is returned.
		UpdateList = []
		with self.env.begin() as txn:
			for Country,MD5SUM_DATA in MD5SUM_DICT.items():
				checkKey = (Country+':'+IPV_TYPE+':MD5').encode()
#				checkKeyEnc = checkKey.encode()
				md5fromDB = txn.get(checkKey,default=False,db=self.countries_db)
				if md5fromDB:
					md5fromDBDec = md5fromDB.decode('utf-8')
					if md5fromDBDec != MD5SUM_DICT[Country]:
						UpdateList.append(Country)
				else:
					UpdateList.append(Country)
		return UpdateList

	def getIPData(self,CountryCode,MD5data,IPV):
		# Download the specific IP file from IPDeny.com and hash the file
		# as MD5 and verify the MD5.  This will either return the IP data
		# or False if the MD5 fails.
		try:
			ip_blocks = urllib.request.urlopen(self.IPDENY_URL[IPV].format(CountryCode))
			ip_blocks_pre = ip_blocks.read()
			ip_blocks_data = ip_blocks_pre.decode('utf-8')
		except:
			ip_blocks_data = False
		if ip_blocks_data:
			HASH_DATA = hashlib.md5(ip_blocks_pre).hexdigest()
			if (HASH_DATA == MD5data):
				return ip_blocks_data
		return False

	def GetIPDenyUpdates(self,UpdateList,MD5SUM_DICT,IPV_TYPE):
		# This function will go through each country and download the updates
		# and put it into the Countries database as required.  If the country
		# was preexisting, the system will overwrite the data..

		with self.env.begin(write=True) as txn:
			for CountryID in UpdateList:
				keyFormat = CountryID +':'+IPV_TYPE+':{}'
				IPData = self.getIPData(CountryID,MD5SUM_DICT[CountryID],IPV_TYPE)
				if IPData:
					ipDataOut = ','.join(IPData.splitlines())
					BipDataOut = ipDataOut.encode()
					BMD5DataOut = MD5SUM_DICT[CountryID].encode()
					BkeyMD5= keyFormat.format('MD5').encode()
					BkeyIPs= keyFormat.format('IPs').encode()
					txn.put(BkeyMD5, BMD5DataOut, db=self.countries_db)
					txn.put(BkeyIPs, BipDataOut, db=self.countries_db)
				else:
					print('No Data for {}.'.format(CountryID))
		return

	def updateIPdb(self,MD5Sums_DICT,IPV_TYPE):
		# Take the current Countries database and overwrite the IPv4s and IPv6s
		# Databases.  This will overwrite all entries while using the Countries
		# as a source.
		# It seems to be faster to overwrite than try and figure out which couuntry
		# has changed.

		if IPV_TYPE=='ipv4_addr':
			ipvs_db = self.ipv4s_db
		else:
			ipvs_db = self.ipv6s_db
		with self.env.begin(write=True) as txn:
			txn.drop(db=ipvs_db,delete=False)
			for Country,MD5SUM_DATA in MD5Sums_DICT.items():
				checkKeyEnc = (Country+':'+IPV_TYPE+':IPs').encode()
				ipList=txn.get(checkKeyEnc,default=False,db=self.countries_db).decode('utf-8').split(',')
				for ipaddress in ipList:
					txn.put(ipaddress.encode(),Country.encode(),db=ipvs_db)
			print('Finished updating {} database'.format(IPV_TYPE))
		return

	def GetCountry(self,ipAddress):
		# This is the meat and gravy fo this system.  This takes an IP address
		# and searches the database for a country that has the IP address in
		# the network.
		# This script simply uses the netmask.  Starting at the biggest real
		# and counting down until the IP address is within the network.
		# That would be a max of 20 quiries on IPv4 and 59 for IPv6.

		try:
			CurrentIP = ipaddress.ip_network(ipAddress)
		except:
			return('Not an IPv4 or IPv6 address')
		if not CurrentIP.is_global:
			return('Not a Global IP Address')

		if CurrentIP.version == 4:
			NetmaskStart = 24
			NetmaskEnd = 2
			ipvs_db = self.ipv4s_db
		else:
			NetmaskStart = 64
			NetmaskEnd = 4
			ipvs_db = self.ipv6s_db
		with self.env.begin() as txn:
			for Masks in range(NetmaskStart,NetmaskEnd,-1):
				checkNet = str(CurrentIP.supernet(new_prefix=Masks)).encode()
				CountrY = txn.get(checkNet,default=False,db=ipvs_db)
				if CountrY:
					break
			if CountrY:
				FixedCountrY = CountrY.decode().upper()
				return FixedCountrY
		return('No Country Found')

	def dumpCC(self,CountryCode):
		# Simple dump of all IP addresses for a specific country code

		with self.env.begin() as txn:
			ReturnedIPs = {}
			for ipv in self.IPTYPES:
				key = CountryCode +':'+ipv+':IPs'
				IPResult = txn.get(key.encode(),default=False,db=self.countries_db)
				if IPResult:
					ReturnedIPlist = IPResult.decode()
					ReturnedIPs[ipv] = ReturnedIPlist.split(',')
		return ReturnedIPs

	def update_countrylist(self):
		# Function for driving the update process

		for ipv in self.IPTYPES:
			MD5Data = self.loadMD5(self.DENY_URL+self.IPDENY_TYPE[ipv]+'MD5SUM')
			IPUpdates = self.RequiredUpdates(MD5Data,ipv)
			if IPUpdates:
				print('Updating the following countries: ',*IPUpdates)
				self.GetIPDenyUpdates(IPUpdates,MD5Data,ipv)
				self.updateIPdb(MD5Data,ipv)
			else:
				print('No Updates for ',ipv)
		print('Done!')
		return

if __name__ == '__main__':
	# Change the LMDB location here
	IPLister = IPCountry('*** BADLMDB NAME ****')
	parser = argparse.ArgumentParser(description='Script to download and evaluate IP address assignment to specific countries')
	parser.add_argument('-u','--update',action ='store_true',help='Update the IP address database')
	parser.add_argument('-l','--lookup',action ='store',help='Look up the IP address and return the source country.')
	parser.add_argument('-d','--dumpcc',action ='store',help='Dump the address for a country code')
	parser.add_argument('-c','--count',action='store',help='Report the current IPv4, IPv6 host address and IPv6 network address counts')

	args = parser.parse_args()
	if args.update:
		IPLister.update_countrylist()
	if args.lookup:
		print(IPLister.GetCountry(args.lookup))
	if args.dumpcc:
		print(IPLister.dumpCC(args.dumpcc))
	if args.count:
		list = IPLister.dumpCC(args.count)
		ipV4 = list['ipv4_addr']
		ipV6 = list['ipv6_addr']
		IPv4Hosts = 0
		for address in ipV4:
			IPv4Hosts += 2 ** (32 - int(address.split('/')[1]))-1
		IPv6Hosts = 0
		IPv6Networks = 0
		for address in ipV6:
			CurrentNetmask = int(address.split('/')[1])
			IPv6Hosts += 2 ** (128 - CurrentNetmask)
			if (CurrentNetmask < 65 ):
				IPv6Networks += 2 ** (64 - CurrentNetmask)
		print('IPv4: {:,}\t IPv6 /64 Networks:  {:,}\tIPv6: {:,}'.format(IPv4Hosts, IPv6Networks, IPv6Hosts))
