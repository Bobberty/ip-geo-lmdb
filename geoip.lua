

function countryip(IPAddr, LmdbLocation)
	local inet = require 'inet'
	local NewNetCheck = inet(IPAddr)
	if not (inet.is(NewNetCheck)) then
		return ('error: Really Bad IP')
	end

	if inet.is6(NewNetCheck) then
		ipdb = 'IPv6s'
		maskstart = 64
		if (inet('::1/128'):contains(NewNetCheck)) then
			return ('IPv6 Loopback')
		elseif (inet('fc00::/7'):contains(NewNetCheck)) then
			return ('IPv6 Locally Assigned Address')
		elseif (inet('fe80::/10'):contains(NewNetCheck)) then
			return ('IPv6 Local Link Address')
		end
	else
		ipdb = 'IPv4s'
		maskstart = 31
		if (inet('10.0.0.0/8'):contains(NewNetCheck) or inet('192.168.0.0/16'):contains(NewNetCheck) or inet('172.16.0.0/12'):contains(NewNetCheck)) then
			return ('IPv4 Non-Routable Address')
		elseif inet('127.0.0.0/8'):contains(NewNetCheck) then
			return ('LocalHost')
		elseif inet('169.254.0.0/16'):contains(NewNetCheck) then
			return ('IPv4 Local Link Address')
		end
	end

	local lightningmdb_lib = require 'lightningmdb'
	local lightningmdb=_VERSION>="Lua 5.2" and lightningmdb_lib or lightningmdb

	local e = lightningmdb.env_create()
	e:set_mapsize(1024*1024*1024)
	e:set_maxdbs(3)
	if not e:open(LmdbLocation,0x20000,420) then
		return ('error: Bad Location')
	end

	local t = e:txn_begin(nil,0x20000)
	local d = t:dbi_open(ipdb,0)

	for IPMask = maskstart,2, -1 do
		local newSearch = tostring(inet(IPAddr .. '/' .. tostring(IPMask)):network())
		result = t:get(d,newSearch)
		if result then
			break
		end
	end
	return result
end

if not (#arg == 2) then
	print('error: Please enter an IP address and the location of the lmdb IPlist database')
	return
end

Kickout = countryip(arg[1],arg[2])
print(Kickout)
return
