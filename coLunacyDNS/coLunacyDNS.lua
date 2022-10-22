-- coLunacyDNS configuration
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1

logLevel = 2 -- Between 0 and 10; higher numbers mean more logging

-- Examples of three API calls we have: timestamp, rand32, and rand16
coDNS.log(string.format("Timestamp: %.1f",coDNS.timestamp())) -- timestamp
coDNS.log(string.format("Random32: %08x",coDNS.rand32())) -- random 32-bit num
coDNS.log(string.format("Random16: %04x",coDNS.rand16())) -- random 16-bit num
-- Note that it is *not* possible to use coDNS.solve here; if we attempt
-- to do so, we will get an error with the message
-- "attempt to yield across metamethod/C-call boundary".  

function processQuery(Q) -- Called for every DNS query received
  -- Because this code uses multiple co-routines, always use "local"
  -- variables
  local returnIP = nil
  local upstream = "9.9.9.9"
  local t = {}

  -- Log query
  coDNS.log("Got IPv4 query for " .. Q.coQuery .. " from " ..
            Q.coFromIP .. " type " ..  Q.coFromIPtype .. 
            " query type " .. Q.coQtype) 

  -- We will use 8.8.8.8 as the upstream server if the query ends in ".tj"
  if string.match(Q.coQuery,'%.tj%.$') then
    upstream = "8.8.8.8"
  end

  -- We will use 4.2.2.1 as the upstream server if the query comes from 
  -- 192.168.99.X
  if string.match(Q.coFromIP,'^192%.168%.99%.') then
    upstream = "4.2.2.1"
  end

  -- Right now, coLunacyDNS can *only* process "A" (IPv4 IP) and
  -- "ip6" (IPv6 IP) queries
  if Q.coQtype ~= 1 and Q.coQtype ~= 28 then -- If it is not an ipv4/v6 query
    -- return {co1Type = "ignoreMe"} -- Ignore the query
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN)
  end

  -- If they ask for example.com, return one of the IPs in the file
  -- "exampleIPs.txt".  The format of this file is: Comments start
  -- with #.  Otherwise, a line can have an IPv4 IP in dotted decimal
  -- notation on it.  
  -- Once we read this file, we randomly choose an IP from the file to
  -- return to the client.
  -- The "return" call closes the opened file for us.
  if string.lower(Q.coQuery) == "example.com." then
    local ipList = {}
    if not coDNS.open1("exampleIPs.txt") then
      return {co1Type = "serverFail"}
    end
    local line = "#"
    while line do
      line = string.gsub(line,'#.*','') -- Remove # comments
      if string.match(line,'^%d') then -- If line starts with a number
        for ip in string.gmatch(line,'%d+%.%d+%.%d+%.%d+') do -- For each IP
          ipList[#ipList + 1] = ip -- Add the IP to the ipList
        end
      end
      line = coDNS.read1()
    end
    -- Return a randomly chosen IP from the list
    return {co1Type = "A", co1Data = ipList[(coDNS.rand32() % #ipList) + 1]}
  end

  -- Contact another DNS server to get our answer
  if Q.coQtype == 1 then
    t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream})
  else
    t = coDNS.solve({name=Q.coQuery, type="ip6", upstreamIp4=upstream})
  end

  if t.rawpacket then coDNS.log("Raw packet: " .. t.rawpacket) end

  -- If coDNS.solve returns an error, the entire processQuery routine is
  -- "on probation" and unable to run coDNS.solve() again (if an attempt
  -- is made, the thread will be aborted and no DNS response sent 
  -- downstream).  
  if t.error then	
    coDNS.log(t.error)
    return {co1Type = "serverFail"} 
  end

  -- Status is 1 when we get an IPv4 from the upstream DNS server, 
  -- 28 when we get an IPv6 from the upstream DNS server, otherwise 0
  -- 1 and 28 are the DNS query type numbers for IPv4 and IPv6 
  -- addresses.
  if (t.status == 1 or t.status == 28) and t.answer then
    returnIP = t.answer
  end

  if string.match(Q.coQuery,'%.invalid%.$') then
    return {co1Type = "A", co1Data = "10.1.1.1"} -- Answer for anything.invalid
  end
  if returnIP and Q.coQtype == 1 then
    return {co1Type = "A", co1Data = returnIP} 
  elseif returnIP and Q.coQtype == 28 then
    return {co1Type = "ip6", co1Data = returnIP} 
  end
  return {co1Type = "notThere"} 
end
