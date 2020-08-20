-- coLunacyDNS configuration
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
-- bindIp6 = "::1" -- Uncomment this line to give program IPv6 address

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

  -- Log query
  coDNS.log("Got IPv4 query for " .. Q.coQuery .. " from " ..
            Q.coFromIP .. " type " ..  Q.coFromIPtype) 

  -- We will use 8.8.8.8 as the upstream server if the query ends in ".tj"
  if string.match(Q.coQuery,'%.tj%.$') then
    upstream = "8.8.8.8"
  end

  -- We will use 4.2.2.1 as the upstream server if the query comes from 
  -- 192.168.99.X
  if string.match(Q.coFromIP,'^192%.168%.99%.') then
    upstream = "4.2.2.1"
  end

  if Q.coQtype ~= 1 then -- If it is not an A (ipv4) query
    -- return {co1Type = "ignoreMe"} -- Ignore the query
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN)
  end

  -- Contact another DNS server to get our answer
  t = coDNS.solve({name=Q.coQuery, type="A", upstreamIp4=upstream})

  -- If coDNS.solve returns an error, the entire processQuery routine is
  -- "on probation" and unable to run coDNS.solve() again (if an attempt
  -- is made, the thread will be aborted and no DNS response sent 
  -- downstream).  
  if t.error then	
    coDNS.log(t.error)
    return {co1Type = "serverFail"} 
  end

  -- Status is 1 when we get an IP from the upstream DNS server, otherwise 0
  if t.status == 1 and t.answer then
    returnIP = t.answer
  end

  if string.match(Q.coQuery,'%.invalid%.$') then
    return {co1Type = "A", co1Data = "10.1.1.1"} -- Answer for anything.invalid
  end
  if returnIP then
    return {co1Type = "A", co1Data = returnIP} 
  end
  return {co1Type = "notThere"} 
end
