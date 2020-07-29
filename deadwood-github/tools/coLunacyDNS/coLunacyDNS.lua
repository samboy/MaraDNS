-- coLunacyDNS configuration
bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1

-- Examples of three API calls we have: timestamp, rand32, and rand16
coDNS.log(string.format("Timestamp: %.1f",coDNS.timestamp())) -- timestamp
coDNS.log(string.format("Random32: %08x",coDNS.rand32())) -- random 32-bit num
coDNS.log(string.format("Random16: %04x",coDNS.rand16())) -- random 16-bit num
-- Note that it is *not* possible to use coDNS.solve here; if we attempt
-- to do so, we will get an error with the message
-- "attempt to yield across metamethod/C-call boundary".  

function processQuery(Q) -- Called for every DNS query received
  if Q.coQtype ~= 1 then -- If it is not an A (ipv4) query
    return {co1Type = "ignoreMe"} -- Ignore the query
  end
  t = coDNS.solve({name="some.example.com.", type="A", upstreamIp4="10.1.2.3"})
  if t.answer then
    coDNS.log(t.answer)
  end
  -- Log query
  coDNS.log("Got IPv4 query for " .. Q.coQuery .. " from " ..
            Q.coFromIP .. " type " ..  Q.coFromIPtype) 
  if string.match(Q.coQuery,'%.com%.$') then
    return {co1Type = "A", co1Data = "10.1.1.1"} -- Answer for anything.com
  end
  return {co1Type = "A", co1Data = "10.1.2.3"} -- Answer for anything not .com
end
