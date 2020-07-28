bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
coDNS.log(string.format("Timestamp: %.1f",coDNS.timestamp())) -- timestamp
coDNS.log(string.format("Random32: %08x",coDNS.rand32())) -- random 32-bit num
coDNS.log(string.format("Random16: %04x",coDNS.rand16())) -- random 16-bit num
function processQuery(mmAll) -- Called for every DNS query received
  if mmAll.mmQtype ~= 1 then -- If it is not an A (ipv4) query
    return {mm1Type = "ignoreMe"} -- Ignore the query
  end
  t = coDNS.solve({name="some.example.com.", type="A", upstreamIp="10.1.2.3"})
  if t.answer then
    coDNS.log(t.answer)
  end
  -- Log query
  coDNS.log("Got IPv4 query for " .. mmAll.mmQuery .. " from " ..
            mmAll.mmFromIP .. " type " .. 
            string.format("%d",mmAll.mmFromIPtype)) 
  if string.match(mmAll.mmQuery,'%.com%.$') then
    return {mm1Type = "A", mm1Data = "10.1.1.1"} -- Answer for anything.com
  end
  return {mm1Type = "A", mm1Data = "10.1.2.3"} -- Answer for anything not .com
end
