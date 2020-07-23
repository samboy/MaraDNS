bindIp = "127.0.0.1" -- We bind the server to the IP 127.0.0.1
function processQuery(mmAll) -- Called for every DNS query received
  if mmAll.mmQtype ~= 1 then -- If it is not an A (ipv4) query
    return {mm1Type = "ignoreMe"} -- Ignore the query
  end
  mmDNS.log("Got IPv4 query for " .. mmAll.mmQuery) -- Log the query
  if string.match(mmAll.mmQuery,'.com.$') then
    return {mm1Type = "A", mm1Data = "10.1.1.1"} -- Answer for anything.com
  end
  return {mm1Type = "A", mm1Data = "10.1.2.3"} -- Answer for anything not .com
end
