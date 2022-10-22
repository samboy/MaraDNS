bindIp="198.41.0.4" -- A.root-servers.net, i.e. not an IP we have
coDNS.log("Hello, there")
function processQuery(Q) -- Called for every DNS query received
  return {co1Type = "A", co1Data = "10.1.1.1"}
end
