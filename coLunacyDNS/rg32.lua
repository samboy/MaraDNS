-- coLunacyDNS configuration
-- This file will, for IPv6 queries, return the RadioGatun[32] sum
-- of the query.  This is a testing tool to make sure bit32.rrotate()
-- and other bit32 calls are working correctly.
bindIp = "127.1.1.32" -- We bind the server to the IP 127.0.0.1
logLevel = 2 -- Between 0 and 10; higher numbers mean more logging

-- RG32 code
-- Note that belt and mill are 1-indexed here
function beltMill(belt, mill) 

  -- Mill to belt feedforward
  for z = 0, 11 do
    offset = z + ((z % 3) * 13) + 1
    belt[offset] = bit32.bxor(belt[offset],mill[z + 2])
  end

  -- Mill core
  local rotate = 0
  local millPrime = {}
  for z = 0, 18 do
    rotate = rotate + z
    local view = (z * 7) % 19
    local num = mill[view + 1]
    view = (view + 1) % 19
    local viewPrime = (view + 1) % 19
    num = bit32.bxor(num,bit32.bor(mill[view + 1],
                     bit32.bnot(mill[viewPrime + 1])))
    num = bit32.rrotate(num,rotate)
    millPrime[z + 1] = num
  end
  for z = 0, 18 do
    local view = (z + 1) % 19
    local viewPrime = (z + 4) % 19
    mill[z + 1] = bit32.bxor(millPrime[z + 1],
	millPrime[view + 1],millPrime[viewPrime + 1])
  end

  -- Belt rotate
  for z = 39, 1, -1 do  
     belt[z + 1] = belt[z]
  end
  for z = 0, 2 do
     belt[(z * 13) + 1] = belt[((z + 1) * 13) + 1]
  end

  -- Belt to mill
  for z = 0, 2 do
     mill[14 + z] = bit32.bxor(belt[(z * 13) + 1],mill[14 + z])
  end

  mill[1] = bit32.bxor(mill[1],1)
end

function initBeltMill()
  local belt = {}
  local mill = {}
  for z = 1, 40 do
    belt[z] = 0
  end
  for z = 1, 19 do
    mill[z] = 0
  end
  return belt, mill
end

-- Output strings which are hex numbers in the same endian order
-- as RadioGatun[32] test vectors, given a float
function makeLittleEndianHex(i) 
  local out = ""
  for z = 1, 4 do
    i = math.floor(i)
    out = out .. string.format("%02x",i % 256)
    i = i / 256
  end
  return out
end

-- Output a 256-bit digest string, given a radiogatun state.  Affects belt and
-- mill, returns string
function makeRG32sum(belt, mill)
  local out = ""
  for z = 1, 4 do
    out = out .. makeLittleEndianHex(mill[2]) .. makeLittleEndianHex(mill[3])
    beltMill(belt, mill)
  end
  return out
end

-- RadioGatun input map; given string return belt, mill
function RG32inputMap(i) 
  local belt, mill
  belt, mill = initBeltMill()
  local phase = 0;
  for a = 1, string.len(i) do
    local c = string.byte(i, a) 
    local b
    c = c % 256
    c = c * (2 ^ (8 * (phase % 4)))
    b = math.floor(phase / 4) % 3
    belt[(13 * b) + 1] = bit32.bxor(belt[(13 * b) + 1],c)
    mill[17 + b] = bit32.bxor(mill[17 + b],c)
    phase = phase + 1
    if phase % 12 == 0 then 
      beltMill(belt, mill)
    end
  end 

  -- Padding byte
  local b = math.floor(phase / 4) % 3
  local c = 2 ^ (8 * (phase % 4))
  belt[(13 * b) + 1] = bit32.bxor(belt[(13 * b) + 1],c)
  mill[17 + b] = bit32.bxor(mill[17 + b],c)

  -- Blank rounds
  for z = 1, 18 do
    beltMill(belt,mill)
  end
  return belt, mill
end

-- Verify rg32 sum, if we're using Lunacy (my Lua 5.1 fork)
function lunacyVerifyVector(i)
  local out = ""
  if math.rand16 then
    math.randomseed(i)
    for z = 1, 16 do
      out = out .. string.format("%04x",math.rand16())
    end
  end 
  return out
end

function RG32sum(i) 
  local belt, mill = RG32inputMap(i)
  -- print(lunacyVerifyVector(i)) -- DEBUG
  return makeRG32sum(belt,mill)
end

-- Initialize a RG32 state we can get 32-bit PRNGs from
function RG32init(i)
  local belt, mill = RG32inputMap(i)
  return {belt = belt, mill = mill, phase = 1}
end

-- This returns a 32-bit pseudo-random integer from a RG32 state
function RG32rand32(state)
  if state.phase == 1 then
    state.phase = 2
  elseif state.phase == 2 then
    state.phase = 3
  else
    state.phase = 2
    beltMill(state.belt,state.mill)
  end
  return state.mill[state.phase]
end

-- print(RG32sum("1234"))
 

function processQuery(Q) -- Called for every DNS query received
  -- Because this code uses multiple co-routines, always use "local"
  -- variables

  -- Log query
  coDNS.log("Got IPv4 query for " .. Q.coQuery .. " from " ..
            Q.coFromIP .. " type " ..  Q.coFromIPtype .. 
            " query type " .. Q.coQtype) 

  local rgn = RG32sum(Q.coQuery)
  rgn = string.sub(rgn,1,32) -- First 128-bits
  -- Right now, coLunacyDNS can *only* process "A" (IPv4 IP) and
  -- "ip6" (IPv6 IP) queries
  if Q.coQtype ~= 1 and Q.coQtype ~= 28 then -- If it is not an ipv4/v6 query
    -- return {co1Type = "ignoreMe"} -- Ignore the query
    return {co1Type = "notThere"} -- Send "not there" (like NXDOMAIN)
  end

  if Q.coQtype == 1 then
    return {co1Type = "A", co1Data = "127.0.0.1" } 
  elseif Q.coQtype == 28 then
    return {co1Type = "ip6", co1Data = rgn} 
  end
  return {co1Type = "notThere"} 
end
