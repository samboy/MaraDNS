cloak = {
name = "A velvet cloak", noun = "clo",
description = "A handsome cloak, of velvet trimmed with satin, and slightly\n"
            .. "spattered with raindrops. Its blackness is so deep that it\n"
            .. "almost seems to suck light from the room.",
carry = false, -- Because it can only be dropped/picked up in cloakroom
carryWhy = "This isn't the best place to leave a smart cloak laying around"
}

message = {
name = "A message on the floor", noun="mes",
description = "The message, neatly marked in the sawdust, reads\n" ..
  "You have won",
carry = false
}

hook = {
name = "A small brass hook", noun="hoo",
description = "It's just a small brass hook, screwed to the wall.",
carry = false
}

inventory = { cloak }

foyer = {
name = "foyer",
description = "You are standing in a spacious hall, splendidly decorated in"
.. "\nred and gold, with glittering chandeliers overhead. The entrance from"
.. "\nthe street is to the north, and there are doorways south and west.",
n = "You've only just arrived, and besides, the weather outside\n" ..
"seems to be getting worse.", items = {}
}


cloakroom = {
name = "cloakroom",
description = "The walls of this small room were clearly once lined with " ..
"hooks,\nthough now only one remains. The exit is a door to the east.",
e = function()
  location = foyer
  cloak.carry = false
end,
items = { hook }
}

bar = {
name = "bar",
dark = "It is too dark to see!",
light = "The bar, much rougher than you'd have guessed after the "
.. "opulence\nof the foyer to the north, is completely empty. There seems to"
.. "\nbe some sort of message scrawled in the sawdust on the floor.",
isLight = false,
n = foyer, items = { message }
}

cloak.onDrop = function()
  bar.isLight = true
  hook.description = "It's just a small brass hook, with a cloak on it."
  return "You put the cloak on the hook."
end
cloak.onGet = function()
  bar.isLight = false
  hook.description = "It's just a small brass hook, screwed to the wall."
end

-- We need function closure to track how many times we do stuff in the
-- bar
function makeBarMoveFunction()
  local barMoveCount = 0
  return function()
    if not bar.isLight then
      barMoveCount = barMoveCount + 1
      if barMoveCount < 3 then
        print("In the dark? You could easily disturb something!")
      else
        print("Blundering around in the dark isn't a good idea!")
        message.description = "The message has been carelessly trampled, "
                  .. " making it difficult to read.\n" ..
                  "You can just distinguish the words...\nYou have lost"
      end
    end
  end
end
bar.onAction = makeBarMoveFunction()

-- Since the cloakroom and bar are now defined, we can give the foyer exits
foyer.w = function()
  location = cloakroom
  cloak.carry = true
end

foyer.s = bar

function regexSplit(subject, splitOn)
  if not splitOn then splitOn = "," end
  local place = true
  local out = {}
  local mark
  local last = 1
  while place do
    place, mark = string.find(subject, splitOn, last, false)
    if place then
      table.insert(out,string.sub(subject, last, place - 1))
      last = mark + 1
    end
  end
  table.insert(out,string.sub(subject, last, -1))
  return out
end

function expand(command)
  if command:find("^%s*n%s*$") then -- Maybe space - "n" - maybe space
    return "go north"
  elseif command:find("^%s*s%s*$") then -- Maybe space - "s" - maybe space
    return "go south"
  elseif command:find("^%s*e%s*$") then -- Maybe space - "e" - maybe space
    return "go east"
  elseif command:find("^%s*w%s*$") then -- Maybe space - "w" - maybe space
    return "go west"
  elseif command:find("^%s*x%s+") then -- "x" short for "examine"
    return command:gsub("^%s*x%s+","examine ")
  end
  return command
end

-- Go to a location.  Reads and affects the global variable "location"
function go(noun)
  local direction = nil
  if noun == "north" or noun == "south" or
     noun == "east" or noun == "west" then
    direction = noun:sub(1,1) -- First letter, e.g. "north" becomes "n"
  else
    print("I do not know how to go " .. noun)
    return nil
  end
  if not location[direction] then
    print("You can not go that way.\n")
    return nil
  elseif type(location[direction]) == "string" then
    print(location[direction] .. "\n")
    return nil
  elseif type(location[direction]) == "function" then
    return location[direction]()
  elseif type(location[direction]) ~= "table" then -- Error detection
    print("Internal error trying to go " .. noun)
    return nil
  end
  location = location[direction]
  return true
end

-- This reads the global "location" and affects the table for
-- the room the player is in, as well as the player inventory
function get(noun)
  if not location.items then -- Error correction
    print("I can not get anything in this location")
    return nil
  end
  subNoun = noun:sub(1,3)
  for item = 1,#location.items do
    if subNoun==location.items[item].noun and location.items[item].carry then
      local thisItem = location.items[item]
      table.insert(inventory,location.items[item])
      table.remove(location.items,item)
      if type(thisItem.onGet) == "function" then
        thisItem.onGet()
      end
      print("Carried\n")
      return true
    elseif subNoun==location.items[item].noun then -- Can not be carried
      if location.items[item].carryWhy then
        print(location.items[item].carryWhy)
      else
        print("That item can not be carried")
      end
      print("")
      return nil
    end
  end
  print("I can not see the " .. noun .. " here.")
end

-- This reads the global "location" and affects the table for
-- the room the player is in, as well as the player inventory
function drop(noun)
  if not location.items then
    print("I can not drop anything in this location")
    return nil
  end
  subNoun = noun:sub(1,3)
  for item = 1,#inventory do
    if subNoun == inventory[item].noun and inventory[item].carry then
      local thisItem = inventory[item]
      table.insert(location.items,inventory[item])
      table.remove(inventory,item)
      message = "Dropped"
      if type(thisItem.onDrop) == "function" then
        message = thisItem.onDrop()
        if type(message) ~= "string" then
          message = "Dropped"
        end
      end
      print(message .. "\n")
      return true
    elseif subNoun == inventory[item].noun then -- Can not be dropped
      if inventory[item].carryWhy then
        print(inventory[item].carryWhy)
      else
        print("That item can not be dropped")
      end
      print("")
      return nil
    end
  end
  print("I am not carrying the " .. noun .. ".")
end

-- Print out what the character is carrying
function seeInventory()
  local seen = false
  print("You are carrying: ")
  for counter = 1, #inventory do
    if type(inventory[counter]) == "table" then
      print(inventory[counter].name)
      seen = true
    end
  end
  if not seen then
    print("Nothing")
  end
  print("")
end

-- Print out visible items in the room
function viewItems(place)
  if not place or not place.items or #place.items < 1 then
    return nil -- No items seen
  end
  print("")
  print("You can see: ")
  for counter = 1, #place.items do
    print(place.items[counter].name)
  end
  return true
end

-- Examine an item
function examine(noun)
  local fullNoun = noun
  noun = noun:sub(1,3) -- We match on first three letters
  -- Look in the player's inventory for the item
  for counter = 1, #inventory do
    if inventory[counter].noun == noun then
      print(inventory[counter].description .. "\n")
      return true
    end
  end
  -- Look in the room for the item
  for counter = 1, #location.items do
    if location.items[counter].noun == noun then
      print(location.items[counter].description .. "\n")
      return true
    end
  end
  print("I can not see the " .. fullNoun .. "\n")
  return false
end

-- Describe a room
function describeRoom(place)
  if place.description then
    print("You are in the " .. place.name .. "\n\n" .. place.description)
    viewItems(location)
  elseif place.isLight then
    print("You are in the " .. place.name .. "\n\n" .. place.light)
    viewItems(location)
  elseif place.dark then
    print(place.dark)
  else -- Error detection and handling
    print("This location has no description.")
  end
end

print("Hurrying through the rain swept November night, you're glad to see the"
.. "\nbright lights of the Opera House. It's surprising that there aren't more"
.. "\npeople about but, hey, what do you expect in a cheap demo game...?\n")

location = foyer

repeat

  describeRoom(location)

  if lastLocation == location and type(location.onAction) == "function" then
    location.onAction()
  end
  lastLocation = location

  io.stdout:write("Tell me what to do> ")
  command = io.stdin:read("*l")

  command = command:lower() -- Case insensitive
  command = expand(command) -- process common interaction fiction abbreviations
  command = command:gsub("^%s+","") -- Remove leading whitespace

  words = regexSplit(command,"%s+")

  -- Look for prepositional phrase
  local preposition = nil
  local prepObject = nil
  for counter = 1, #words - 1 do
    if words[counter] == "on" then -- The only preposition this game has
      preposition = words[counter]
      table.remove(words,counter)
      prepObject = words[counter]
      table.remove(words,counter)

    elseif words[counter] == "at" then -- Allow "look at" to be "look"
      table.remove(words,counter)
    end
  end

  -- Now, grab the verb and noun
  local verb = nil
  local noun = nil
  if #words >= 2 then
    verb = words[1]
    verb = verb:sub(1,3)
    noun = words[2]

  elseif #words == 1 and (words[1] == "i" or words[1]:sub(1,3) == "inv") then
    seeInventory()
  elseif #words < 2 then
    print("Sorry, I can not understand you.\n")
  end

  if verb == "go" or verb == "mov" then -- mov: Move
    go(noun)
  elseif verb == "get" or verb == "car" then -- car: Carry
    get(noun)
  elseif verb == "put" or verb == "dro" then -- dro: drop
    drop(noun)
  elseif verb=="loo" or verb=="exa" or verb=="rea" then -- look/examine/read
    examine(noun)
  elseif verb then
    print("Sorry, I can not understand you.\n")
  end

until false
