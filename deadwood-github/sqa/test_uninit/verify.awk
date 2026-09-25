#!/usr/bin/awk -f

BEGIN {
  a["137a45b055a771a7"] = "@"
  a["3e012a3197f5bc10"] = "A"
  a["db024ef413e07bf9"] = "B"
  a["e4c59395700c0f7e"] = "C"
  a["336f4af3f0dee2db"] = "D"
  a["8f748c8bd1507646"] = "E"
  a["f6c0dfb46d175d6b"] = "F"
  a["d698a880d522f33c"] = "G"
  a["4e7b8d5b7331f153"] = "H"
  a["ef4bb7950d9bb1bd"] = "I"
  a["6484ecdf19908d79"] = "J"
  a["bebc904e60a98229"] = "K"
  a["ecc5690427ecd2dc"] = "L"
  a["a3779663486121f3"] = "M"
  a["c2838c67c2cf0a30"] = "N"
  a["52ef34dd3e6cb6a7"] = "O"
  a["b5b1d6618bdd1f28"] = "P"
  a["370ac9ef5b310999"] = "Q"
  a["74a9f425805dcb1a"] = "R"
  a["e678d08dab001a8b"] = "S"
  a["39f9bd2e6bc272ba"] = "T"
  a["8ff4028e00c0d9be"] = "U"
  a["e59dcb8b3203a854"] = "V"
  a["0433cac6b9bce5e4"] = "W"
  a["ee86038fec0298ca"] = "X"
  a["e2debd407b8321fd"] = "Y"
  a["06ce9bfbd02ccb8d"] = "Z"
  a["c72ce031596383bc"] = "["
  a["a32402e5ab36e349"] = "\\"
  a["75745db836680c9b"] = "]"
  a["2eef723a6de94374"] = "_"
  out = ""
}

{out = $1}

END {
  if(a[out]) {
    print "SECURE: We used " a[out]
  } else {
    print "INSECURE: RG32 not correctly run"
  }
}

