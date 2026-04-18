#!/bin/sh

for a in origin sourcehut bitbucket codeberg sourceforge ; do
  echo $a
  git push $a
  echo
done

echo Gitlab annoyance: I had to use Chrome to update my SSH key
git push gitlab
echo

cat > /dev/null << EOF
[remote "origin"]
        url = git@github.com:samboy/MaraDNS.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[remote "sourcehut"]
        url = git@git.sr.ht:~samiam/MaraDNS
[remote "bitbucket"]
        url = git@bitbucket.org:maradns/maradns.git
[remote "codeberg"]
        url = git@codeberg.org:samboy/MaraDNS.git
[remote "gitlab"]
        url = git@gitlab.com:maradns/maradns.git
[remote "sourceforge"]
        url = ssh://samboy@git.code.sf.net/p/maradns-git/code
EOF

