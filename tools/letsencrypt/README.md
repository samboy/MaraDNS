These are generic versions of the files I use for Letsencrypt
certificate updating.  This allows me to update all of my
domain certs running only a single shell script, `certbot.all.sh`.

Here is the general setup:

* I use DNS verification, and MaraDNS to host the DNS verified records
* The `_acme-challenge.example.com` record is a CNAME to a subdomain.
  The reason for the subdomain is so that the DNS records are only hosted
  on one DNS server, even though other records are mirrored across
  multiple DNS servers.
* The script is run on the same machine hosting the DNS records we
  verify.
* The `t-add`, `t-count`, and `t-zap` scripts are in `/usr/local/bin`
* The `run.certbot.sh`, `certbot.all.sh`, and `hook.sh` scripts are
  in `/root/certbot`
* The `db.example.com` and `db.letsencrypt-verify` files are in
  `/etc/maradns`
