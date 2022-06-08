%       SOA     % email@% 1 7200 3600 604800 1800 ~

%       NS      ns1.% ~
%       NS      ns2.% ~

ns1.%   A 10.1.2.3 ~
ns2.%   A 10.1.2.4 ~
_acme-challenge.% +30 CNAME example-com.letsencrypt-verify.example.com. ~
letsencrypt-verify.% NS ns1.letsencrypt-verify.% ~
ns1.letsencrypt-verify.% A 10.1.2.3 ~

%               10.2.2.2           ~

