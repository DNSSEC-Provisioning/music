## MUSIC

MUSIC, Multi-Signer Controller, is a proof of concept software implementation of the 
[dnsop-dnssec-automation](https://datatracker.ietf.org/doc/draft-ietf-dnsop-dnssec-automation/) 
Internet Draft. Based on the following RFCs:

* [RFC8901](https://datatracker.ietf.org/doc/rfc8901/) "Multi-Signer DNSSEC Models"
* [RFC8078](https://datatracker.ietf.org/doc/rfc8078/) "Managing DS Records from the Parent
  via CDS/CDNSKEY"
* [RFC7477](https://datatracker.ietf.org/doc/rfc7477/) "Child-to-Parent Synchronization in
  DNS"

### Install MUSIC 
This is just enough to get MUSIC up and running.
W.I.P
```

git clone git@github.com:DNSSEC-Provisioning/music.git
cd music

make all

cd musicd
make
make install

cd ../music-cli 
make
make install

```

### Configure MUSIC

* By default MUSIC uses config files located in-tree, in the directory
  music/etc/. If you want to use a more stable location, please change
  the variable DefaultCfgFile in the two files music/musicd/defaults.go
  and music/music-cli/cmd/defaults.go to something you like better
  (eg. like /etc/music/...).

  Note that the variable DefaultCfgFile has different values for musicd
  and music-cli, respectively

### Suggestions for a simple MUSIC test lab setup

* Decide on a set of zone names that are easy to remember, like
  test1.example. test2.example., test3.example., etc. Generate
  zone files with some trivial contents for all the zones.

* Configure the zones as primary zones on two separate authoritative
  nameservers under your control. Note that you should copy the zone
  files to both servers.

* Setup DNSSEC for the zones on both servers. I.e. if using BIND9 add
  a "inline-signing yes; auto-dnssec maintain;" statements to each
   zone statement. The reason to not use the more modern "dnssec-policy"
   configuration is to avoid having BIND9 initiate key rollovers.

* Generate a TSIG key for each server that may be used to update the zones:
```
bash# tsig-keygen my.test.key.
key "signer1.key." {
	algorithm hmac-sha256;
	secret "h1j2pj-PLEASE-GENERATE-YOUR-OWN-KEYS-ZqwFSnmGGKuk6o=";
};
``` 

* Add an "update-policy" that allows holders of the TSIG key to update
  DNSKEY, CDS, CDNSKEY, CSYNC and NS RRs in the MUSIC test zones.

* Example BIND9 configuration for a test zone:
```
        zone "music1.example" {
                type primary;
                inline-signing yes;
                auto-dnssec maintain;
                key-directory "/etc/domain/keys";
                update-policy { grant signer1.key. name music1.example. DNSKEY CDS CDNSKEY CSYNC NS; };
                file "/etc/domain/test/music1.example";
        };
```

* [TODO] Add minimal test lab description
* [TODO] Add explanation of config settings
* [TODO] Add list of test scenarios
