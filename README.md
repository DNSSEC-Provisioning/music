### MUSIC

MUSIC, Multi-Signer Controller, is a proof of concept software implementation of the 
[dnsop-dnssec-automation](https://datatracker.ietf.org/doc/draft-ietf-dnsop-dnssec-automation/) 
Internet Draft. Based on the following RFCs:

* [RFC8901](https://datatracker.ietf.org/doc/rfc8901/) "Multi-Signer DNSSEC Models"
* [RFC8078](https://datatracker.ietf.org/doc/rfc8078/) "Managing DS Records from the Parent
  via CDS/CDNSKEY"
* [RFC7477](https://datatracker.ietf.org/doc/rfc7477/) "Child-to-Parent Synchronization in
  DNS"


## W.I.P
### Requirements:
* Working golang installation

### Download and Install MUSIC 

This is just enough to get MUSIC up and running.

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

## Configure MUSIC

* By default MUSIC uses config files located in-tree, in the directory
  music/etc/. If you want to use a more stable location, please change
  the variable DefaultCfgFile in the two files music/musicd/defaults.go
  and music/music-cli/cmd/defaults.go to something you like better
  (eg. like /etc/music/...).

  Note that the variable DefaultCfgFile has different values for musicd
  and music-cli, respectively

## Suggestions for a Simple MUSIC Test Lab Setup

* Decide on a set of zone names that are easy to remember, like
  music1.example. music2.example., music3.example., etc. Generate
  zone files with some trivial contents for all the zones.

* Configure the zones as primary zones on two separate authoritative
  nameservers under your control. Note that you should copy the zone
  files to both servers. We will refer to these two servers as "signer1"
  and "signer2" respectively.

* Setup DNSSEC for the zones on both signers. I.e. if using BIND9 add
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
Add the TSIG key to the nameserver configuration on each signer.

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

When all this is done you should have two nameserver, signer1 and
signer2, each with its own TSIG key to authenticate updates. You
should also have several DNSSEC signed zones served by both signers
and with update policies that enable remote updates to the RRs that
MUSIC needs to control.

* Everything is now ready for you to set up MUSIC itself.

## Configuring MUSIC and Starting the MUSICD Server

* Once certs, etc, are in order, get the MUSIC server running in a separate terminal window.
  There will be lots of output:
```
bash# musicd -v
LoadConfig: reloading config from "../etc/musicd.yaml". Safemode: false
2022/11/04 14:02:01 NewMusicDB: using sqlite db in file /var/tmp/music.db
2022/11/04 14:02:01 NewDB: Running DB in WAL (write-ahead logging) mode.
Setting up missing tables
NewClient: Creating 'deSEC' API client based on root CAs in file '../etc/certs/PublicRootCAs.pem'
Setting up deSEC API client:
* baseurl is: https://desec.io/api/v1 
* apikey is:  
* authmethod is: Authorization 
2022/11/04 14:02:01 dbUpdater: Starting DB Update Service.
2022/11/04 14:02:01 Starting FSM Engine (will run once every 20 seconds)
2022/11/04 14:02:01 Starting DDNS Manager. Will rate-limit DDNS requests (queries and updates).
2022/11/04 14:02:01 Starting deSEC Manager. Will rate-limit deSEC API requests.
2022/11/04 14:02:01 Starting API dispatcher. Listening on 127.0.0.1:8080
2022/11/04 14:02:01 mainloop: entering signal dispatcher
```

### Verifying that Interaction between MUSIC-CLI and MUSICD Works

* The simplest test is to send a "ping" request via the MUSIC API and
see whether it was accepted:

```
bash# music-cli ping
Pings: 2 Pongs: 1 Message: TLS pong from musicd @ nyx.johani.org

```
If the response is a "pong", then all is good, TLS is working correctly, etc.

## Do a Simple Test
* Add the two signers to MUSIC:
```
bash# music-cli signer add -v -s S1 --method ddns --address 1.2.3.4 --auth hmac-sha256:signer1.key.:YOUR-SIGNER1-KEY 
Using config file: ../etc/music-cli.yaml
New signer S1 successfully added.
bash# music-cli signer add -s S2 --method ddns --address 4.3.2.1 --auth hmac-sha256:signer2.key.:YOUR-SIGNER2-KEY 
New signer S2 successfully added.
```
* Verify that MUSIC now knows about your new signers:
```
bash# music-cli signer list -H
Signer   Method  Address          Port  SignerGroups
S1       ddns    1.2.3.4          53    ---
S2       ddns    4.3.2.1          53    ---
```
Note that the signers do not belong to any signer group (yet).
Let's create a signer group.

### Create a MUSIC Signer Group
```
bash# music-cli signergroup add -g GROUP1
Signergroup GROUP1 created.
bash# music-cli signer join -s S1 -g GROUP1 
Signer S1 has joined signer group GROUP1 as the first signer. No zones entered the 'add-signer' process.
```

The reason for the message about no zones entering the 'add-signer'
process is (obviously) that we don't have any zones in MUSIC yet. If
there were zones associated the the signer group GROUP1 and a new signer
was added to the group, then those zones would have to go through the
'add-signer' process, as that's the whole point with the Multi-Signer
design.

### Add a Couple of Zones to MUSIC

* It is possible to add zones without attaching them to a signer
group. Then MUSIC will not do anything with the zone:

```
bash# music-cli zone add -z music1.example  
Zone music1.example. was added but is not yet attached to any signer group.
```

* It is also possible to add a new zone and immediately attach it to a
signer group. Then MUSIC will ensure that the zone is in sync with all
the signers in that signer group (i.e. initiate the 'add-signer'
process for the new zone):

```
bash# music-cli zone add -z music2.example -g GROUP1
Zone music2.example. was added and immediately attached to signer group GROUP1.
bash# music-cli zone add -z music3.example -g GROUP1
Zone music3.example. was added and immediately attached to signer group GROUP1.
```

* If we check the status of the zones we see that the zones attached
to the signer group GROUP1 started their progress through the
'add-signer' process:

```
bash# music-cli zone list -H                               
Zone                       SignerGroup  Process     State             Timestamp            Next State(s)
music1.example.     ---          ---         IN-SYNC           2022-11-04 13:24:53  []
music2.example.     GROUP1       add-signer  signers-unsynced  2022-11-04 13:25:05  [dnskeys-synced]
music3.example.     GROUP1       add-signer  signers-unsynced  2022-11-04 13:25:19  [dnskeys-synced]

bash# music-cli signergroup list -H
Group   Locked  Signers   # Zones  # Proc Zones  Current Process  PendingAddition  PendingRemoval
GROUP1  false   S1        2        2             ---              ---              ---
```

* Let's add the third zone to the signer group:

```
bassh# music-cli zone join -z music1.example -g GROUP1 -v
Using config file: ../etc/music-cli.yaml
Zone music1.example. has joined signer group GROUP1 and started the process 'add-signer'.
```

### Moving Zones Through a MUSIC Process Manually

```
../sbin/music-cli zone step-fsm -z music1.example -v
Using config file: ../etc/music-cli.yaml
Zone music1.example. did not transition from signers-unsynced to dnskeys-synced.
Latest stop-reason: dns: bad authentication
Zone                    SignerGroup  Process     State             Timestamp            Next State(s)
music1.example.  GROUP1       add-signer  signers-unsynced  2022-11-04 13:24:53  [dnskeys-synced]
```

### Moving Zones Through a MUSIC Process Automatically

```
bash# music-cli zone update -z music1.example --fsmmode auto
Zone music1.example. updated.

bash# music-cli zone list -H                                       
Zone                       SignerGroup  Process     State             Timestamp            Next State(s)
music1.example.[A]  GROUP1       add-signer  signers-unsynced  2022-11-04 13:24:53  [dnskeys-synced]
music2.example.     GROUP1       add-signer  signers-unsynced  2022-11-04 13:25:05  [dnskeys-synced]
music3.example.     GROUP1       add-signer  signers-unsynced  2022-11-04 13:25:19  [dnskeys-synced]
```

Note that there is an '[A]' after the name of the zone that we put in
"automatic" mode. This zone will now work its way through each step
automatically.

* [todo] Add minimal test lab description
* [TODO] Add explanation of config settings
* [TODO] Add list of test scenarios
