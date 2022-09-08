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

* [TODO] Add minimal test lab description
* [TODO] Add explanation of config settings
* [TODO] Add minimal test lab description
