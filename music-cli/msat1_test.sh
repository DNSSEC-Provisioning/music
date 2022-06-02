../sbin/music-cli signergroup add -g msat1 -v -d
../sbin/music-cli signer add -s signer1 --address 13.53.206.47 --method ddns --auth msat1tsig1:2LAWdXO9VDS6eqZ7OOl9j4ul7Z64i7zSJaSa9bhEq9I= -v -d
../sbin/music-cli signer add -s signer2 --address 13.53.34.31 --method ddns --auth msat1tsig2:bNFiS9LGTQbS7L2r+p7h7w/PMvZALBb5n9/umdnf3ow= -v -d
../sbin/music-cli signer join -s signer1 -g msat1 -v -d
../sbin/music-cli zone add -z msat1.catch22.se -g msat1 -v -d
../sbin/music-cli zone meta -z msat1.catch22.se --metakey parentaddr --metavalue 13.48.238.90:53 -v -d
../sbin/music-cli signer join -s signer2 -g msat1 -v -d
