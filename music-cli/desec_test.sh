../sbin/music-cli signergroup add -g desec -v -d
../sbin/music-cli signer add -s signer1 --address 13.53.206.47 --method ddns --auth musiclab:ZZkwxLJ06pCbmN0GvhdX4NKXPUST2gLSvxPa1A4sI9c= -v -d
../sbin/music-cli signer add -s desec1 --address 45.54.76.1 --port 53 --method desec-api
../sbin/music-cli signer join -s signer1 -g desec -v -d
../sbin/music-cli zone add -z desec.catch22.se -g desec -v -d
../sbin/music-cli zone meta -z desec.catch22.se --metakey parentaddr --metavalue 13.48.238.90:53 -v -d
../sbin/music-cli signer join -s desec1 -g desec
