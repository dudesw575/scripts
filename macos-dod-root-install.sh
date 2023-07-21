export CERT_URL='https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip'

# Download & Extract DoD root certificates
cd ~/Downloads/

/usr/bin/curl -LOJ ${CERT_URL}
/usr/bin/unzip -o $(basename ${CERT_URL})

cd $(/usr/bin/zipinfo -1 $(basename ${CERT_URL}) | /usr/bin/awk -F/ '{ print $1 }' | head -1)

# Convert pem.p7b certs to straight pem and import
for item in *pem.p7b; do
  TOPDIR=$(pwd)
  TMPDIR=$(mktemp -d /tmp/$(basename ${item} .p7b).XXXXXX) || exit 1
  PEMNAME=$(basename ${item} .p7b)
  openssl pkcs7 -print_certs -in ${item} -out "${TMPDIR}/${PEMNAME}"
  cd ${TMPDIR}
  /usr/bin/split -p '^$' ${PEMNAME}
  rm $(ls x* | tail -1)
  for cert in x??; do
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert}
  done
  cd ${TOPDIR}
  rm -rf ${TMPDIR}
done
