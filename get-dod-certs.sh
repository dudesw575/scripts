#!/bin/bash
# DoD Root Certificate install 19 July 2019
# to do: add Firefix import
#        set cert numbers as variables
#        combine fingerprint functions
#        check all root CA fingerprints
#        compare against CRL

SECONDS='0'
NC='\e[0m'
WHITE='\e[1;37m'
YELLOW='\e[1;33m'
LIGHT_BLUE='\e[1;34m'
CYAN='\e[0;36m'
RED='\e[0;31m'

version='5.6'
filename='certificates_pkcs7_v5-6_dod.zip'
domain=https://dl.dod.cyber.mil
url=${domain}/wp-content/uploads/pki-pke/zip/${filename}
root_pem='DoD_PKE_CA_chain.pem'
list='certutil unzip curl openssl dos2unix crlutil'
# The Root CA cert zip SHA-256 checksum
zip_sum='a073a68ba18eb6e9b31bcb82f3020311869b6a55aa8b93fbaf56b99c88cf503b'
dir=~/.dod_certs
exdir='Certificates_PKCS7_v5.6_DoD'
pki_dir=~/.pki
#cert_num={35..48} {53..65}
cert_url=https://crl.gds.disa.mil
crl_list=${domain}/wp-content/uploads/pki-pke/txt/unclass-dod_eca_crldps_nipr_20190529.txt

# Check if root
if [[ $EUID = 0 ]]; then
   echo -e "${RED}Do not run as root. Exiting.${NC}\n"
   exit 1
fi

echo -e "\nThis will download. validate, and install the following DoD 
certificates:\n\n\
    - ${LIGHT_BLUE}DoD Root Certificate Bundle${NC} version 
${WHITE}${version}${NC} from ${CYAN}public.cyber.mil\n\
    - ${LIGHT_BLUE}DoD ID CAs 33-34, 39-44, 49-52, 59${NC} from 
${CYAN}crl.gds.disa.mil${NC}\n\
    - ${LIGHT_BLUE}DoD ID SW CAs 35-38, 45-48${NC} from 
${CYAN}crl.gds.disa.mil${NC}\n\
    - ${LIGHT_BLUE}DoD SW CAs 53-58, 60-611${NC} from 
${CYAN}crl.gds.disa.mil${NC}\n\n\
More info: 
${CYAN}https://public.cyber.mil/pki-pke/pkipke-document-library/${NC}\n\n\
Required software: ${WHITE}${list}${NC}"
echo -e "\n"
read -p "Do you want to continue? [y/n] " choice
case "$choice" in 
    [yY]|[yY][eE][sS])
        echo ""
        echo -e "${YELLOW}Starting...${NC}\n"
        ;;
    n|N|no|No|NO )
        echo ""
        echo -e "${RED}Exiting.${NC}\n"
        exit 1
        ;;
    * ) 
        echo ""
        echo -e "${RED}Invalid option. Exiting.${NC}\n"
        exit 2
        ;;
esac

# functions

displaytime () {
   local T=$SECONDS
   local D=$((T/60/60/24))
   local H=$((T/60/60%24))
   local M=$((T/60%60))
   local S=$((T%60))
   [[ $D > 0 ]] && printf '%d days ' $D
   [[ $H > 0 ]] && printf '%d hours ' $H
   [[ $M > 0 ]] && printf '%d minutes ' $M
   [[ $D > 0 || $H > 0 || $M > 0 ]] && printf 'and '
   printf '%d seconds\n' $S
}

validate_fingerprint () {
    fingerprint2=$(curl --silent \
    'https://crl.gds.disa.mil/viewsign?DOD+ROOT+CA+3' \
    -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) 
Gecko/20100101 Firefox/68.0' \
    -H 'Accept: text/html, */*; q=0.01' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    --compressed \
    -H 'Referer: https://crl.gds.disa.mil/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    -H 'DNT: 1' \
    -H 'Connection: keep-alive' \
    -H 'Cookie: sawGDSwarning=1' \
    | grep SHA-1 | sed -e 's/<\/b>/-/g' -e 's/<[^>]*>//g' | awk '{ print 
$2 }')
}

get_fingerprint_remote () {
    format=${1}
    num=${2}
    if [[ "${format}" == "DODIDCA_" ]]; then
        req=DOD+ID+CA-
    elif [[ "${format}" == "DODIDSWCA_" ]]; then
        req=DOD+ID+SW+CA-
    elif [[ "${format}" == "DODSWCA_" ]]; then
        req=DOD+SW+CA-
    elif [[ "${format}" == "DODROOTCA" ]]; then
        req=DOD+ROOT+CA+
    else
        echo no value
        exit 2
    fi
    fingerprint_remote=$(curl --silent \
    "${cert_url}/viewsign?${req}${num}" \
    -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) 
Gecko/20100101 Firefox/68.0' \
    -H 'Accept: text/html, */*; q=0.01' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    --compressed \
    -H 'Referer: https://crl.gds.disa.mil/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    -H 'DNT: 1' \
    -H 'Connection: keep-alive' \
    -H 'Cookie: sawGDSwarning=1' \
    | grep SHA-1 | sed -e 's/<\/b>/-/g' -e 's/<[^>]*>//g' | awk '{ print 
$2 }')
}

get_fingerprint_local () {
    type=${1}
    num=${2}
    fingerprint_local=$(openssl x509 -noout -fingerprint -sha1 -inform pem 
-in ${type}${num}.pem  | tr -d ":" | sed -e 's/SHA1\ Fingerprint\=//')
}

compare_fingerprint () {
    echo -e "SHA-1 fingerprint local file  
${WHITE}${fingerprint_local}${NC}"
    echo -e "SHA-1 fingerprint from source 
${WHITE}${fingerprint_remote}${NC}"
    if [[ "${fingerprint_local}" == "${fingerprint_remote}" ]]; then
    local _ret=$?
    if [ $_ret -ne 0 ] ; then
        echo "compare_fingerprint returned with exit code $_ret, 
aborting!" >&2
        return $_ret
    else
        echo "  SHA-1 fingerprints match. Safe to proceed."
        echo ""
        return $_ret
    fi
fi
}

download () {
    format=${1}
    num=${2}
    if [[ "${format}" == "DODIDCA_" ]]; then
        req=DOD+ID+CA-
    elif [[ "${format}" == "DODIDSWCA_" ]]; then
        req=DOD+ID+SW+CA-
    elif [[ "${format}" == "DODSWCA_" ]]; then
        req=DOD+SW+CA-
    elif [[ "${format}" == "DODROOTCA" ]]; then
        req=DOD+ROOT+CA+
    else
        echo no value
        exit 2
    fi
    echo -e "Downloading 
${LIGHT_BLUE}${LIGHT_BLUE}${type}${x}.cer${NC}..."
    cd ${dir}
    curl --silent \
    "${cert_url}/getsign?${req}${num}" \
    -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) 
Gecko/20100101 Firefox/68.0' \
    -H 'Accept: 
text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    --compressed \
    -H 'Referer: https://crl.gds.disa.mil/' \
    -H 'DNT: 1' \
    -H 'Connection: keep-alive' \
    -H 'Cookie: sawGDSwarning=1' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -o ${type}${num}.cer
    local _ret=$?
    if [[ $_ret -ne 0 ]] ; then
        echo "${RED}Download failed returned with exit code $_ret, 
aborting!${NC}" >&2
        return $_ret
        exit 1
    else
        echo "  Download successful."
        echo ""
        return $_ret
    fi
}

download_root () {
# Download the root CA certs archive file
    curl --silent -o ${dir}/${filename} ${url}
# Get the local file checksum
    zip_sum_dl=$(sha256sum ${dir}/${filename} | awk '{ print $1 }')
    if [[ "${zip_sum}" == "${zip_sum_dl}" ]]; then
        echo -e "Download success: ${WHITE}${filename}${NC} SHA 256 
matches. Proceeding...\n"
    else
        echo -e "${RED}Warning: ${filename} SHA 256 does not match 
${zip_sum}${NC}"
        echo -e "Exiting.\n"
        exit 1
fi
# Extract cert 
    unzip -q ${filename} -d ${dir}
    cd ${dir}/${exdir}
}

convert () {
    format=${1}
    num=${2}
    echo -e "Converting ${LIGHT_BLUE}${type}${x}.cer${NC} to 
${LIGHT_BLUE}${type}${x}.pem${NC}..."
    cd ${dir}
    openssl x509 -inform der -in ${format}${num}.cer -outform pem -out 
${format}${num}.pem
    local _ret=$?
    if [[ $_ret -ne 0 ]] ; then
        echo "${RED}openssl convert failed and returned with exit code 
$_ret, aborting!${NC}" >&2
        return $_ret
        exit 1
    else
        echo "  Convert successful."
        echo ""
        return $_ret
    fi
}

get_crl_list () {
    file='crl_tmp.txt'
    curl -o ${file} --silent ${crl_list}
    sed -i '/#####\ ECA\ PKI\ #####/,$d' ${file}
    sed -i '/#####\ DoD\ PKI\ #####/,$!d' ${file}
    sed -i '/#####\ DoD\ PKI\ #####/d' ${file}

# Check for installed software
for sw in ${list}; do
	echo -ne "Checking if ${WHITE}${sw}${NC} is installed..."
    if ! [ -x "$(command -v ${sw})" ]; then
        echo -e "${RED}Error: ${WHITE}${sw}${NC}${RED} is not installed. 
Please install ${sw}. Exiting.${NC}\n" >&2
        exit 1     
    else
	echo -e " Done."
    fi
done

# Check internet connectivity
if curl --output /dev/null --silent --head --fail "${url}"; then
    echo -e "\nURL is accessible: ${CYAN}${url}${NC}. Proceeding...\n"
    else
        echo -e "\n${RED}Warning: Unable to access: 
${CYAN}${url}${NC}${RED}. Exiting.${NC}\n"
	exit 1
fi

# Cleanup old mess
if [[ -d ${dir} ]]; then
	echo -e "Removing old certs download...\n"
	rm -rf ${dir}
	mkdir -p ${dir}
        cd ${dir}
    else
    	echo -e "Creating tmp working dir...\n"
	mkdir -p ${dir}
        cd ${dir}
fi

# Backup user .pki dir
echo -e "Backing up existing NSS PKI directory (${pki_dir}).\n"
cp -a ${pki_dir} ${pki_dir}_$(date +%Y%m%d)

# # Download the root CA certs archive file
# curl --silent -o ${dir}/${filename} ${url}
# zip_sum_dl=$(sha256sum ${dir}/${filename} | awk '{ print $1 }')
# if [[ "${zip_sum}" == "${zip_sum_dl}" ]]; then
# 	echo -e "Success: ${WHITE}${filename}${NC} SHA 256 matches. 
Proceeding...\n"
# else
# 	echo -e "${RED}Warning: ${filename} SHA 256 does not match 
${zip_sum}${NC}"
# 	echo -e "Exiting.\n"
# 	exit 1
# fi# 

# # Extract cert 
# unzip -q ${filename} -d ${dir}
# cd ${dir}/${exdir}

# Verify
echo -e "Determine the Fingerprint of DoD Root CA 3\n"
fingerprint1=$(openssl x509 -noout -fingerprint -sha1 -inform pem -in 
${dir}/${exdir}/${root_pem} | tr -d ":" | sed -e 's/SHA1\ 
Fingerprint\=//')

validate_fingerprint

#echo -e "Fingerprint 1= ${WHITE}${fingerprint1}${NC}"
#echo -e "Fingerprint 2= ${WHITE}${fingerprint2}${NC}"
echo ""
# Compare DoD Root CA 3 fingerprint
if [[ "${fingerprint1}" == "${fingerprint2}" ]]; then
	echo -ne "Comparing SHA1 fingerprints..."
	echo -ne "  SHA1 fingerprints match."
	echo -e " Proceeding...\n"
	subjects=$(openssl crl2pkcs7 -nocrl -certfile 
${dir}/${exdir}/${root_pem} | openssl pkcs7 -print_certs -noout | sed 
'/^[[:space:]]*$/d')
	echo -e "Will import following ROOT certificates:\n"
	echo -e "${CYAN}${subjects}${NC}"
	echo ""
	echo -e "Verifying smime SHA256 signature of certificates...\n"
	openssl smime -verify -in Certificates_PKCS7_v5.6_DoD.sha256 
-inform DER -CAfile ${root_pem} | dos2unix | sha256sum -c
	    ret_val=$?
	    echo ""
            if [[ $ret_val -ne 0 ]]; then
                echo -e "${RED}Warning: SHA 256 signatures do not match. 
Exiting.${NC}\n"
                exit 1
            else
            	echo -e "Proceeding to import...\n"
            fi
	    for i in ${dir}/${exdir}/*.der.p7b; do
		echo -ne "Importing ${i}..."
	        certutil -d sql:$HOME/.pki/nssdb -A -t TC -n ${i} -i ${i}
		echo -e " Done."
        done
    else
    	echo -e "${RED}Warning: SHA1 Fingerprints do not match. 
Exiting.${NC}\n"
    	exit 1
fi

# DODIDSWCA
for x in {35..38} {45..48}; do
    type='DODIDSWCA_'
    download ${type} ${x}
    convert ${type} ${x}
    get_fingerprint_remote ${type} ${x}
    get_fingerprint_local ${type} ${x}
    compare_fingerprint
done

# DODIDCA
for x in {33..34} {39..44} {49..52} 59; do
    type='DODIDCA_'
    download ${type} ${x}
    convert ${type} ${x}
    get_fingerprint_remote ${type} ${x}
    get_fingerprint_local ${type} ${x}
    compare_fingerprint
done

# DODSWCA
for x in {53..58} {60..61}; do
    type='DODSWCA_'
    download ${type} ${x}
    convert ${type} ${x}
    get_fingerprint_remote ${type} ${x}        
    get_fingerprint_local ${type} ${x}
    compare_fingerprint
done

# DODROOTCA
for x in {1..6}; do
    type='DODROOTCA'
    download_root
    get_fingerprint_remote ${type} ${x}
    get_fingerprint_local ${type} ${x}
done

read -p "Delete tmp dir (y/n)?" choice
case "$choice" in 
    y|Y ) 
        echo -e "Deleting tmp dir (${dir})...\n"
        if [[ -d ${dir}  ]]; then
	    echo -e "Cleaning up...\n"
	    rm -rf ${dir}
        fi
	;;
    n|N ) 
        echo "Preserving tmp dir."
	;;
    * ) 
        echo -e "${RED}Invalid option. Doing nothing.${NC}\n"
	;;
esac

echo "Took $(displaytime) to complete ${0}."

exit 0

