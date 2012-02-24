#!/bin/sh

O=/usr/local/ssl/bin/openssl #path to rfc3779-enabled openssl
I=$1 #directory+basename for issuer-files, e.g. only_one_block/ripe/ripe
S=$2 #directory+basename for subject-files
$O x509 -days 3600 -extfile $S.ext -CA $I.cer -CAkey $I.key -set_serial 01 -sha256 -in $S.csr -req -out $S.cer && $O x509 -inform PEM -in $S.cer -outform DER -out $S.der && $O x509 -inform DER -in $S.der -text -out $S.txt