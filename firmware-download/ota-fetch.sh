echo "DO NOT RUN THIS ON THE CLOUD. YOUR TONIEBOX WILL LIKELY GET BLACKLISTED AND CLOUD ACCESS REVOKED. THIS WILL BRICK YOUR TONIEBOX!"
exit 1

#SERVER="https://prod.de.tbs.toys"
SERVER="https://10.0.0.2"
#SERVER="http://127.0.0.1:8000"
# --cacert /tmp/certs/client/ca.der did not work; using -k
FILE=6
curl "$SERVER/v1/ota/$FILE?cv=1640950635" -A 'RoseRed TB/1640950635' -H 'Accept:' \
-k \
--cert-type DER --cert /tmp/teddycloud/certs/client/client.der \
--key-type DER --key /tmp/teddycloud/certs/client/private.der \
--output $FILE # --no-check-certificate

