#!/bin/bash
#
# Read a list of URLs from stdin and print if the url is Ok (200 or 301 with one redirect to a 200)
#
#

while read line
do
    status_code=$(curl --write-out %{http_code} --max-redirs 1 --silent --output /dev/null  -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0" -m 2 -s --head  --request GET -L ${line})
    if [[ "$status_code" -ne 200 ]] ; then
        echo "Nok (${status_code}): ${line}"
    else
        echo "Ok (${status_code}): ${line}"
    fi
done

