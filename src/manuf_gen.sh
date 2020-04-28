#! /bin/bash

# This script will generate macvlist.h

echo "struct _macvendor macv_list[] = {"

grep '^[0-9A-F][0-9A-F]\:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]' manuf | tr -s '[:space:]' | while read line; do
	linec=`echo "${line}" | sed 's/\t/ /g'`
	mac=`echo "${linec}" | awk '{ print $1; }'`
	name=`echo "${linec}" | cut -f2- -d' ' | sed 's/[^[:alpha:]. ()]//g'`
	macc=`echo "${mac}" | sed 's/:/, 0x/g'`;
	echo  "{{0x${macc}}, \"${name}\"},"
done

echo "{{0x00, 0x00, 0x00}, NULL}"
echo "};"

