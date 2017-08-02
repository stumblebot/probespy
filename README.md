# Probespy 
Probespy is a dumb and dirty tool for analyzing directed and broadcast probe request data sent by wifi client devices.

Usage:  bash probespy.sh -c <dir> -d <dir>
        bash probespy.sh -c <dir> -d <dir> -l <"lat,lng"> -r <miles>
        bash probespy.sh -c <dir> -d <dir> -l <"lat,lng"> -r <miles> -f <txt|html>
Options:
-c: The directory to read pcap files from
-f: Report output format
	  Options: html or txt
-d: The directory to write the current report to
-l: The location to bound our SSID search to
-r: The distance to search from the coordinate
	  designated by -l
-h: Display this help
