#!/bin/bash

#TODO

#PRIORITY
#Local database lookup via wigle export
# figure out what is going on with the elongated lat/lng values

#BACK BURNER
#Centralized report file
#re-integrate direct capture from probespy
#update report display format
#active attacks??
# beacon honeypotting
#Change maps lookups to use openstreetmaps instead of google
#cluster search
#turn on/off location lookup
#sort a given run by profile mac address or SSID
#wigle billing status check

#set the internal field separator to newlines only
IFS=$'\n'

#Initialize variables from probespy.conf
#check if probespy.conf is present
if [[ -z "$(ls probespy.conf 2>/dev/null)" ]];
then 
	echo probespy.conf could not be found. Please create probespy.conf, in the current directory
	echo and add a WIGLE API key in the following format.
	echo
	echo WIGLE_API_KEY=\'AID0d903714c7d78b11a222c77b956d4200:e6c1b74909bdba1f331776e5b96c696f\'
else
	echo -n found probespy.conf
	#source conf file
	. probespy.conf
	if [[ -z "$(echo $WIGLE_API_KEY)" ]]
	then
		echo
		echo No WIGLE API key present. Please add a key to probespy.conf in the following format
		echo
		echo WIGLE_API_KEY=\'AID0d903714c7d78b11a222c77b956d4200:e6c1b74909bdba1f331776e5b96c696f\'
	else	
		echo ...WIGLE API key loaded
	fi
fi

userLocation=''

usage() {
	echo "Usage:  bash probespy.sh -c <dir> -d <dir>" 1>&2
	echo "        bash probespy.sh -c <dir> -d <dir> -l <\"lat,lng\"> -r <miles>" 1>&2
	echo "        bash probespy.sh -c <dir> -d <dir> -l <\"lat,lng\"> -r <miles> -f <txt|html>" 1>&2
#	echo "        bash probespy.sh -c <dir> -i <iface>" 1>&2
	echo "Options:" 1>&2
	echo "-c: The directory to read pcap files from" 1>&2
#	echo "-i: The network interface to capture packets on" 1>&2
	echo "-f: Report output format" 1>&2
	echo "	  Options: html or txt" 1>&2
	echo "-d: The directory to write the current report to" 1>&2
	echo "-l: The location to bound our SSID search to" 1>&2
	echo "-r: The distance to search from the coordinate" 1>&2
	echo "	  designated by -l" 1>&2
	echo "-h: Display this help" 1>&2
	exit 1 
}

#Defining script arguments
while getopts :i:c:f:d:l:r:g:h option;
do
        case $option in
        i)
                networkInterface=$OPTARG
		;;
	c)
		captureDir=$OPTARG
		;;
	f)
		reportFormat=$OPTARG
		;;
	d)
		reportDir=$OPTARG
		;;
	l)
		userLocation=$OPTARG
		;;
	r)
		searchRange=$OPTARG
		;;
	g)
		clusterSearch=$OPTARG
		;;
        h)
		usage
                ;;
	\?)
		echo "Invalid option: $OPTARG" 1>&2
		;;
	:)
		echo "option -$OPTARG needs an argument"
		exit
		;;
	esac
done

#Check for valid capture directory
if [ -z "$captureDir" ]; then
	echo "ERROR: supply a directory to read pcaps from"
	echo ""
	usage
fi

#Check for valid report directory
if [ -z "$reportDir" ]; then
	echo "ERROR: supply a directory to write report results"
	echo ""
	usage
fi

#Check for valid report format
if [ -z $reportFormat ]
then
	echo Report format was not set, Defaulting to TXT
	echo Report will be printed to stdout
elif [ $reportFormat == html ]
then
	echo Report format set to HTML
	echo Report will be written to $reportDir
elif [ $reportFormat == txt ]
then
	echo Report format set to TXT
	echo Report will be printed to stdout
else
	echo Reporting format $reportFormat is not recognized
	echo Please define a valid reporting format
	echo ------------------------------------------------
	usage
	exit
fi

#Check for valid user location
if [ -z $userLocation ]
then
	echo No location has been set to search within
	userLocation='NOLOC'
else
	echo -n Location has been set as: $userLocation
fi

echo \ with a range of $searchRange miles
echo ------------------------------------------------

#INITIALIZE MORE VARIABLES
dataDir=$(echo $reportDir/data/)
htmlDir=$(echo $reportDir/html/)


###############################################################################
#INTERFACE CAPTURE JUNK
# This code is not in use right now, but may be helpful if/when I re-implement 
# capturing probe requests from within probespy
###############################################################################
#clear pcaps from the ringbuffer directory
#rm ringbuffer/*

#TEMP DEV SHIT
#copy other pcaps in here because sometimes we dont have awesome sampling 
#cp ~/a/directory/*.cap ringbuffer/

#start capturing data from the wireless adapter to the ringbuffer
#tshark -i $networkInterface -f 'subtype probereq ' -w ringbuffer/probes -b duration:60 -b files:5 2> /dev/null &
#alternate with no ringbuffer
#tshark -i $networkInterface -f 'subtype probereq ' -w ringbuffer/probes 2> /dev/null &

#wait for tshark to write something to the ringbuffer dir before continuing
: '
echo -n "Initializing tshark"
while [ -z $(ls ringbuffer/) ]
do 
        echo -n .
        sleep 1
done
echo

#wait for a probe request before continuing
echo -n "Waiting for probe requests"
while [[ -z $probes ]]
do
        probes=$(for files in $( ls ringbuffer/);do sudo tshark -r ringbuffer/$files 2> /dev/null | grep "Probe Request, SN=";done)
	echo -n .
        sleep 1
done
echo


# perform the rest of these actions until the user cancels the script
while [ 1 -eq 1 ]
do
#'
#END OF INTERFACE CAPTURE JUNK
###############################################################################

###############################################################################
#CREATE REPORTING DIRECTORIES
###############################################################################
report_directory (){
	mkdir -p $dataDir
	mkdir -p $htmlDir
}


###############################################################################
#PCAP PROCESSING FUNCTION
###############################################################################
pcap_processing () {

	#clear profile data from previous runs
	rm -f $dataDir/*.mac
	rm -f $dataDir/*.compressed

	#do some actions for each pcap in the current captureDir
	for i in $( ls $captureDir/ | grep .cap );
	do
		echo 'Processing '$i
		#for each pcap, output only the data we want, the source MAC and SSID
		for j in $( tshark -r $captureDir/$i -Y 'wlan.fc.type_subtype == 0x0004' -Nn 2> /dev/null | egrep -v 'SSID=Broadcast$|\[Malformed Packet\]$' | cut -d '.' -f 2- | cut -d ' ' -f 2,12- | sed 's/ SSID=/,SSID=/g' | egrep -v "\\\001|\\\002|\\\003|\\\004|\\\005|\\\006|\\\016|\\\017|\\\020|\\\021|\\\022|\\\023|\\\024|\\\025|\\\026|\\\027|\\\030|\\\031|\\\032|\\\033|\\\034|\\\035|\\\036|\\\037|\\\277|\\\357" | sort -u ) 
		do
			echo $j >> $dataDir/$i.compressed
			#also create a file for each source mac from each capture file
			touch $dataDir/$(echo $j | cut -d , -f 1).mac
		done
	done
	
	echo Compressing results
	#Create a sorted, deduped file of all data
	cat $dataDir/*.compressed | sort -u > $dataDir/all.compressed
}

###############################################################################
#MASTER GEOLOCATION FUNCTION
###############################################################################
geolocation () {
	#create the file location.db if it does not already exist
	#if [ -z $(ls $dataDir/location.db) ];
	#then 
	#seems like maybe I don't actually need to check if this file exists
		touch $dataDir/location.db
	#fi
	
	echo -------------------------------Begin SSID Lookup---------------------------------
	
	#run a wigle query for all SSIDs listed in all.compressed
	#we need to pass some arguments to the other function in order for it to work
	cat $dataDir/all.compressed | cut -d = -f 2- | sort -u | parallel --no-notice -j 10 ssidGeolocation {} $dataDir $userLocation $WIGLE_API_KEY $searchRange

	echo ------------------------------SSID Lookup Complete-------------------------------

	#remove duplicates and sort
	echo Trimming the database
        sort -u -o $dataDir/location.db $dataDir/location.db
}

###############################################################################
#SSID GEOLOCATION FUNCTION
# Runs a the geolocation search via wigle and handles some other location 
# meta-info gathering tasks at this time.
###############################################################################
ssidGeolocation () {
	#re-instantiate variables (required for parallelization)
	i=$(echo $1)
	dataDir=$(echo $2)	
	userLocation=$(echo $3)
	WIGLE_API_KEY=$(echo $4)
	searchRange=$(echo $5)
	
	#sanitize control chars from bash because... I don't have a better way to fix the bug now
	sanSSID=$(echo $i | sed -e 's/\*/\\*/g' \
				-e 's/\[/\\[/g' \
				-e 's/\]/\\]/g' \
				-e 's/\&/\\&/g' )
	if [ -z "$(grep -i "\"ssid\"\:\"$sanSSID\"" $dataDir/location.db)" ]
	then
		#entry is new
                echo -n $i

		#urlencode spaces with sed because curl bitches at you otherwise
                urlencodeSSID=$(echo $i | sed -e 's/ /%20/g' -e 's/\&/%26/g')

	        #run query for the current SSID by wigle
	        #at this time, since we haven't determined better criteria, only 
	        #       keep entries that return one network            
	        if [ $userLocation == 'NOLOC' ]
		then
			wigle=$(curl --connect-timeout 30 -s -u $WIGLE_API_KEY "https://api.wigle.net/api/v2/network/search?latrange1=&latrange2=&longrange1=&longrange2=&variance=0.010&lastupdt=&netid=&ssid=$urlencodeSSID&ssidlike=&Query=Query&resultsPerPage=2" | grep "\"resultCount\"\:1\," )
		else
			#this isn't the RIGHT way to calc these distances, but it's pretty close most of the time 
			# and I don't care that much about precision at the moment
			
			latRange=$(echo $searchRange/69.2 | bc -l)
			lngRange=$(echo $searchRange/69.2 | bc -l)

			lat=$(echo $userLocation | cut -d , -f 1)
			lng=$(echo $userLocation | cut -d , -f 2)
			latlow=$(echo "$lat-$latRange" | bc)
			lathigh=$(echo "$lat+$latRange" | bc)
			lnglow=$(echo "$lng-$lngRange" | bc)
			lnghigh=$(echo "$lng+$lngRange" | bc)

			#lat/lng is not placed dynamicaly at this time, so these location settings
			# will only work in the north american lat/lng quadrant
			wigle=$(curl --connect-timeout 30 -s -u $WIGLE_API_KEY "https://api.wigle.net/api/v2/network/search?latrange1=$latlow&latrange2=$lathigh&longrange1=$lnglow&longrange2=$lnghigh&variance=0.010&lastupdt=&netid=&ssid=$urlencodeSSID&ssidlike=&Query=Query&resultsPerPage=2" | grep "\"resultCount\"\:1\," )
		fi
			
	        if [ -z "$wigle" ]
	        then
	                echo "\"trilat\":NULL,\"trilong\":NULL,\"ssid\":\"$i\",\"wep\":\"\"" >> $dataDir/location.db
			echo ""
	        else
			gkey=$(echo "AIzaSyCPMj_9PkQKstTkTNv9RH5gwY40WmJP8N4")
			trilat=$(echo $wigle | jq .results[].trilat )
                        trilong=$(echo $wigle | jq .results[].trilong )

			#add headers and junk for the location.db (re-evaluate if this is still needed pls)
			displaytrilat=$(echo $trilat | sed -e 's/^/\"trilat\":/g')
			displaytrilong=$(echo $trilong | sed -e 's/^/\"trilong\":/g')

			#bits and pieces that we need from the wigle results
			coordinates=$( echo $trilat,$trilong )
			ssid=$(echo $wigle | jq .results[].ssid | sed -e 's/^/\"ssid\":/g')
			encryption=$(echo $wigle | jq .results[].encryption)

			#if the coordinates from wigle return 0,0, as they sometimes do, fix them by
			# marking the locations as unlocated and avoid running the meta-info lookup 
			# because there's no point
			if [ $coordinates = '0,0' ]
			then
				displaytrilat=$(echo "\"trilat\":NULL")
	                        displaytrilong=$(echo "\"trilong\":NULL")
				address=$(echo "NULL")
				addressType=$(echo "NULL")
				encryption=$(echo "NULL")
			else
				#Otherwise, try to find out how the location has been identified by google
				#stored json from google's geocoding API
				geocode=$(curl -s https://maps.googleapis.com/maps/api/geocode/json?latlng=$coordinates)
				#google's placeid is required to get more meta information about the location
				placeid=$(echo $geocode | jq .results[].place_id | head -n1 | sed 's/\"//g')
				#identify what type of address this is
				addressType=$(curl -s "https://maps.googleapis.com/maps/api/place/details/json?placeid=$placeid&key=$gkey" | jq .result.types[])
				address=$(echo $geocode | jq .results[].formatted_address | head -n1)
			fi

			echo $displaytrilat,$displaytrilong,$ssid,$encryption,$address,$addressType >> $dataDir/location.db 
			echo "	:LOCATED"
	        fi
	fi
}
#function needs to be exported so parallel can interact with it
export -f ssidGeolocation

###############################################################################
#DEVICE PROFILING FUNCTION
# place SSID probes from each source MAC in its own file 
# ensure that only unique entries are in each file
###############################################################################
profile_gen () {
	for i in $(cat $dataDir/all.compressed )
	do
		echo $(echo $i | cut -d , -f 2) >> $dataDir/$(echo $i | cut -d , -f 1).mac
	done

	for i in $(ls $dataDir/*.mac)
	do
		sort -u -o $i $i
	done
}

###############################################################################
#TXT REPORT GENERATION FUNCTION
###############################################################################
txt_gen () {
	for i in $(ls $dataDir/*.mac);
	do
        	for e in $(cat $i);
        	do
                	mac=$(echo $i | rev | cut -d \/ -f 1 | rev | cut -d . -f 1)
               		ssid=$(echo $e | cut -d = -f 2)

                	extended=$(grep "$ssid" $dataDir/location.db)
                	if [ -z $(echo $extended | grep "\"trilat\"\:NULL\,\"trilong\"\:NULL\,") ]
                	then
                        	#network has lat/lng
                        	ext=$(echo $extended | cut -d , -f 1,2,4-)
                	else
                        	#network has no lat/lng
                        	#check for behavior data
                        	behavior=$(grep "^$ssid:" network_meta_info.txt)
                        	if [[ -z $behavior ]]
                        	then
                                	#no information is known about this network
                                	ext=$(echo NO_DATA)
                        	else
                                	#a beavioral profile has been determined for this network
                                	ext=$(echo $behavior | cut -d : -f 2-)
                        	fi
                	fi

                	echo $mac:$ssid:$ext;
        	done;
	done
}

###############################################################################
#HTML REPORT GENERATION FUNCTION
###############################################################################
html_gen () {
	#clear old html files
	rm -f $htmlDir/*.html

	echo ------------------------------Generating Profiles--------------------------------
	#generate a default display.html so there's always something 
	#for the active page to refresh to
	#this is decommissioned for now
	#echo "<html><meta http-equiv="refresh" content="5"></head><body style="background-color\:black\;"><center><h1 style="color\:green\;font-family\:courier\;">BEAR WITH US<P>TECHNICAL DIFFICULTIES</h1><img src='../giphy.gif'><img src='../putin.jpeg'><img src='../giphy.gif'></center></html>" > html/display.html

	#perform these actions on each .mac profile
	for i in $( ls $dataDir/*.mac)
	do
		echo -n .
		#woo variables because we reuse them all the time
		mac=$(echo $i |  sed 's/.*\///g' | cut -d . -f 1)
		manufacturer=$(grep -i $(echo $mac | cut -d : -f -3 | sed 's/://g' ) /usr/share/ieee-data/oui.txt | cut -d '	' -f 3)
		#apply the following actions only on .mac profiles with more than one SSID
		#I'm disabling this temporarily for now. I may make it a flagged option?
#		if [ "$(cat $i | wc -l)" -gt 1 ]
#		then 
			#Download google maps image for this location
			#for each SSID in this .mac profile
			for j in $(cat $i | cut -d = -f 2-)
			do 
				#create a variable for all this shit 
				#because we're going to be using it a LOT
				data=$(grep ":\"$j\"," $dataDir/location.db | grep -v "\"trilat\":NULL,\"trilong\":NULL,")
				ssid=$(echo $data | cut -d , -f 3 | sed -e 's/\"ssid\":"//g' -e 's/\"$//g')
				#display the current lat,lng
				latlng=$(echo $data | cut -d , -f 1-2 | sed -e 's/"trilat"://g' -e 's/"trilong"://g')
				#if the current SSID does not have google maps photo
				if ls $htmlDir/$ssid.png 1> /dev/null 2>&1
				then
					#do nothing, file exists
					:
				else
					#if the file does not exst, see if we have
					#coordinates for it, don't download anything if we
					#don't. DUH
					if [[ $loc == *"\"trilat\":NULL,\"trilong\":NULL,"* ]]
					then
						:
					else
						wget -q https://maps.googleapis.com/maps/api/staticmap?markers=color:red%7Clabel:$ssid%7C$latlng\&zoom=13\&size=400x400\&maptype=roadmap -O $htmlDir/$ssid.png
					fi
				fi
			done
	
			#generate html page
			#for each SSID in this .mac profile
			for n in $(cat $i | cut -d = -f 2-)
			do
				if [ -z "$manufacturer" ]
				then
					manufacturer=$(echo UNKNOWN)
				fi

				#if an image exists for this network, add it to the html
				if [ -z "$(ls $htmlDir/*.png  2>/dev/null | grep "\/$n.png")" ]
		                then
		                        :
		                else
					#if we haven't created an html file for this
					# profile yet, add the boilerplate header
					if [ -z "$(grep $mac $htmlDir/*html  2>/dev/null)" ]
		                	then
						uniqueNets=$(cat $i | wc -l)
		                        	echo -n "<html><head><meta http-equiv=\"refresh\" content=\"15\"></head><style>table, th, td {border: 1px solid green;color: green;font-family: courier;border-collapse: collapse;} td { width:400px} body{background-color: black}h1 {color: green; text-align: left; font-family: courier; } p { color: green; font-family: courier; } h3 {color: green; font-family: courier; } p {color: green; font-family: courier; } ul {color: green; font-family: courier; }</style><body><h2><p>Device ID $mac, manufacturer:$manufacturer <p>Looking for $uniqueNets network(s):::Located network count: LOCATED_NETS_STRING_HERE</h1><table><tr>" >> $htmlDir/$mac.html
		                	fi
					#add the image to the profile
					address=$(grep \"$n\" $dataDir/location.db | cut -d , -f 5- | sed -e 's/\",\"/<h3>/g' -e 's/,/<h3>/' -e 's/\"$//g' -e 's/^\"//g')
					latlng=$(grep \"$n\" $dataDir/location.db | cut -d , -f 1-2 | sed -e 's/"trilat"://g' -e 's/"trilong"://g' )
					encryption=$(grep \"$n\" $dataDir/location.db| cut -d , -f 4 | sed 's/\"//g')
					echo -n "<td><h3>SSID: $n<h3>LAT,LNG: $latlng<h3>Encryption: $encryption<h3>$address<img src=\"$n.png\"></td>" >> $htmlDir/$mac.html
					#echo -n "<tr><td rowspan=\"3\"><img src=\"$n.png\"</th><td>SSID: $n</td></tr><tr><td>COORDINATE: $latlng</td></tr><tr><td>ADDRESS: $address</td></tr>" >> html/$mac.html
		                fi
			done
#end of 'one probe' profile generation loop
#		fi

		#now that the profile has been fully generated, replace placeholder 
		#	for number of located networks with the actual value
		if [ -z "$(grep $mac $htmlDir/*html 2>/dev/null )" ]
		then
			:
		else
			locatedNets=$(sed 's/\.png/.png\n/g' $htmlDir/$mac.html  2>/dev/null | wc -l)
			if [ $locatedNets -ne 0 ]
			then
				sed -i -e "s/LOCATED_NETS_STRING_HERE/$locatedNets/" $htmlDir/$mac.html
			fi

			echo "<p><p>Networks that have not been located<ul>" >> $htmlDir/$mac.html
			cat $i | cut -d = -f 2- | while read net
			do
				behavior=$(grep "^$net:" network_meta_info.txt)
				if [ -z "$behavior" ]
				then
					if [ -z "$(grep -v "\"trilat\":NULL,\"trilong\":NULL" $dataDir/location.db | grep ",\"ssid\":\"$net\"," )" ]
					then 
						echo $net | sed 's/^/<li>/g' >> $htmlDir/$mac.html
					fi
#					echo $net | sed 's/^/<li>/g' >> $htmlDir/$mac.html
				else
					echo $behavior | sed -e 's/\(.*\):/<b>\1<\/b>:/' -e 's/^/<li>/g' >> $htmlDir/$mac.html
				fi
			done
			
			if [ -z "$(grep "<li>" $htmlDir/$mac.html)" ]
			then 
				sed -i -e 's/<p>Networks that have not been located<ul>//g' $htmlDir/$mac.html
			fi
			
			echo "</ul></body></html>" >> $htmlDir/$mac.html
		fi
		
		echo -n .
	done
	echo ''
	echo -------------------------------Profiles Complete---------------------------------
}

###############################################################################
#CALL FUNCTIONS TO DO THINGS!
###############################################################################
report_directory
pcap_processing
geolocation
profile_gen

if [ -z $reportFormat ]
then
        txt_gen
elif [ $reportFormat == html ]
then
	html_gen
elif [ $reportFormat == txt ]
then
	txt_gen
fi

###############################################################################
#CHILL FUNCTION
###############################################################################
chill_out () {
#just chill for a second. jesus
echo -n Chill out. Take a beat
for ani in $(seq 1 5)
do
	sleep 1
        echo -n .
done
echo " Back to it"
}

#continue looping
#done
