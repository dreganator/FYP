BROADCAST=`ip address show $DEV | grep 'inet .* brd ' | head -1 | sed -e 's/^.* brd \([0-9\.]*\) .*$/\1/'` 
#the line above gets the broadcast address
b2=${BROADCAST%.*}
b2=$b2.*
#removes the end and replaces with a star
nmap -n -sn $b2 -oG - | awk '/Up$/{print $2}'
#finds all active addresses on the network

