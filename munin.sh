#!/bin/bash

if [ "$1" = "config" ]; then
    echo "graph_data_size custom 1d, 1m for 1w, 1m for 1t, 1m for 1y"
    echo "update_rate 30"
fi

case $1 in
   config)
        cat <<'EOM'
graph_title Temperaturen DG
graph_vlabel Temperatur
graph_category haus
temp0.label Bad Raumtemperatur
temp1.label Zulauf
temp2.label Rücklauf Bad
temp3.label Rücklauf Schlafzimmer 1
temp4.label Rücklauf Schlafzimmer 2
temp5.label Rücklauf Wohnzimmer 1
temp6.label Rücklauf Wohnzimmer 2
temp7.label Rücklauf Küche
EOM
        exit 0;;
esac

# load.label load
# load.warning 1.35
# load.critical 1.4


IFS=$'\n'
VALUES=($(cargo run "192.168.3.222:51" \
    "28:ff:d8:61:c1:17:05:72"  \
    "28:ff:f3:54:c1:17:05:33"  \
    "28:ff:fe:35:c1:17:05:c0"  \
    "28:ff:71:14:c0:17:04:6e"  \
    "28:ff:fe:55:c1:17:05:50"  \
    "28:ff:4b:19:c1:17:04:61"  \
    "28:ff:0d:13:c0:17:04:a4"  \
    "28:ff:f7:08:c1:17:04:b8"  \
))
unset IFS

echo "temp0.value ${VALUES[0]}"
echo "temp1.value ${VALUES[1]}"
echo "temp2.value ${VALUES[2]}"
echo "temp3.value ${VALUES[3]}"
echo "temp4.value ${VALUES[4]}"
echo "temp5.value ${VALUES[5]}"
echo "temp6.value ${VALUES[6]}"
echo "temp7.value ${VALUES[7]}"