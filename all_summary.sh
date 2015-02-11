#!/bin/bash
echo "Usage: ./all_summary start_time,stop_time DIRS"

TIME=$1
shift
DIRS=$@

for cond in both3 both4 rmnet3 rmnet4 wlan both4TCL5pD100m both4TCL5p both4TCL15p both4TCD10m both4TCD100m both4TCD1000m; do
    for app in dailymotion drive dropbox facebook firefox firefoxspdy messenger shazam spotify youtube; do
        echo "Summary with $cond on app $app"
        ./summary.py -a $app -c $cond $TIME -d $DIRS
    done
done
