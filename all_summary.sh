#!/bin/bash
echo "Usage: ./all_summary start_time,stop_time DIRS"

TIME=$1
shift
DIRS=$@

for cond in both3 both4 rmnet3 rmnet4 wlan; do
    for app in dailymotion drive dropbox facebook firefox messenger spotify youtube; do
        echo "Summary with $cond on app $app"
        ./summary.py -a $app -c $cond $TIME -d $DIRS
    done
done
