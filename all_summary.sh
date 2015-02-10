echo "Usage: ./all_summary start_time,stop_time"
for cond in both3 both4 rmnet3 rmnet4 wlan both4TCL5pD100m both4TCL5p both4TCL15p both4TCD10m both4TCD100m both4TCD1000m; do
    for app in dailymotion drive dropbox facebook firefox firefoxspdy messenger shazam spotify youtube; do
        echo "Summary with $cond on app $app"
        ./summary.py -a $app -c $cond $1 -d 20150205-013004_3ce3bfb30b83684f8df0d5f8988ac419df41f8ba 20150206-013001_2d76483465df60aeaa59185fa95b32e48125d0c0 20150207-013001_2d76483465df60aeaa59185fa95b32e48125d0c0 20150208-013002_2d76483465df60aeaa59185fa95b32e48125d0c0 20150209-013003_2d76483465df60aeaa59185fa95b32e48125d0c0 20150210-013002_2d76483465df60aeaa59185fa95b32e48125d0c0
    done
done
