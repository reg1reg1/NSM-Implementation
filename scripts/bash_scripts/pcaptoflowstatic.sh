for filename in ./*.pcap; do
    yaf --in $filename --silk --ip4-only --applabel --mac --max-payload=2048 --flow-stats --metadata-export --delta --plugin-name=/usr/local/lib/yaf/dpacketplugin.la | rwipfix2silk --silk-output=/home/sensor/static_rwflow_data/$filename.rw \
      --interface-values=vlan
done
