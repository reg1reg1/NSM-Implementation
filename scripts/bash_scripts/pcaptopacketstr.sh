for filename in ./*.pcap; do
filelogname=${filename::-5}
justniffer -f $filename -l "%request.timestamp2|%source.ip|%source.port|%dest.port|%dest.ip|%request.line|%request.size|%request.header.host|%response.size|%response.code|%connection.time|%idle.time.0|%idle.time.1" -n N/A -u > $filelogname-ptsrstatic-traffic.log
done
