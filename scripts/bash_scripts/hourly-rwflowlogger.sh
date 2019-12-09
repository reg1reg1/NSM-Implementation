generaldate=$(date '+%Y.%m.%d')

filterDate=$(date '+%Y/%m/%d')

start=$(date -d '-60 minutes' +%Y/%m/%d:%T)
endd=$(date +%Y/%m/%d:%T)

echo $start $end

#Create
rwfilter --start-date=$start --end-date=$endd --type=all --proto=0- --pass=stdout | rwcut --all-fields --timestamp-format=epoch --no-columns --no-titles --no-final-delimiter >> /home/sensor/filebeat/$generaldate-all-traffic.log

#hourly traffic
rwfilter --proto=0- --start-date=$start --end-date=$endd --type=all --pass=stdout | rwcount --bin-size=3600 --timestamp-format=epoch --no-titles --no-columns --no-final-delimiter  >>  /home/sensor/filebeat/$generaldate-hourly-traffic.log


#wqweb flow traffic


#smtp flow traffic


#ping flow traffic


