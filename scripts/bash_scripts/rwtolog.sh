for filename in ./*.rw; do
    filelogname=${filename::-8}
    rwcut --all-fields --timestamp-format=epoch --no-columns --no-titles --no-final-delimiter $filename> $filelogname-static-traffic.log 	
    echo $filelogname+"created"
done
