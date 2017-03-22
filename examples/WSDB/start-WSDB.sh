python webServerWSDB.py $1 &
pid=$!
disown $pid
echo $pid > .WSDB.pid
