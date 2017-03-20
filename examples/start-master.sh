python master.py -u "addr=192.168.10.2" -G remote -a 129.6.229.58 --source udp_sockets -f 724 &
pid=$!
disown $pid
echo $pid > .master.pid
