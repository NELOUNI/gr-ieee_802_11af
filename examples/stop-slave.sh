ps auxw | grep slave.py | awk '{print $2}' | xargs sudo kill -9 
