ps auxw | grep -ie "master.py" | awk '{print $2}' | xargs sudo kill -9 
