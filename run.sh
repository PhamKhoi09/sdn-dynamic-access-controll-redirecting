h1 ping -c1 10.0.0.1
h1 ping -c1 10.0.0.2
h1 ping -c1 10.0.0.3
mininet> h2 bash -c 'mkdir -p /tmp/web1; echo "WEB1 - GUEST" > /tmp/web1/w.html; python3 -m http.server 80 --directory /tmp/web1' &
mininet> h3 bash -c 'mkdir -p /tmp/web2; echo "WEB2 - ADMIN" > /tmp/web2/w.html; python3 -m http.server 80 --directory /tmp/web2' &
mininet> h4 bash -c 'mkdir -p /tmp/web3; echo "WEB3 - EMPLOYEE" > /tmp/web3/w.html; python3 -m http.server 80 --directory /tmp/web3' &