# QoS
# Requirement :
- Install Mininet,Pyhton3,Ryu,OVS
# How to deploy

+ Git clone : git clone https://github.com/Huycon2352/QoS
+ Run Ryu COntroller : ryu-manager dynamic_access_controller.py
+ Run mininet : mn --custom topology.py --topo dynamicaccesstopo --controller=remote --switch ovsk,protocols=OpenFlow13 --mac
+ Run apply queue setup shapping on Link target : ./setup_qos.sh s1-eth4
# Observality
+ Test with mininet cli :  -  h1 ping h4
                           -  h1 ping -f h4
+ Using xterm on mininet cli : xterm h1 h2 h3 h4
    - H4 : iperf3 -s
    - H1 : iperf3 -c 10.0.0.4 -u
