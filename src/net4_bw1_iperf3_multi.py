#!/usr/bin/env python

from time import time
from time import sleep
from signal import SIGINT

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from mininet.util import pmonitor

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate( self ):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class BasicTopo(Topo):
    def build(self, **_opts):
        for i in [1,2,3,4]:
            self.addNode('R%d' % i, cls=LinuxRouter, ip=None)
            self.addHost('H%d' % i, ip=None, defaultRoute='via 10.0.%d.254' % i)
            self.addLink('H%d' % i, 'R%d' % i,
                         intfName1='H%d-eth0' % i, params1={'ip':'10.0.%d.1/24' % i},
                         intfName2='R%d-eth0' % i, params2={'ip':'10.0.%d.254/24' % i})

        for u,v in [(1,2), (1,3), (2,3), (2,4), (3,4)]:
            self.addLink('R%d' % u, 'R%d' % v, cls=TCLink,
                         intfName1='R%d-eth%d' % (u,v), params1={'ip':'10.%d.%d.%d/24' % (u,v,u)},
                         intfName2='R%d-eth%d' % (v,u), params2={'ip':'10.%d.%d.%d/24' % (u,v,v)},
                         bw=1, delay='5ms')

def run():
    net = Mininet(topo=BasicTopo(), controller=None)
    net.start()

    router1 = net['R1']
    router2 = net['R2']
    router3 = net['R3']
    router4 = net['R4']

    # routing
    router1.cmd('ip route add 10.0.2.0/24 via 10.1.2.2')
    router1.cmd('ip route add 10.0.3.0/24 via 10.1.3.3')
    router1.cmd('ip route add 10.0.4.0/24 via 10.1.2.2')
    # router1.cmd('ip route add 10.0.4.0/24 via 10.1.3.3') # <== better option
    router2.cmd('ip route add 10.0.1.0/24 via 10.1.2.1')
    router2.cmd('ip route add 10.0.3.0/24 via 10.2.3.3')
    router2.cmd('ip route add 10.0.4.0/24 via 10.2.4.4')
    router3.cmd('ip route add 10.0.1.0/24 via 10.1.3.1')
    router3.cmd('ip route add 10.0.2.0/24 via 10.2.3.2')
    router3.cmd('ip route add 10.0.4.0/24 via 10.3.4.4')
    router4.cmd('ip route add 10.0.1.0/24 via 10.2.4.2')
    # router4.cmd('ip route add 10.0.1.0/24 via 10.3.4.3') # <== better option
    router4.cmd('ip route add 10.0.2.0/24 via 10.2.4.2')
    router4.cmd('ip route add 10.0.3.0/24 via 10.3.4.3')

    h1 = net['H1']
    h2 = net['H2']
    h4 = net['H4']

    test_duration = 10

    P = {}
    output = {}

    info ('starting iperf3 server\n')
    P['H4 server1'] = h4.popen('iperf3 -s -p 5201 -1 --forceflush', shell=False)
    P['H4 server2'] = h4.popen('iperf3 -s -p 5202 -1 --forceflush', shell=False)

    output['H4 server1'] = []
    output['H4 server2'] = []
    
    sleep(1)

    info ('starting iperf3 client on H1\n')
    P['H1'] = h1.popen('iperf3 -c 10.0.4.1 -p 5201 -t %d --forceflush' % test_duration, shell=False)
    
    info ('starting iperf3 client on H2\n')
    P['H2'] = h2.popen('iperf3 -c 10.0.4.1 -p 5202 -t %d --forceflush' % test_duration, shell=False)

    output['H1'] = []
    output['H2'] = []
    
    end_time = time() + test_duration
    
    for host, line in pmonitor(P, timeoutms=(test_duration + 1)*1000):
        if host:
            l = '%s: %s' % ( host,  line )
            info (l)
            output[host].append(line)

        if time() >= end_time:
	    # Close all iperf3 processes
            for p in P.values():
                p.send_signal( SIGINT )

    net.stop()

    for h, lines in output.items():
        print(h, '='*(78 - len(h)))
        for l in lines:
            print(l,end='')

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
