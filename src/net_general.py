#!/usr/bin/env python

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

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

class InputGraphTopo(Topo):
    def add_edge (self, u, v):
        if u in self.V:
            self.V[u].append(v)
        else:
            self.V[u] = [v]

    # initialize a graph by reading the edges from the given file
    def __init__(self, filename):
        self.V = dict()         # Adjacency list: Node --> list of neighbor nodes
        self.E = set()          # Edges: set of pairs (u,v)
        f = open(filename)
        for l in f:
            u,v = l.strip().split()
            u = int(u)
            v = int(v)
            if v < u:
                u,v = v,u
            self.add_edge(u, v)
            self.add_edge(v, u)
            self.E.add((u,v))
        f.close()
        Topo.__init__(self)

    def build(self, **_opts):
        for v in self.V.keys():
            self.addNode('R%d' % v, cls=LinuxRouter, ip=None)
            self.addHost('H%d' % v, ip=None, defaultRoute='via 10.0.%d.254' % v)
            self.addLink('H%d' % v, 'R%d' % v,
                         intfName1='H%d-eth0' % v, params1={'ip':'10.0.%d.1/24' % v},
                         intfName2='R%d-eth0' % v, params2={'ip':'10.0.%d.254/24' % v})

        for u,v in self.E:
            self.addLink('R%d' % u, 'R%d' % v, 
                         intfName1='R%d-eth%d' % (u,v), params1={'ip':'10.%d.%d.%d/24' % (u,v,u)},
                         intfName2='R%d-eth%d' % (v,u), params2={'ip':'10.%d.%d.%d/24' % (u,v,v)})

def run(topo_file):
    net = Mininet(topo=InputGraphTopo(topo_file), controller=None)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    import sys
    if len(sys.argv) < 2:
        print('usage:', sys.argv[0], '<topology-filename>')
        sys.exit(1)
    else:
        run(sys.argv[1])
