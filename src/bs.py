
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.cli import CLI

class LinuxRouter( Node ):

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

class NetworkTopo( Topo ):

    def build( self, **_opts ):

        r1 = self.addHost('r1', cls=LinuxRouter, ip='10.0.0.1/24')
        r2 = self.addHost('r2', cls=LinuxRouter, ip='10.0.0.2/24')
        self.addLink(r1, r2, intfName1='r1-eth0', intfName2='r2-eth0')

        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, failMode='standalone')
        self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip':'10.0.1.1/24'})
        self.addLink(s2, r2, intfName2='r2-eth1', params2={'ip':'10.0.2.1/24'})

        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        h3 = self.addHost('h3', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        h4 = self.addHost('h4', ip='10.0.2.3/24', defaultRoute='via 10.0.2.1')

        for h, s in [(h1, s1), (h2, s1), (h3, s2), (h4, s2)]:
            self.addLink (h, s)

def run():
    topo = NetworkTopo()
    net = Mininet(topo = topo)
    net.start()
    info('*** Routing Table on Router:\nR1:\n')
    info(net['r1'].cmd('route'))
    info('\nR2:\n')
    info(net['r2'].cmd('route'))
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()