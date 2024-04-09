import argparse
import dataclasses
import math
from pathlib import Path
from typing import List, Dict, Optional
import ipaddress
from collections import defaultdict
import yaml
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node
from mininet.topo import Topo


def validate_definition_file(definition_file: Path):
    if not definition_file.exists():
        raise FileNotFoundError(definition_file)
    if not definition_file.is_file():
        raise FileNotFoundError(definition_file)
    if not definition_file.suffix == '.yaml':
        raise ValueError(f'File {definition_file} is not a yaml')
    return


def read_definition(definition_file: Path) -> dict:
    with open(definition_file, 'r') as def_file:
        return yaml.safe_load(def_file)


class BaseInterface:
    def __init__(self, name: str, address: str, mask: str, node):
        self._node = node
        self._name: str = name
        self._address: str = address
        self._mask: str = mask

    def ip_address(self):
        return self._address

    def mask(self):
        return self._mask

    def node_name(self):
        return self._node.name()

    def name(self):
        return self._name

    def full_address(self):
        network = ipaddress.IPv4Network(f"{self._address}/{self._mask}", strict=False)
        return f"{self._address}/{network.prefixlen}"


class RouterInterface(BaseInterface):
    def __init__(self, name: str, address: str, mask: str, node, cost: int = 1):
        super().__init__(name=name, address=address, mask=mask, node=node)
        self._cost: int = cost

    def cost(self) -> int:
        return self._cost


class Connection:
    def __init__(self, node1, node2, interface1: BaseInterface, interface2: BaseInterface, cost: int):
        # TODO: make this a dataclass
        self._node1 = node1
        self._node2 = node2
        self._interface1 = interface1
        self._interface2 = interface2
        self._cost: int = cost

    def node1(self):
        return self._node1

    def node2(self):
        return self._node2

    def cost(self) -> int:
        return self._cost

    def interface1(self):
        return self._interface1

    def interface2(self):
        return self._interface2


class RouterDefinition:
    def __init__(self, name: str, router_def: dict):
        self._name: str = name
        self._interfaces: List[RouterInterface] = []
        for interface_name, interface_description in router_def.items():
            address: str = interface_description.get('address')
            mask: str = interface_description.get('mask')
            cost: int = interface_description.get('cost', 1)
            self._interfaces.append(RouterInterface(name=interface_name, address=address, mask=mask,
                                                    cost=cost, node=self))
        self._connections: List[Connection] = []

    def add_connection(self, connection: Connection):
        self._connections.append(connection)

    def connections(self):
        return self._connections

    def name(self) -> str:
        return self._name

    def interfaces(self) -> List[RouterInterface]:
        return self._interfaces


class HostDefinition:
    def __init__(self, name: str, interface_name: str, interface_address: str, interface_mask: str):
        self._name: str = name
        self._interface: BaseInterface = BaseInterface(name=interface_name,
                                                       address=interface_address,
                                                       mask=interface_mask,
                                                       node=self)
        self._switch: Optional[SwitchDefinition] = None
        self._connections: List[Connection] = []

    def add_connection(self, connection: Connection):
        self._connections.append(connection)

    def set_switch(self, switch):
        self._switch = switch

    def switch(self):
        return self._switch

    def ip_address(self):
        return self._interface.ip_address()

    def mask(self):
        return self._interface.mask()

    def interface(self):
        return self._interface

    def name(self) -> str:
        return self._name


class SwitchDefinition:
    def __init__(self, name: str, subnet: str, hosts: List[HostDefinition]):
        self._name: str = name
        self._subnet: str = subnet
        self._hosts: List[HostDefinition] = hosts
        ip_ends = [int(host.ip_address().split(".")[-1]) for host in hosts]
        end = 0
        if min(ip_ends) == 0:
            end = max(ip_ends) + 1
        ip_exploded = hosts[0].ip_address().split(".")[:-1]
        ip_exploded.append(f"{end}")
        ip_address = ".".join(ip_exploded)
        self._interface: BaseInterface = BaseInterface(name=name, address=ip_address, mask=hosts[0].mask(), node=self)
        self._connections: List[Connection] = []

    def add_connection(self, connection: Connection):
        self._connections.append(connection)

    def ip_address(self):
        return self._interface.ip_address()

    def mask(self):
        return self._interface.mask()

    def interface(self):
        return self._interface

    def name(self) -> str:
        return self._name

    def hosts(self):
        return self._hosts


@dataclasses.dataclass
class ShortestPath:
    router_to_dist: Dict[RouterDefinition, float]
    router_to_prev: Dict[RouterDefinition, Optional[RouterDefinition]]


class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class NetworkTopology(Topo):
    def __init__(self, routers: List[RouterDefinition],  hosts: List[HostDefinition],
                 switches: List[SwitchDefinition], paths: Dict[RouterDefinition, ShortestPath]):
        self._routers = routers
        self._hosts = hosts
        self._switches = switches
        self._paths = paths
        Topo.__init__(self)

    def _create_routers(self):
        for router in self._routers:
            self.addNode(router.name(), cls=LinuxRouter, ip=None)
        connections = [c for router in self._routers for c in router.connections()]
        connections = [c for c in connections
                       if type(c.node1()) is RouterDefinition and type(c.node2()) is RouterDefinition]
        connections = set(connections)
        for c in connections:
            router1 = c.node1()
            router2 = c.node2()
            interface1 = c.interface1()
            interface2 = c.interface2()
            print("Adding link router")
            print(f"{router1.name()}-{interface1.name()} {interface1.full_address()}")
            print(f"{router2.name()}-{interface2.name()} {interface2.full_address()}")
            # EXTREMELY IMPORTANT: intfName1 and intfName2 must be unique
            # I wasted 2 hours to find this bug
            intfname1 = f"{router1.name()}-{router2.name()}-{interface1.name()}-{interface2.name()}"
            intfname2 = f"{router2.name()}-{router1.name()}-{interface2.name()}-{interface1.name()}"
            self.addLink(router1.name(), router2.name(),
                         cls=TCLink,
                         intfName1=intfname1, params1={"ip": interface1.full_address()},
                         intfName2=intfname2, params2={"ip": interface2.full_address()})
        return

    def _create_switches(self):
        for switch in self._switches:
            sw = self.addSwitch(switch.name())
            for host in switch.hosts():
                self.addLink(switch.name(), host.name())
        connections = [c for router in self._routers for c in router.connections()]
        connections = [c for c in connections
                       if type(c.node1()) is SwitchDefinition or type(c.node2()) is SwitchDefinition]
        connections = set(connections)
        for c in connections:
            router1 = c.node1()
            switch = c.node2()
            interface1 = c.interface1()
            interface2 = c.interface2()
            print("Adding link router")
            print(f"{router1.name()}-{interface1.name()} {interface1.full_address()}")
            print(f"{switch.name()}-{interface2.name()} {interface2.full_address()}")
            # EXTREMELY IMPORTANT: intfName1 and intfName2 must be unique
            # I wasted 2 hours to find this bug
            intfname1 = f"{router1.name()}-{switch.name()}-{interface1.name()}-{interface2.name()}"
            intfname2 = f"{switch.name()}-{router1.name()}-{interface2.name()}-{interface1.name()}"
            self.addLink(router1.name(), switch.name(),
                         cls=TCLink,
                         intfName1=intfname1, params1={"ip": interface1.full_address()},
                         intfName2=intfname2, params2={"ip": interface2.full_address()})
        return

    def _create_hosts(self):
        for host in self._hosts:
            self.addHost(host.name(), ip=None)

    def set_routing_tables(self):
        pass

    def build(self, **_ops):
        self._create_routers()
        self._create_hosts()
        self._create_switches()
        self.set_routing_tables()


class NetworkDefinition:
    def __init__(self, network_definition: dict) -> None:
        self._routers: List[RouterDefinition] = NetworkDefinition._get_routers_definition(definition=network_definition)
        self._hosts: List[HostDefinition] = NetworkDefinition._get_hosts_definition(definition=network_definition)
        self._switches: List[SwitchDefinition] = []
        self.create_switches()
        self._connect_components()

    @staticmethod
    def same_subnet(interface: BaseInterface, other: BaseInterface) -> bool:
        subnet = NetworkDefinition.get_subnet(interface.ip_address(), interface.mask())
        other_subnet = NetworkDefinition.get_subnet(other.ip_address(), other.mask())
        return subnet == other_subnet

    @staticmethod
    def _attempt_connecting_routers(router1: RouterDefinition, router2: RouterDefinition):
        for interface in router1.interfaces():
            for other_interface in router2.interfaces():
                NetworkDefinition._attempt_connecting_interfaces(node1=router1,
                                                                 node2=router2,
                                                                 interface1=interface,
                                                                 interface2=other_interface,
                                                                 cost=interface.cost())
        return

    @staticmethod
    def _attempt_connecting_interfaces(node1, node2, interface1: BaseInterface, interface2: BaseInterface, cost: int):
        if NetworkDefinition.same_subnet(interface=interface1, other=interface2):
            new_connection = Connection(node1=node1, node2=node2, interface1=interface1,
                                        interface2=interface2, cost=cost)
            node1.add_connection(connection=new_connection)
            node2.add_connection(connection=new_connection)
        return

    def _connect_components(self):
        # connect routers together
        for i in range(len(self._routers)):
            router = self._routers[i]
            for j in range(i+1, len(self._routers)):
                other_router = self._routers[j]
                if router != other_router:
                    self._attempt_connecting_routers(router1=router, router2=other_router)
        # connect router to hosts
        for router in self._routers:
            for interface in router.interfaces():
                for host in self._hosts:
                    if not host.switch():
                        host_interface: BaseInterface = host.interface()
                        self._attempt_connecting_interfaces(node1=router, node2=host,
                                                            interface1=interface,
                                                            interface2=host_interface,
                                                            cost=interface.cost())
                # connect switches to routers
                for switch in self._switches:
                    switch_interface: BaseInterface = switch.interface()
                    self._attempt_connecting_interfaces(node1=router, node2=switch,
                                                        interface1=interface,
                                                        interface2=switch_interface,
                                                        cost=interface.cost())
        return

    def create_switches(self):
        subnet_to_hosts: Dict[str, List[HostDefinition]] = defaultdict(list)
        for host in self._hosts:
            subnet: str = NetworkDefinition.get_subnet(ip=host.ip_address(), netmask=host.mask())
            subnet_to_hosts[subnet].append(host)
        subnet_to_hosts = {k: v for k, v in subnet_to_hosts.items() if len(v) > 1}
        switch_id: int = 0
        for subnet, hosts in subnet_to_hosts.items():
            new_switch: SwitchDefinition = SwitchDefinition(name=f"s{switch_id}", subnet=subnet, hosts=hosts)
            self._switches.append(new_switch)
            for host in hosts:
                host.set_switch(switch=new_switch)
            switch_id += 1
        return

    def _find_shortest_paths(self):
        router_to_paths: Dict[RouterDefinition, ShortestPath] = {}
        for router in self._routers:
            router_to_dist, router_to_prev = self._dijkstra(router)
            router_to_paths[router] = ShortestPath(router_to_dist=router_to_dist, router_to_prev=router_to_prev)
        return router_to_paths

    @staticmethod
    def _find_vertex_with_smallest_distance(Q, router_to_dist: Dict[RouterDefinition, float]) -> RouterDefinition:
        dist_to_router = {dist: router for router, dist in router_to_dist.items() if router in Q}
        min_dist = min(dist_to_router.keys())
        return dist_to_router[min_dist]

    def _dijkstra(self, source_router: RouterDefinition):
        # Dijkstra as seen on wikipedia https://en.wikipedia.org/wiki/Dijkstra's_algorithm
        router_to_dist: Dict[RouterDefinition, float] = {}
        router_to_prev: Dict[RouterDefinition, Optional[RouterDefinition]] = {}
        Q: List[RouterDefinition] = [router for router in self._routers if router]
        for router in self._routers:
            router_to_dist[router] = math.inf
            router_to_prev[router] = None
        router_to_dist[source_router] = 0
        while len(Q) > 0:
            u = self._find_vertex_with_smallest_distance(Q, router_to_dist)
            Q = [r for r in Q if r != u]

            # find neighbours of u still in Q
            connections = [c for c in u.connections()
                           if (c.node1() != u and c.node1() in Q) or (c.node2() != u and c.node2() in Q)]
            for conn in connections:
                alt = router_to_dist[u] + conn.cost()
                v = conn.node1() if conn.node1() != u else conn.node2()
                if alt < router_to_dist[v]:
                    router_to_dist[v] = alt
                    router_to_prev[v] = u
        return router_to_dist, router_to_prev

    def set_up_emulation(self):
        router_to_path: Dict[RouterDefinition, ShortestPath] = self._find_shortest_paths()
        topology = NetworkTopology(routers=self._routers,
                                   hosts=self._hosts,
                                   switches=self._switches,
                                   paths=router_to_path)
        net = Mininet(topo=topology, controller=None)
        net.start()
        CLI(net)
        net.stop()
        return

    @staticmethod
    def get_subnet(ip: str, netmask: str):
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network.network_address)

    @staticmethod
    def _get_routers_definition(definition: dict) -> List[RouterDefinition]:
        router_definitions: List[RouterDefinition] = []
        routers: dict = definition.get('routers')
        for router_name, router_def in routers.items():
            router_definition: RouterDefinition = RouterDefinition(name=router_name, router_def=router_def)
            router_definitions.append(router_definition)
        return router_definitions

    @staticmethod
    def _get_hosts_definition(definition: dict) -> List[HostDefinition]:
        hosts_definitions: List[HostDefinition] = []
        hosts: dict = definition.get('hosts')
        for host_name, host_def in hosts.items():
            interface_name: str = list(host_def.keys())[0]
            interface_address: str = host_def[interface_name]['address']
            interface_mask: str = host_def[interface_name]['mask']
            host_definition: HostDefinition = HostDefinition(name=host_name,
                                                             interface_name=interface_name,
                                                             interface_address=interface_address,
                                                             interface_mask=interface_mask)
            hosts_definitions.append(host_definition)
        return hosts_definitions

    def output_graph_representation(self):
        print("graph Network {")
        # add routers
        for router in self._routers:
            print(f"  {router.name()} [shape=circle];")

        connections = [c for router in self._routers for c in router.connections()]
        connections = list(set(connections))
        for connection in connections:
            node1 = connection.node1()
            node2 = connection.node2()
            if type(node1) is not RouterDefinition or type(node2) is not RouterDefinition:
                continue
            cost = connection.cost()
            print(f'  {node1.name()} -- {node2.name()} [label="{cost}"];')
        print("}")


def main():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="A tool to define the emulation of a network")
    parser.add_argument("--draw", action="store_true",
                        help="output a map of the routers in GraphViz format")
    parser.add_argument("definition", type=Path, help="the definition file of the network in YAML")
    args: argparse.Namespace = parser.parse_args()

    definition_file: Path = args.definition
    should_draw: bool = args.draw
    validate_definition_file(definition_file=definition_file)
    network_specification: dict = read_definition(definition_file=definition_file)
    network_definition: NetworkDefinition = NetworkDefinition(network_definition=network_specification)
    network_definition.set_up_emulation()
    if should_draw:
        network_definition.output_graph_representation()
    return


if __name__ == '__main__':
    main()
