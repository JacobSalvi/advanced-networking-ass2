import argparse
import math
import dataclasses
import ipaddress
from collections import defaultdict
from enum import IntEnum
from pathlib import Path
from typing import Optional, Dict, List
import yaml
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node, OVSBridge
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


def get_subnet(address: str, mask: str) -> str:
    network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
    return str(network.network_address)


def dotted_to_mask(mask_dotted: str) -> int:
    split_mask = [bin(int(el)) for el in mask_dotted.split('.')]
    return sum(el.count('1') for el in split_mask)


class NodeType(IntEnum):
    ROUTER = 1
    HOST = 2


@dataclasses.dataclass
class NodeDefinition:
    address: str
    mask: str
    link_name: str
    node_name: str
    node_type: NodeType

    def complete_address(self):
        return f"{get_subnet(self.address, self.mask)}/{dotted_to_mask(self.mask)}"


class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super().terminate()


class NetworkTopology(Topo):
    def __init__(self, subnet_to_nodes, subnet_to_cost: Dict[str, int]):
        self._subnet_to_nodes = subnet_to_nodes
        self._subnet_to_cost = subnet_to_cost
        self.switch_id: int = 0
        super().__init__()

    def build(self):
        # create nodes
        nodes = [n for v in self._subnet_to_nodes.values() for n in v]
        hosts: List[NodeDefinition] = [n for n in nodes if n.node_type == NodeType.HOST]
        for host in hosts:
            self.addHost(host.node_name, defaultRoute=f"via {host.address}")

        # create routers
        router_names = [n.node_name for n in nodes if n.node_type == NodeType.ROUTER]
        router_names = list(set(router_names))
        for router_name in router_names:
            self.addNode(router_name, cls=LinuxRouter, ip=None)

        # link stuff together
        for subnet, subnet_nodes in self._subnet_to_nodes.items():
            if len(subnet_nodes) == 2:
                node_1 = subnet_nodes[0]
                node_2 = subnet_nodes[1]
                intfname1 = f"{node_1.node_name}-{node_1.link_name}-{node_2.node_name}-{node_2.link_name}"
                intfname2 = f"{node_2.node_name}-{node_2.link_name}-{node_1.node_name}-{node_1.link_name}"
                self.addLink(node_1.node_name, node_2.node_name, cls=TCLink,
                             intfName1=intfname1, params1={"ip": f"{node_1.address}/{dotted_to_mask(node_1.mask)}"},
                             intfName2=intfname2, params2={"ip": f"{node_2.address}/{dotted_to_mask(node_2.mask)}"})
            else:
                # create switch  and connect everything to the switch
                switch_name = f"switch{self.switch_id}"
                switch = self.addSwitch(switch_name)
                self.switch_id += 1
                for node in subnet_nodes:
                    intfname2 = f"{node.node_name}-{node.link_name}-{switch_name}"
                    self.addLink(switch, node.node_name,
                                 intfName2=intfname2, params2={"ip": f"{node.address}/{dotted_to_mask(node.mask)}"})
                pass
        pass


class NetworkDefinition:
    def __init__(self, network_definition: dict):
        self._subnet_to_nodes: Dict[str, List[NodeDefinition]] = defaultdict(list)
        self._subnet_to_cost: Dict[str, int] = defaultdict(lambda: 1)
        routers: dict = network_definition.get("routers")
        hosts: dict = network_definition.get("hosts")
        self._load_routers(routers_def=routers)
        self._load_hosts(hosts_def=hosts)

    def _load_routers(self, routers_def: dict):
        for routers_name, routers_def in routers_def.items():
            for link_name, link_def in routers_def.items():
                address: str = link_def.get("address")
                mask: str = link_def.get("mask")
                cost: Optional[int] = link_def.get("cost")
                subnet: str = get_subnet(address, mask)
                if cost is not None:
                    self._subnet_to_cost[subnet] = cost
                node: NodeDefinition = NodeDefinition(address=address, mask=mask,
                                                      node_type=NodeType.ROUTER,
                                                      link_name=link_name, node_name=routers_name)
                self._subnet_to_nodes[subnet].append(node)
        return

    def _load_hosts(self, hosts_def: dict):
        for host_name, hosts_def in hosts_def.items():
            for link_name, link_def in hosts_def.items():
                address: str = link_def.get("address")
                mask: str = link_def.get("mask")
                subnet: str = get_subnet(address, mask)
                cost = 1
                if cost is not None:
                    self._subnet_to_cost[subnet] = cost
                node: NodeDefinition = NodeDefinition(address=address, mask=mask,
                                                      node_type=NodeType.HOST,
                                                      link_name=link_name, node_name=host_name)
                self._subnet_to_nodes[subnet].append(node)
        return

    def _find_shortest_paths(self):
        node_to_paths = {}
        nodes = [n for v in self._subnet_to_nodes.values() for n in v]
        for node in nodes:
            node_to_dist, node_to_prev = self._dijkstra(source_node=node)
            node_to_paths[node.node_name] = (node_to_dist, node_to_prev)
        return node_to_paths

    @staticmethod
    def _find_vertex_with_smallest_distance(Q, router_to_dist):
        dist_to_router = {dist: router for router, dist in router_to_dist.items() if router in Q}
        min_dist = min(dist_to_router.keys())
        return dist_to_router[min_dist]

    def _find_neighbours(self, source_node_name: str):
        neighbours = []
        for subnet, nodes in self._subnet_to_nodes.items():
            node_names = [n.node_name for n in nodes]
            if source_node_name in node_names:
                neighbours.extend([node for node in nodes if node.node_name != source_node_name])
        return neighbours

    def _dijkstra(self, source_node):
        # Dijkstra as seen on wikipedia https://en.wikipedia.org/wiki/Dijkstra's_algorithm
        node_to_dist: Dict[str, float] = {}
        node_to_prev: Dict[str, Optional[str]] = {}
        nodes = [n for v in self._subnet_to_nodes.values() for n in v]
        Q = [n.node_name for n in nodes]
        Q = list(set(Q))
        for node in nodes:
            node_to_dist[node.node_name] = math.inf
            node_to_prev[node.node_name] = None
        node_to_dist[source_node.node_name] = 0
        while len(Q) > 0:
            u = self._find_vertex_with_smallest_distance(Q, node_to_dist)
            Q = [r for r in Q if r != u]

            # find neighbours of u still in Q
            neighbours = self._find_neighbours(u)
            for conn in neighbours:
                cost = self._subnet_to_cost[get_subnet(conn.address, conn.mask)]
                alt = node_to_dist[u] + cost
                v = conn.node_name
                if alt < node_to_dist[v]:
                    node_to_dist[v] = alt
                    node_to_prev[v] = u
        return node_to_dist, node_to_prev

    def output_graph(self):
        routers: List[NodeDefinition] = [n for v in self._subnet_to_nodes.values()
                                         for n in v if n.node_type == NodeType.ROUTER]
        router_names: List[str] = [n.node_name for n in routers]
        router_names = list(set(router_names))
        print("graph Network{")
        for router_name in router_names:
            print(f"    {router_name} [shape=circle];")
        for subnet, nodes in self._subnet_to_nodes.items():
            cost: int = self._subnet_to_cost[subnet]
            for i in range(len(nodes)):
                for j in range(i+1, len(nodes)):

                    print(f'    {nodes[i].node_name} -- {nodes[j].node_name} [label="{cost}"];')
        print("}")
        return

    def find_shortest_link_between(self, node_name1: str, node_name2: str) -> NodeDefinition:
        common_subnets: list[str] = []
        for subnet, nodes in self._subnet_to_nodes.items():
            contained_nodes: list[str] = [n.node_name for n in nodes]
            if node_name1 in contained_nodes and node_name2 in contained_nodes:
                common_subnets.append(subnet)
        cost_to_subnet = {cost: subnet for subnet, cost in self._subnet_to_cost.items() if subnet in common_subnets}
        min_cost = min(cost_to_subnet.keys())
        cheapest_subnet = cost_to_subnet[min_cost]
        # If a node a multiple interfaces in the cheapest subnet I believe that taking any of them should suffice
        return [n for n in self._subnet_to_nodes[cheapest_subnet] if n.node_name == node_name2][0]

    def set_up_emulation(self):
        shortest_paths = self._find_shortest_paths()
        topology: NetworkTopology = NetworkTopology(subnet_to_nodes=self._subnet_to_nodes,
                                                    subnet_to_cost=self._subnet_to_cost)

        # r2 ip route add 192.168.0.4/30 via 192.168.0.1
        # r3 ip route add 192.168.0.0/30 via 192.168.0.5

        net = Mininet(topo=topology, controller=None, switch=OVSBridge)
        net.start()
        r2 = net["r2"]
        r3 = net["r3"]

        node_names = [n.node_name for v in self._subnet_to_nodes.values() for n in v]
        node_names = list(set(node_names))
        # set up routing tables
        for source_node, paths in shortest_paths.items():
            node_to_dist = paths[0]
            node_to_prev = paths[1]
            source_node_interfaces = [n for v in self._subnet_to_nodes.values() for n in v if
                                      n.node_name == source_node]
            for node_name in node_names:
                if node_name == source_node:
                    continue
                prev = node_to_prev[node_name]
                # prev and node are neighbours therefore they are both part of at least one subnet
                link = self.find_shortest_link_between(node_name, prev)

                for si in source_node_interfaces:
                    complete_subnet_address = si.complete_address()
                    print(f"{node_name} ip route add {complete_subnet_address} via {link.address}")
                    net[node_name].cmd(f"ip route add {complete_subnet_address} via {link.address}")
                pass
            #  router1.cmd('ip route add 10.0.2.0/24 via 10.1.2.2')
            pass
        pass


        # r2.cmd("ip route add 192.168.0.4/30 via 192.168.0.1")
        # r3.cmd("ip route add 192.168.0.0/30 via 192.168.0.5")

        CLI(net)
        net.stop()
        return


def main():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="A tool to define the emulation a network")
    parser.add_argument("--draw", action="store_true",
                        help="output a map of the routers in GraphViz format")
    parser.add_argument("definition", type=Path, help="the definition file of the network in YAML")
    args: argparse.Namespace = parser.parse_args()
    
    definition_file: Path = args.definition
    should_draw: bool = args.draw
    validate_definition_file(definition_file=definition_file)
    network_specification: dict = read_definition(definition_file=definition_file)
    network_definition: NetworkDefinition = NetworkDefinition(network_definition=network_specification)
    if should_draw:
        network_definition.output_graph()

    network_definition.set_up_emulation()


if __name__ == "__main__":
    main()
