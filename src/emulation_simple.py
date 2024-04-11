import argparse
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
        host_names: List[str] = [n.node_name for n in nodes if n.node_type == NodeType.HOST]
        for host_name in host_names:
            self.addHost(host_name)

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
                switch = self.addSwitch(f"switch-{self.switch_id}")
                self.switch_id += 1
                for node in subnet_nodes:
                    self.addLink(switch, node.node_name)
                pass
        pass


class NetworkDefinition:
    def __init__(self, network_definition: dict):
        self._subnet_to_nodes: Dict[str, List[NodeDefinition]] = defaultdict(list)
        self._subnet_to_cost: Dict[str, int] = defaultdict(lambda: 1)
        routers: dict = network_definition.get("routers")
        self._load_routers(routers_def=routers)

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

    def set_up_emulation(self):
        topology: NetworkTopology = NetworkTopology(subnet_to_nodes=self._subnet_to_nodes,
                                                    subnet_to_cost=self._subnet_to_cost)
        net = Mininet(topo=topology, controller=None)
        net.start()
        # set up routing tables
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
