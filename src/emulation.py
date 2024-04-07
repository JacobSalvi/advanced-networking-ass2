import argparse
from pathlib import Path
from typing import List, Dict, Optional
import ipaddress
from collections import defaultdict
import yaml


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


class RouterInterface(BaseInterface):
    def __init__(self, name: str, address: str, mask: str, node, cost: int = 1):
        super().__init__(name=name, address=address, mask=mask, node=node)
        self._cost: int = cost

    def cost(self) -> int:
        return self._cost


class Connection:
    def __init__(self, node1, node2, interface1: BaseInterface, interface2: BaseInterface, cost: int):
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
                    else:
                        switch = host.switch()
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
    if should_draw:
        network_definition.output_graph_representation()
    return


if __name__ == '__main__':
    main()
