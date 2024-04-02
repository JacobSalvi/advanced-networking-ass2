import argparse
from pathlib import Path
from typing import List

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
    def __init__(self, name: str, address: str, mask: str):
        self._name: str = name
        self._address: str = address
        self._mask: str = mask


class RouterInterface(BaseInterface):
    def __init__(self, name: str, address: str, mask: str, cost: int = 1):
        super().__init__(name=name, address=address, mask=mask)
        self._cost: int = cost


class RouterDefinition:
    def __init__(self, name: str, router_def: dict):
        self._name: str = name
        self._intefaces: List[RouterInterface] = []
        for interface_name, interface_description in router_def.items():
            address: str = interface_description.get('address')
            mask: str = interface_description.get('mask')
            cost: int = interface_description.get('cost', 1)
            self._intefaces.append(RouterInterface(name=interface_name, address=address, mask=mask, cost=int(cost)))

    def name(self) -> str:
        return self._name


class HostDefinition:
    def __init__(self, name: str, interface_name: str, interface_address: str, interface_mask: str):
        self._name: str = name
        self._interface: BaseInterface = BaseInterface(name=interface_name,
                                                       address=interface_address, mask=interface_mask)


class NetworkDefinition:
    def __init__(self, network_defition: dict) -> None:
        self._routers: List[RouterDefinition] = NetworkDefinition._get_routers_definition(definition=network_defition)
        self._hosts: List[HostDefinition] = NetworkDefinition._get_hosts_definition(definition=network_defition)

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
        for router in self._routers:
            print(f"  {router.name()} [shape=circle];")
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
    network_definition: NetworkDefinition = NetworkDefinition(network_defition=network_specification)
    if should_draw:
        network_definition.output_graph_representation()
    return


if __name__ == '__main__':
    main()
