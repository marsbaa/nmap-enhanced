import re
import shlex
from typing import Optional
from xml.etree import ElementTree
IGNORED_CPES = {"cpe:/o:linux:linux_kernel"}


class OutputParser:
    """
    Parse Nmap raw XML output
    """

    @staticmethod
    def parse_nmap_xml(xml: str):
        """
        Parse XML and return details for the scanned ports.
        It is assumed this method is never called directly by the user, so no special sanity checks are done in the XML
        @param xml: NMAP results in XML file
        @return: tuple NMAP arguments, port details
        """
        parsed_data = []
        root = ElementTree.fromstring(xml)
        nmap_args = root.attrib['args']
        for host in root.findall('host'):
            for address in host.findall('address'):
                curr_address = address.attrib['addr']
                data = {
                    'address': curr_address,
                    'ports': []
                }
                states = host.findall('ports/port/state')
                ports = host.findall('ports/port')
                for i in range(len(ports)):
                    if states[i].attrib['state'] == 'closed':
                        continue  # Skip closed ports
                    port_id = ports[i].attrib['portid']
                    protocol = ports[i].attrib['protocol']
                    services = ports[i].findall('service')
                    cpe_list = []
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    for service in services:
                        for key in ['name', 'product', 'version']:
                            if key in service.attrib:
                                if key == 'name':
                                    service_name = service.attrib['name']
                                elif key == 'product':
                                    service_product = service.attrib['product']
                                elif key == 'version':
                                    service_version = service.attrib['version']
                        cpes = service.findall('cpe')
                        for cpe in cpes:
                            if cpe.text in IGNORED_CPES:
                                continue
                            cpe_list.append(cpe.text)
                        data['ports'].append({
                            'port_id': port_id,
                            'protocol': protocol,
                            'service_name': service_name,
                            'service_product': service_product,
                            'service_version': service_version,
                            'cpes': cpe_list
                        })
                parsed_data.append(data)
        return nmap_args, parsed_data


MIN_LEN_TARGET = 9
MAX_LEN_TARGET = 50


def target_validator(target: Optional[str]) -> str:
    """
    Simple validator for NMAP target expressions
    @param target: (scanme.homenmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254). None or empty are valid
    @return:
    """
    if target:
        regexp_list = [
            '-[a-z-A-Z][A-Z]*',
            '-[a-zA-Z]\\d*',
            '--[a-z-]+'
        ]
        if len(target) < MIN_LEN_TARGET:
            raise ValueError(
                f"Provided length for target is too small < {MIN_LEN_TARGET}")
        if len(target) > MAX_LEN_TARGET:
            raise ValueError(
                f"Provided length for target is too big < {MAX_LEN_TARGET}")
        for arg in shlex.split(target):
            for regexp in regexp_list:
                if re.search(regexp, arg):
                    raise ValueError(
                        f"You cannot override NMAP arguments: {arg}")
    return target
