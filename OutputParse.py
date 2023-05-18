import xml.etree.ElementTree as ElementTree
IGNORED_CPES = {"cpe:/o:linux:linux_kernel"}


class OutputParser:
    """
    Parse Nmap raw XML output
    """

    @staticmethod
    def parse_nmap_xml(xml: str):
        """
        Parse XML and return details for the scanned ports
        @param xml:
        @return: tuple nmaps arguments, port details
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
