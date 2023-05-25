#!/usr/bin/env python
import sys
from rich.console import Console
from OutputParse import OutputParser
from Table import fill_simple_table

if __name__ == "__main__":
    console = Console()
    nmap_xml = sys.argv[1]
    with open(nmap_xml, 'r') as xml:
        xml_data = xml.read()
        rundata, parsed = OutputParser.parse_nmap_xml(xml_data)
        nmap_table = fill_simple_table(
            exec_data=rundata, parsed_xml=parsed)
        console.print(nmap_table)
