#!/usr/bin/env python
import sys
import logging
from rich.console import Console
from OutputParse import OutputParser
from Table import fill_simple_table
from NetworkScanner import NMapRunner
if __name__ == "__main__":
    console = Console()
    try:
        scanner = NMapRunner()
    #
    # nmap_xml = sys.argv[1]
    # with open(nmap_xml, 'r') as xml:
    #     xml_data = xml.read()
    #     rundata, parsed = OutputParser.parse_nmap_xml(xml_data)
    #     nmap_table = fill_simple_table(
    #         exec_data=rundata, parsed_xml=parsed)
    #     console.print(nmap_table)
    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        console.log("Scan interrupted, exiting...")
        pass
    sys.exit(0)
