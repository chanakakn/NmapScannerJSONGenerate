#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import argparse
import nmap
import json
import logging

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(levelname)s - %(message)s")
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class NmapScannerJSONGenerate:
    def __init__(self):
        self.nmsc = nmap.PortScanner()

    def nmapScan(self, host, port):
        try:
            logger.info("Checking port %s ..........", port)
            self.nmsc.scan(host, port)

            # Command info
            logger.info("Executing command: %s", self.nmsc.command_line())
            port_info = self.nmsc[host]['tcp'][int(port)]
            state = port_info['state']
            logger.info("%s tcp/%s %s", host, port, state)
            logger.info(port_info)
            server = port_info.get('product', '')
            version = port_info.get('version', '')
            logger.info("%s %s tcp/%s", server, version, port)

        except Exception as e:
            logger.error("Error connecting to %s for port scanning: %s", host, str(e))

    def nmapScanJSONGenerate(self, host, ports):
        try:
            logger.info("Checking ports %s ..........", ports)
            self.nmsc.scan(host, ports)

            # Command info
            logger.info("Executing command: %s", self.nmsc.command_line())

            results = {}
            for host in self.nmsc.all_hosts():
                if 'tcp' in self.nmsc[host]:
                    open_ports = []
                    for port, port_info in self.nmsc[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append({str(port_info['name']): port})
                    if open_ports:
                        results[host] = open_ports

            # Store info
            file_info = "scan_{}.json".format(host)
            with open(file_info, "w") as file_json:
                json.dump(results, file_json)

            logger.info("File '%s' was generated with scan results", file_info)

        except Exception as e:
            logger.error("Error connecting to %s for port scanning: %s", host, str(e))


def main():
    parser = argparse.ArgumentParser(description="Nmap Port Scanner with JSON Output")
    parser.add_argument('-H', dest='host', type=str, help='Specify the target host.')
    parser.add_argument('-p', dest='ports', type=str, help='Specify the target port(s) separated by comma.')
    args = parser.parse_args()

    if args.host is None or args.ports is None:
        parser.print_help()
        exit(1)

    host = args.host
    ports = args.ports.split(',')

    try:
        NmapScannerJSONGenerate().nmapScanJSONGenerate(host, ports)
    except Exception as e:
        logger.error("An error occurred during port scanning: %s", str(e))


if __name__ == "__main__":
    main()
