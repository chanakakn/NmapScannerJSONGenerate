#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import optparse
import nmap
import json
import argparse
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def callbackMySql(host, result, results_df):
    try:
        script = result['scan'][host]['tcp'][3306]['script']

        logger.info("Command line: " + result['nmap']['command_line'])

        for key, value in script.items():
            logger.info('Script {0} --> {1}'.format(key, value))
            results_df = results_df.append({'Host': host, 'Script': key, 'Result': value}, ignore_index=True)

    except KeyError:
        # Key is not present
        pass


class NmapScannerAsync:
    def __init__(self):
        self.nmsync = nmap.PortScanner()
        self.nmasync = nmap.PortScannerAsync()

    def scanning(self):
        while self.nmasync.still_scanning():
            self.nmasync.wait(5)

    def nmapScan(self, hostname, port, results_df):
        try:
            logger.info("Checking port " + port + " ..........")

            self.nmsync.scan(hostname, port)

            self.state = self.nmsync[hostname]['tcp'][int(port)]['state']
            logger.info("[+] " + hostname + " tcp/" + port + " " + self.state)

            # MySQL
            if port == '3306' and self.nmsync[hostname]['tcp'][int(port)]['state'] == 'open':
                logger.info('Checking MySQL port with Nmap scripts......')

                script_list = [
                    'mysql-audit',
                    'mysql-brute',
                    'mysql-databases',
                    'mysql-dump-hashes',
                    'mysql-empty-password',
                    'mysql-enum',
                    'mysql-info',
                    'mysql-query',
                    'mysql-users',
                    'mysql-variables',
                    'mysql-vuln-cve2012-2122',
                    'mysql-vuln-cve2016-6662',
                    'mysql-vuln-cve2019-11581'
                ]

                for script in script_list:
                    logger.info('Checking {0}.nse.....'.format(script))
                    self.nmasync.scan(hostname, arguments="-A -sV -p3306 --script {0}".format(script),
                                      callback=callbackMySql, callback_args=(results_df,))
                    self.scanning()

        except Exception as e:
            logger.error(str(e))
            logger.error("Error connecting to " + hostname + " for port scanning")
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nmap scanner async')

    # Main arguments
    parser.add_argument("-target", dest="target", help="target IP / domain", required=True)
    parser.add_argument("-ports", dest="ports",
                        help="Please specify the target port(s) separated by commas [80,8080 by default]",
                        default="80,8080")
    parser.add_argument("-output", dest="output", help="output Excel file name", default="results.xlsx")

    parsed_args = parser.parse_args()

    port_list = parsed_args.ports.split(',')
    ip = parsed_args.target
    output_file = parsed_args.output

    results_df = pd.DataFrame(columns=['Host', 'Script', 'Result'])

    try:
        for port in port_list:
            NmapScannerAsync().nmapScan(ip, port, results_df)
    except Exception as e:
        logger.error(str(e))

    try:
        results_df.to_excel(output_file, index=False)
        logger.info("Results saved to " + output_file)
    except Exception as e:
        logger.error("Error saving results to " + output_file)
        logger.error(str(e))
