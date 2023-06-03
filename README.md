# NmapScannerJSONGenerate

The script defines a class called NmapScannerJSONGenerate with two methods:

nmapScan: This method takes a host and a port as input and performs a port scan using the nmap module. It prints the state, server, and version information for the specified port on the specified host.

nmapScanJSONGenerate: This method takes a host and a list of ports as input and performs a port scan using the nmap module. It generates a JSON file with the scan results, including the host, protocol, port, and state information for each open port.

The main function is responsible for parsing command-line options using optparse and calling the nmapScanJSONGenerate method with the specified host and ports.

To use this script, you need to have the nmap and optparse modules installed. You can run it from the command line and specify the target host and port(s) using the -H and -p options, respectively. The script will then perform the port scan and generate a JSON file with the results.
