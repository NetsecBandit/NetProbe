
User Guide: NetProbe


Introduction
This guide will walk you through how to use the Python-based Network Enumeration and Scanning Tool. This tool allows you to discover active devices on a network, check which ports are open, identify the services running on those ports, and check for potential vulnerabilities.

Requirements
Python 3.x: Ensure you have Python installed. Check by running:
	python --version

Clone or download the script.

Ensure any required libraries (like argparse, socket, subprocess, etc.) are installed. For most users, these libraries come pre-installed with Python.

Run the following command:
python NET_Probe.py --target <IP or IP range> --output <output format>


Command-Line Options
--target: This is the IP address or IP range you want to scan.

Example of a range: 192.168.1.0/24 (scans all IPs in that range).
Example of a single IP: 192.168.1.1.
--output: Specifies the format in which you want the results saved.

text: Saves the results in a plain text file (scan_results.txt).
json: Saves the results in a structured JSON format (scan_results.json).



How It Works
Network Discovery (Ping Sweep):

The tool sends ping requests to each IP address in the specified range to check if devices are online.
Active devices will be scanned further.
Port Scanning:

The tool checks a list of common ports (e.g., 22 for SSH, 80 for HTTP, 443 for HTTPS) to see if they are open or closed.
If a port is open, it suggests that a service is running on that port.
Banner Grabbing:

The tool connects to open ports and tries to read the initial "banner" that the service sends. This banner often contains information about the software version.
Vulnerability Checking:

The tool compares the service banner (software version) to a list of known vulnerabilities. If a match is found, it reports the relevant security vulnerability.
OS Fingerprinting:

The tool makes an educated guess about the operating system running on the device, based on network characteristics.



Best Practices for Using the Tool
Run in a Controlled Environment:

Make sure you have permission to scan the network. Unauthorized scanning may violate terms of service or laws.
Start with Small IP Ranges:

Scanning large networks can take a long time. Start with a small range (e.g., 192.168.1.0/28) and expand as needed.
Analyze Open Ports Carefully:

Open ports could indicate services that may need to be secured or patched.
Review Vulnerabilities:

If the tool detects vulnerabilities, ensure those services are updated or patched to avoid security risks.
Save Your Results:

Use the --output json option if you plan to analyze the data later or import it into another tool.
Common Issues and Solutions
No Active Hosts Found:

Make sure the devices on the network are powered on and connected to the network.
Verify the IP range is correct.
Port Scanning Takes Too Long:

Use a smaller IP range or reduce the number of ports being scanned.
No Banners Received:

Some services may not provide a banner, or the port may be blocked by a firewall.



Advanced Usage
Modify Port List:

By default, the tool scans common ports (22, 80, 443). You can modify the script to scan additional ports by updating the list in the port_scan function.
Multithreading (Optional):

For advanced users, consider adding multithreading to the tool to speed up scans, especially on large networks.
