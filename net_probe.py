import argparse
import json
import os
import platform
import socket
import subprocess

def ping_sweep(ip_range):
    active_hosts = []
    os_type = platform.system()

    for i in range(1, 255):
        ip = f"{ip_range}.{i}"
        if os_type == "Windows":
            command = f"ping -n 1 -w 1 {ip}"
        else:
            command = f"ping -c 1 -W 1 {ip}"

        response = subprocess.call(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response == 0:
            active_hosts.append(ip)

    return active_hosts

def port_scan(host, ports):
    open_ports = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports[port] = 'open'
        else:
            open_ports[port] = 'closed'
        sock.close()
    return open_ports

def banner_grab(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception as e:
        return f"Error: {str(e)}"

def check_vulnerabilities(service_banner):
    vulnerabilities = {
        "Apache/2.4.1": "CVE-2012-0053",
        "OpenSSH_7.4": "CVE-2016-10009"
    }
    return vulnerabilities.get(service_banner, "No known vulnerabilities")

def os_fingerprinting(ttl_value):
    if ttl_value >= 128:
        return "Windows"
    elif ttl_value >= 64:
        return "Linux/Unix"
    else:
        return "Unknown OS"

def find_and_kill_process(host, port):
    os_type = platform.system()

    if os_type == "Windows":
        try:
            result = subprocess.check_output(f'netstat -ano | findstr :{port}', shell=True, text=True)
            lines = result.strip().split('\n')
            for line in lines:
                if host in line or '0.0.0.0' in line or '::' in line:
                    pid = line.strip().split()[-1]
                    print(f"Found PID {pid} using port {port}.")
                    confirm = input(f"Do you want to kill PID {pid}? (y/n): ")
                    if confirm.lower() == 'y':
                        subprocess.call(f'taskkill /PID {pid} /F', shell=True)
                        print(f"Process {pid} killed.")
        except subprocess.CalledProcessError:
            print(f"Could not find any process using port {port}.")
    else:
        try:
            result = subprocess.check_output(f'lsof -i :{port}', shell=True, text=True)
            lines = result.strip().split('\n')
            if len(lines) > 1:
                pid = lines[1].split()[1]
                print(f"Found PID {pid} using port {port}.")
                confirm = input(f"Do you want to kill PID {pid}? (y/n): ")
                if confirm.lower() == 'y':
                    subprocess.call(f'kill -9 {pid}', shell=True)
                    print(f"Process {pid} killed.")
        except subprocess.CalledProcessError:
            print(f"Could not find any process using port {port}.")

def get_ttl(host):
    os_type = platform.system()
    try:
        if os_type == "Windows":
            result = subprocess.check_output(f"ping -n 1 {host}", shell=True, text=True)
            for line in result.splitlines():
                if "TTL=" in line:
                    ttl_value = int(line.split("TTL=")[-1])
                    return ttl_value
        else:
            result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
            for line in result.splitlines():
                if "ttl=" in line.lower():
                    ttl_value = int(line.lower().split("ttl=")[-1].split()[0])
                    return ttl_value
    except Exception as e:
        print(f"Error getting TTL for {host}: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description='A Beginner-Friendly Network Enumeration and Scanning Tool')
    
    parser.add_argument('--target', type=str, required=True, help='Target IP or IP range (e.g., 192.168.1.0/24)')
    parser.add_argument('--output', type=str, choices=['text', 'json'], help='Output format (text or json)', default='text')
    
    args = parser.parse_args()

    print(f"Scanning target: {args.target}")
    ip_range = args.target.rsplit('.', 1)[0]
    active_hosts = ping_sweep(ip_range)

    scan_results = {'hosts': {}}

    for host in active_hosts:
        print(f"Scanning host: {host}")
        open_ports = port_scan(host, [22, 80, 443])
        scan_results['hosts'][host] = {
            'ports': open_ports,
            'banners': {},
            'vulnerabilities': {},
            'os_guess': None
        }
        for port, status in open_ports.items():
            if status == 'open':
                banner = banner_grab(host, port)
                scan_results['hosts'][host]['banners'][port] = banner
                vuln = check_vulnerabilities(banner)
                scan_results['hosts'][host]['vulnerabilities'][port] = vuln

        ttl = get_ttl(host)
        if ttl:
            os_guess = os_fingerprinting(ttl)
        else:
            os_guess = "Unknown"
        scan_results['hosts'][host]['os_guess'] = os_guess

    # Offer to kill processes on open ports
    for host, details in scan_results['hosts'].items():
        for port, status in details['ports'].items():
            if status == 'open':
                choice = input(f"Host {host} has port {port} open. Do you want to attempt to kill the process using this port? (y/n): ")
                if choice.lower() == 'y':
                    find_and_kill_process(host, port)

    if args.output == 'json':
        with open('scan_results.json', 'w') as f:
            json.dump(scan_results, f, indent=4)
        print("Results saved to scan_results.json")
    else:
        with open('scan_results.txt', 'w') as f:
            for host, details in scan_results['hosts'].items():
                f.write(f"Host: {host}\n")
                for port, status in details['ports'].items():
                    f.write(f"  Port {port}: {status}\n")
                    if port in details['banners']:
                        f.write(f"    Banner: {details['banners'][port]}\n")
                    if port in details['vulnerabilities']:
                        f.write(f"    Vulnerability: {details['vulnerabilities'][port]}\n")
                f.write(f"  OS Guess: {details['os_guess']}\n")
        print("Results saved to scan_results.txt")

if __name__ == '__main__':
    main()