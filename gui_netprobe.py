import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import platform
import subprocess
import socket
import json

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
        return None

def find_and_kill_process(host, port):
    os_type = platform.system()

    if os_type == "Windows":
        try:
            result = subprocess.check_output(f'netstat -ano | findstr :{port}', shell=True, text=True)
            lines = result.strip().split('\n')
            for line in lines:
                if host in line or '0.0.0.0' in line or '::' in line:
                    pid = line.strip().split()[-1]
                    return pid
        except subprocess.CalledProcessError:
            return None
    else:
        try:
            result = subprocess.check_output(f'lsof -i :{port}', shell=True, text=True)
            lines = result.strip().split('\n')
            if len(lines) > 1:
                pid = lines[1].split()[1]
                return pid
        except subprocess.CalledProcessError:
            return None

def kill_pid(pid):
    os_type = platform.system()
    if os_type == "Windows":
        subprocess.call(f'taskkill /PID {pid} /F', shell=True)
    else:
        subprocess.call(f'kill -9 {pid}', shell=True)

def scan_network(target_ip, output_widget):
    output_widget.delete(1.0, tk.END)
    ip_range = target_ip.rsplit('.', 1)[0]
    active_hosts = ping_sweep(ip_range)

    scan_results = {'hosts': {}}

    for host in active_hosts:
        output_widget.insert(tk.END, f"\nScanning host: {host}\n")
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

        for port, status in open_ports.items():
            output_widget.insert(tk.END, f"Port {port}: {status}\n")
            if status == 'open':
                output_widget.insert(tk.END, f"    Banner: {scan_results['hosts'][host]['banners'][port]}\n")
                output_widget.insert(tk.END, f"    Vulnerability: {scan_results['hosts'][host]['vulnerabilities'][port]}\n")
                pid = find_and_kill_process(host, port)
                if pid:
                    def kill_this(pid=pid):
                        if messagebox.askyesno("Kill Process", f"Kill process {pid} using port {port} on host {host}?"):
                            kill_pid(pid)
                            messagebox.showinfo("Process Killed", f"Process {pid} has been killed.")
                    kill_btn = tk.Button(output_widget, text=f"Kill PID {pid}", command=kill_this)
                    output_widget.window_create(tk.END, window=kill_btn)
                    output_widget.insert(tk.END, "\n")

        output_widget.insert(tk.END, f"OS Guess: {os_guess}\n")

    output_widget.insert(tk.END, "\nScan complete!\n")

def start_scan(entry, output_widget):
    target = entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP or range.")
        return
    threading.Thread(target=scan_network, args=(target, output_widget)).start()

def create_gui():
    window = tk.Tk()
    window.title("Network Scanner GUI")
    window.geometry("800x600")

    label = tk.Label(window, text="Target IP/Range:")
    label.pack(pady=5)

    target_entry = tk.Entry(window, width=50)
    target_entry.pack(pady=5)

    scan_button = tk.Button(window, text="Start Scan", command=lambda: start_scan(target_entry, output))
    scan_button.pack(pady=10)

    output = scrolledtext.ScrolledText(window, width=100, height=30)
    output.pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    create_gui()