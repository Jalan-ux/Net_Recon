#!/usr/bin/env python3
"""
Network Scanner Tool with GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import nmap
from scapy.all import ARP, Ether, srp
import socket
import ipaddress
import netifaces

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.discovered_hosts = []
        self.scanning = False
        
        # Create main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Network Scanner", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)
        
        # Phase 1: Network Discovery Section
        discovery_frame = ttk.LabelFrame(main_frame, text="Phase 1: Network Discovery", 
                                        padding="10")
        discovery_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        discovery_frame.columnconfigure(1, weight=1)
        
        # Network range display
        ttk.Label(discovery_frame, text="Network Range:").grid(row=0, column=0, 
                                                               sticky=tk.W, pady=5)
        self.network_range_var = tk.StringVar(value="Detecting...")
        ttk.Label(discovery_frame, textvariable=self.network_range_var, 
                 font=('Arial', 10)).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Start scan button
        self.start_scan_btn = ttk.Button(discovery_frame, text="Start Network Scan", 
                                         command=self.start_network_scan)
        self.start_scan_btn.grid(row=0, column=2, padx=5)
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(discovery_frame, textvariable=self.progress_var).grid(row=1, column=0, 
                                                                        columnspan=3, 
                                                                        sticky=tk.W, pady=5)
        self.progress_bar = ttk.Progressbar(discovery_frame, mode='indeterminate')
        self.progress_bar.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Discovered Devices", padding="10")
        results_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview for results
        columns = ('IP Address', 'MAC Address', 'Hostname')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=10)
        
        # Define headings
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=250)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Advanced scan section
        advanced_frame = ttk.LabelFrame(main_frame, text="Phase 2: Advanced Scan", 
                                       padding="10")
        advanced_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        advanced_frame.columnconfigure(1, weight=1)
        
        ttk.Label(advanced_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_ip_var = tk.StringVar()
        self.target_ip_entry = ttk.Entry(advanced_frame, textvariable=self.target_ip_var, 
                                         width=30)
        self.target_ip_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        self.advanced_scan_btn = ttk.Button(advanced_frame, text="Start Advanced Scan", 
                                           command=self.start_advanced_scan, state='disabled')
        self.advanced_scan_btn.grid(row=0, column=2, padx=5)
        
        # Advanced scan results
        results_text_frame = ttk.LabelFrame(main_frame, text="Advanced Scan Results", 
                                           padding="10")
        results_text_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_text_frame.columnconfigure(0, weight=1)
        results_text_frame.rowconfigure(0, weight=1)
        
        main_frame.rowconfigure(4, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_text_frame, height=15, 
                                                      wrap=tk.WORD, font=('Courier', 9))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Detect network range on startup
        self.detect_network_range()
        
    def detect_network_range(self):
        """Detect the local network range"""
        try:
            # Get default gateway interface
            gws = netifaces.gateways()
            default_interface = gws['default'][netifaces.AF_INET][1]
            
            # Get IP address and netmask
            addrs = netifaces.ifaddresses(default_interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip_addr = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network range
            network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
            self.network_range = str(network)
            self.network_range_var.set(self.network_range)
            
        except Exception as e:
            self.network_range = "192.168.1.0/24"  # Default fallback
            self.network_range_var.set(f"{self.network_range} (default)")
            print(f"Error detecting network: {e}")
    
    def start_network_scan(self):
        """Start the network discovery scan"""
        if self.scanning:
            messagebox.showwarning("Scan in Progress", 
                                  "A scan is already running. Please wait.")
            return
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.discovered_hosts = []
        self.results_text.delete(1.0, tk.END)
        
        # Start scan in separate thread
        self.scanning = True
        self.start_scan_btn.config(state='disabled')
        self.advanced_scan_btn.config(state='disabled')
        self.progress_bar.start(10)
        self.progress_var.set("Scanning network... Please wait")
        
        scan_thread = threading.Thread(target=self.perform_network_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def perform_network_scan(self):
        """Perform ARP scan to discover devices on the network"""
        try:
            # Create ARP request
            arp_request = ARP(pdst=self.network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            total = len(answered_list)
            for idx, element in enumerate(answered_list):
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                
                host_info = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname
                }
                self.discovered_hosts.append(host_info)
                
                # Update progress
                progress = int((idx + 1) / total * 100)
                self.progress_var.set(f"Scanning... {progress}%")
            
            # Update UI
            self.root.after(0, self.update_discovery_results)
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Scan Error", msg))
        finally:
            self.scanning = False
            self.root.after(0, self.scan_complete)
    
    def update_discovery_results(self):
        """Update the treeview with discovered hosts"""
        for host in self.discovered_hosts:
            self.tree.insert('', tk.END, values=(host['ip'], host['mac'], host['hostname']))
    
    def scan_complete(self):
        """Called when network scan is complete"""
        self.progress_bar.stop()
        self.progress_var.set(f"Scan complete! Found {len(self.discovered_hosts)} device(s)")
        self.start_scan_btn.config(state='normal')
        
        if self.discovered_hosts:
            # Ask if user wants to perform advanced scan
            response = messagebox.askyesno("Advanced Scan", 
                                          "Network scan complete!\n\n"
                                          "Would you like to perform an advanced scan "
                                          "on a specific device?")
            if response:
                self.advanced_scan_btn.config(state='normal')
                messagebox.showinfo("Advanced Scan", 
                                  "Please enter the IP address from the list above "
                                  "and click 'Start Advanced Scan'")
    
    def start_advanced_scan(self):
        """Start advanced nmap scan"""
        target_ip = self.target_ip_var.get().strip()
        
        if not target_ip:
            messagebox.showwarning("No Target", "Please enter a target IP address")
            return
        
        # Validate IP is in discovered hosts
        valid_ips = [host['ip'] for host in self.discovered_hosts]
        if target_ip not in valid_ips:
            messagebox.showwarning("Invalid IP", 
                                  "Please select an IP from the discovered devices")
            return
        
        # Start scan in separate thread
        self.advanced_scan_btn.config(state='disabled')
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting advanced scan on {target_ip}...\n\n")
        
        scan_thread = threading.Thread(target=self.perform_advanced_scan, args=(target_ip,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def perform_advanced_scan(self, target_ip):
        """Perform nmap scan for ports, services, and OS detection"""
        try:
            nm = nmap.PortScanner()
            
            self.root.after(0, lambda: self.results_text.insert(tk.END, 
                                                               "Scanning top ports...\n"))
            
            # Scan top 1000 ports with service version detection and OS detection
            # Note: OS detection requires root/admin privileges
            nm.scan(target_ip, arguments='-sV -O --top-ports 1000')
            
            results = []
            results.append("=" * 80)
            results.append(f"ADVANCED SCAN RESULTS FOR {target_ip}")
            results.append("=" * 80)
            results.append("")
            
            if target_ip in nm.all_hosts():
                host = nm[target_ip]
                
                # Host status
                results.append(f"Host Status: {host.state()}")
                results.append("")
                
                # OS Detection
                if 'osmatch' in host:
                    results.append("OS DETECTION:")
                    results.append("-" * 40)
                    for osmatch in host['osmatch']:
                        results.append(f"  OS: {osmatch['name']}")
                        results.append(f"  Accuracy: {osmatch['accuracy']}%")
                        results.append("")
                else:
                    results.append("OS DETECTION: Unable to detect (may require root privileges)")
                    results.append("")
                
                # Port scan results
                results.append("OPEN PORTS AND SERVICES:")
                results.append("-" * 40)
                
                for proto in host.all_protocols():
                    results.append(f"Protocol: {proto.upper()}")
                    ports = host[proto].keys()
                    
                    for port in sorted(ports):
                        port_info = host[proto][port]
                        state = port_info['state']
                        
                        if state == 'open':
                            service = port_info.get('name', 'unknown')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            extrainfo = port_info.get('extrainfo', '')
                            
                            service_str = f"  Port {port}: {state}"
                            service_str += f"\n    Service: {service}"
                            
                            if product:
                                service_str += f"\n    Product: {product}"
                            if version:
                                service_str += f" {version}"
                            if extrainfo:
                                service_str += f" ({extrainfo})"
                            
                            results.append(service_str)
                            results.append("")
                
                if not any('Port' in line for line in results):
                    results.append("  No open ports detected in the top 1000 ports")
                    results.append("")
                
            else:
                results.append(f"Host {target_ip} appears to be down or unreachable")
            
            results.append("=" * 80)
            results.append("Scan Complete!")
            results.append("=" * 80)
            
            # Update UI
            result_text = "\n".join(results)
            self.root.after(0, lambda: self.display_advanced_results(result_text))
            
        except Exception as e:
            error_msg = f"Error during advanced scan: {str(e)}\n\n"
            error_msg += "Note: OS detection requires root/administrator privileges.\n"
            error_msg += "Try running the script with sudo (Linux/Mac) or as Administrator (Windows)."
            self.root.after(0, lambda msg=error_msg: self.display_advanced_results(msg))
        finally:
            self.root.after(0, lambda: self.advanced_scan_btn.config(state='normal'))
    
    def display_advanced_results(self, text):
        """Display advanced scan results in the text widget"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, text)

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
def is_valid_target_ip(target_ip, discovered_hosts):
    return target_ip in [host['ip'] for host in discovered_hosts]
