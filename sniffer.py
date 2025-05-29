import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
from collections import Counter
import matplotlib.pyplot as plt
import queue
import platform
from scapy.all import sniff, TCP, UDP, IP, DNS, DNSQR, ICMP, Raw

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        root.title("Basic Packet Sniffer")
        root.configure(bg="#2E2E2E")
        root.geometry("1000x800")  
        root.minsize(1000, 800)
        root.maxsize(1000, 800)
        
        # Initialize variables
        self.packet_counter = Counter()
        self.pause_flag = threading.Event()
        self.stop_flag = threading.Event()
        self.sniffing_active = False
        self.current_protocol_filter = "All"
        self.captured_packets = []
        self.search_term = ""
        self.display_options = {"IP": True, "Ports": True, "Protocol": True, "Size": True}
        self.packet_queue = queue.Queue()
        
        # Initialize filter variables
        self.filter_tcp = tk.BooleanVar(value=True)
        self.filter_udp = tk.BooleanVar(value=True)
        self.filter_dns = tk.BooleanVar(value=True)
        self.filter_icmp = tk.BooleanVar(value=True)  
        self.filter_other = tk.BooleanVar(value=True)
        
        # Determine default network interface
        self.interface = self.get_default_interface()
        
        # Create GUI components
        self.create_frames()
        self.create_control_frame()
        self.create_filter_frame()
        self.create_display_frame()
        self.create_summary_frame()
        self.create_output_text()
        
        # Start GUI update loop
        self.root.after(100, self.update_gui)
    
    def get_default_interface(self):
        if platform.system() == "Windows":
            return None  # Let scapy choose default on Windows
        else:
            try:
                import netifaces
                gateways = netifaces.gateways()
                return gateways['default'][netifaces.AF_INET][1]
            except:
                return "eth0"  # Fallback to eth0 if netifaces not available
    
    def create_frames(self):
        self.control_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.control_frame.pack(pady=5, fill=tk.X)
        
        self.filter_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.filter_frame.pack(pady=5, fill=tk.X)
        
        self.display_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.display_frame.pack(pady=5, fill=tk.X)
        
        self.summary_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.summary_frame.pack(pady=5, fill=tk.X)
    
    def create_control_frame(self):
        # Define styles
        BUTTON_STYLE = {
            'bg': '#4CAF50', 
            'fg': 'white', 
            'activebackground': '#45a049',
            'relief': 'flat', 
            'font': ('Arial', 14, 'bold')
        }
        
        if platform.system() == "Darwin":  
            tk.Button(self.control_frame, text="Start", command=self.start_sniffer).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Pause", command=self.pause_sniffer).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Resume", command=self.resume_sniffer).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Stop", command=self.stop_sniffer).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Clear", command=self.clear_output).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Visualize", command=self.show_visualization).pack(side=tk.LEFT, padx=2)
        else:
            tk.Button(self.control_frame, text="Start", command=self.start_sniffer, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Pause", command=self.pause_sniffer, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Resume", command=self.resume_sniffer, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Stop", command=self.stop_sniffer, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Clear", command=self.clear_output, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
            tk.Button(self.control_frame, text="Visualize", command=self.show_visualization, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
    
    def create_filter_frame(self):
        LABEL_STYLE = {
            'bg': '#2E2E2E', 
            'fg': 'white', 
            'font': ('Arial', 14)
        }
        
        ENTRY_STYLE = {
            'bg': '#333333', 
            'fg': 'white', 
            'relief': 'flat', 
            'font': ('Arial', 14),
            'insertbackground': 'white'
        }
        
        BUTTON_STYLE = {
            'bg': '#4CAF50', 
            'fg': 'white', 
            'activebackground': '#45a049',
            'relief': 'flat', 
            'font': ('Arial', 14, 'bold')
        }
        
        # Dropdown menu for selecting type of protocol and filtering the rest
        tk.Label(self.filter_frame, text="Protocol Filter:", **LABEL_STYLE).pack(side=tk.LEFT, padx=2)
        
        self.protocol_filter = ttk.Combobox(self.filter_frame, values=["All", "TCP", "UDP", "DNS", "ICMP"], width=8, state="readonly")
        self.protocol_filter.set("All")
        self.protocol_filter.pack(side=tk.LEFT, padx=2)
        
        if platform.system() == "Darwin":  
            tk.Button(self.filter_frame, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        else:
            tk.Button(self.filter_frame, text="Apply", command=self.apply_filter, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
        
        tk.Label(self.filter_frame, text="Search:", **LABEL_STYLE).pack(side=tk.LEFT, padx=2)
        self.search_entry = tk.Entry(self.filter_frame, **ENTRY_STYLE, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=2)
        
        if platform.system() == "Darwin":   
            tk.Button(self.filter_frame, text="Search", command=self.search_stored_packets).pack(side=tk.LEFT, padx=2)
        else:
            tk.Button(self.filter_frame, text="Search", command=self.search_stored_packets, **BUTTON_STYLE).pack(side=tk.LEFT, padx=2)
    
    def create_display_frame(self):
        LABEL_STYLE = {
            'bg': '#2E2E2E', 
            'fg': 'white', 
            'font': ('Arial', 14)
        }
        
        # Allows us to filter the output to include size, port, protocol
        tk.Label(self.display_frame, text="Disable:", **LABEL_STYLE).pack(side=tk.LEFT, padx=2)
        for option in self.display_options:
            var = tk.BooleanVar(value=self.display_options[option])
            tk.Checkbutton(self.display_frame, text=option, variable=var, 
                          command=lambda o=option: self.toggle_display(o),
                          **LABEL_STYLE, selectcolor="#555555").pack(side=tk.LEFT, padx=2)
    
    def create_summary_frame(self):
        LABEL_STYLE = {
            'bg': '#2E2E2E', 
            'fg': 'white', 
            'font': ('Arial', 14)
        }
        
        # Summary showing how many packets for each type of protocol 
        self.summary_text = tk.StringVar()
       
        self.summary_text.set("TCP: 0 | UDP: 0 | DNS: 0 | ICMP: 0 | Other: 0")
        self.summary_label = tk.Label(self.summary_frame, textvariable=self.summary_text, **LABEL_STYLE)
        self.summary_label.pack()
    
    def create_output_text(self):
        TEXT_STYLE = {
            'bg': '#1C1C1C', 
            'fg': 'white', 
            'font': ('Consolas', 14),
            'insertbackground': 'white',
            'state': 'disabled'
        }
        
        # Output Text
        self.output_text = scrolledtext.ScrolledText(self.root, **TEXT_STYLE, width=100, height=25, wrap=tk.WORD)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.output_text.tag_config('highlight', background='yellow', foreground='black')
    
    # Function to process each packet
    def process_packet(self, packet):
        if self.pause_flag.is_set(): #checks if packet processing is paused
            return

        try:
            protocol = "Other"
            size = len(packet) #Extracts the packet size
            result = ""
            ip_src = ip_dst = sport = dport = dns_query = icmp_type = icmp_code = "" #initializing

            if IP in packet:
                ip_src = packet[IP].src #extracts source & destination addresses
                ip_dst = packet[IP].dst

                if TCP in packet:
                    protocol = "TCP"
                    sport = packet[TCP].sport  #extracting source and destination port no.
                    dport = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    if DNS in packet and packet[DNS].qr == 0:  # DNS Query
                        protocol = "DNS"
                        if packet.haslayer(DNSQR):
                            try:
                                dns_query = packet[DNSQR].qname.decode('utf-8', 'ignore') #extracting DNS query name
                            except:
                                dns_query = "Malformed DNS Query"
                elif ICMP in packet:  
                    protocol = "ICMP"
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code

            # Apply protocol filter
            if self.current_protocol_filter != "All" and self.current_protocol_filter != protocol:
                return

            # Increment protocol counter
            self.packet_counter[protocol] += 1

            # Build result string for displaying according to filter selected
            result = f"\n=> Packet Captured:\n"
            if self.display_options["IP"] and ip_src:      
                result += f"    Source IP: {ip_src}\n    Destination IP: {ip_dst}\n"
            if self.display_options["Protocol"]:
                result += f"    Protocol: {protocol}\n"
            if self.display_options["Ports"] and sport:
                result += f"    Source Port: {sport}\n    Destination Port: {dport}\n"
            if protocol == "ICMP" and icmp_type != "": 
                result += f"    ICMP Type: {icmp_type} (Code: {icmp_code})\n"
                # Common ICMP types
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    5: "Redirect",
                    8: "Echo Request (Ping)",
                    11: "Time Exceeded"
                }
                if icmp_type in icmp_types:
                    result += f"    ICMP Message: {icmp_types[icmp_type]}\n"
            if self.display_options["Size"]:
                result += f"    Packet Size: {size} bytes\n"
            if protocol == "DNS" and dns_query:
                result += f"    DNS Query: {dns_query}\n"

            # Save packet to storage
            self.captured_packets.append(result)

            # Apply search term if specified
            if self.search_term and self.search_term.lower() not in result.lower():
                return

            # Add to queue for GUI update
            self.packet_queue.put(result)

        except Exception as e:
            error_msg = f"[!] Error processing packet: {str(e)}\n"
            self.packet_queue.put(error_msg)
    
    # Function to update GUI from queue
    def update_gui(self):
        while not self.packet_queue.empty():
            message = self.packet_queue.get()
            self.output_text.configure(state='normal')
            self.output_text.insert(tk.END, message)
            self.output_text.configure(state='disabled')
            self.output_text.see(tk.END)
        self.update_summary()
        self.root.after(100, self.update_gui)
    
    def update_output(self, message):
        """Add messages to the output text area"""
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, message)
        self.output_text.configure(state='disabled')
        self.output_text.see(tk.END)
    
    # Search function
    def search_stored_packets(self):
        search_term = self.search_entry.get()
        self.output_text.tag_remove('highlight', '1.0', tk.END)

        if not search_term:
            return

        start_pos = '1.0'
        found_any = False

        while True:
            start_pos = self.output_text.search(search_term, start_pos, stopindex=tk.END, nocase=True)
            if not start_pos:
                break
            found_any = True
            end_pos = f"{start_pos}+{len(search_term)}c"
            self.output_text.tag_add('highlight', start_pos, end_pos)
            start_pos = end_pos

        if found_any:
            self.output_text.tag_config('highlight', background='yellow', foreground='black')
        else:
            self.packet_queue.put(f"No results found for '{search_term}'\n")
    
    # Update summary
    def update_summary(self):
        self.summary_text.set(f"TCP: {self.packet_counter['TCP']} | UDP: {self.packet_counter['UDP']} | DNS: {self.packet_counter['DNS']} | ICMP: {self.packet_counter['ICMP']} | Other: {self.packet_counter['Other']}")
    
    # Sniffer control functions
    def start_sniffer(self):
        if self.sniffing_active:
            return
            
        self.sniffing_active = True
        self.pause_flag.clear() #Clears any pause flags
        
        sniff_thread = threading.Thread(target=self.start_sniffing_thread, daemon=True)
        #Creates and starts a separate thread for packet capture to prevent UI freezing and daemon is  
        # set to true hence it will run independently and indefinitely detached from UI like web servers 

        sniff_thread.start()
        self.update_output("[*] Sniffer started...\n")
    
    def start_sniffing_thread(self):
        try: 
            sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.sniffing_active)
            '''
            Scapy's func sniff(iface, prn, store, stop)
            iface: The network interface to capture from =self.interface
            prn: Callback function (process_packet) that handles each captured packet
            store=False: Prevents storing packets in memory (better for long captures)
            stop_filter: Lambda function that stops capturing when sniffing_active is False
            '''

        except Exception as e:
            self.packet_queue.put(f"[!] Sniffing error: {str(e)}\n")
    
    def stop_sniffer(self):
        self.sniffing_active = False
        self.update_output("[*] Sniffer stopped\n")
    
    def pause_sniffer(self):
        self.pause_flag.set()
        self.update_output("[*] Sniffer paused\n")
    
    def resume_sniffer(self):
        self.pause_flag.clear()
        self.update_output("[*] Sniffer resumed\n")
    
    def clear_output(self):
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')
        self.packet_counter.clear()
        self.captured_packets.clear()
        self.update_summary()
    
    # Filter and display functions
    def apply_filter(self):
        self.current_protocol_filter = self.protocol_filter.get()
        self.update_output(f"[*] Filter set to: {self.current_protocol_filter}\n")
    
    def toggle_display(self, option):
        self.display_options[option] = not self.display_options[option]
        self.update_output(f"[*] Display option '{option}' set to {self.display_options[option]}\n")
    
    # Plotting a Bar Graph showing number of packets captured in each protocol 
    def show_visualization(self):
        if sum(self.packet_counter.values()) == 0:
            self.update_output("[!] No packets captured yet\n")
            return

        protocols = []
        counts = []
        for proto, count in self.packet_counter.items():
            if count > 0:
                protocols.append(proto)
                counts.append(count)

        if not protocols:
            self.update_output("[!] No packet data to visualize\n")
            return

        plt.figure(figsize=(8, 5))
        # Different colours for each protocol graph 
        colors = ['blue', 'green', 'red', 'orange', 'purple']
        plt.bar(protocols, counts, color=colors[:len(protocols)])
        plt.title("Packet Capture Summary")
        plt.xlabel("Protocol")
        plt.ylabel("Packet Count")
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.show()

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
