import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3
import threading
import time
from datetime import datetime
import json
import os

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not installed. Install with: pip install scapy")

class NetworkSecurityAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Traffic Analyzer - CSC662")
        self.root.geometry("1400x900")
        self.root.configure(bg='#f0f8ff')
        
        # Initialize variables
        self.packets = []
        self.filtered_packets = []
        self.db_connection = None
        self.analysis_results = {}
        self.current_file = None
        
        # Create database
        self.init_database()
        
        # Create GUI
        self.create_gui()
        
    def init_database(self):
        """Initialize SQLite database for packet storage"""
        try:
            self.db_connection = sqlite3.connect('network_analysis.db')
            cursor = self.db_connection.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    ip_version TEXT,
                    network_type TEXT,
                    packet_size INTEGER,
                    threat_level TEXT,
                    threat_type TEXT,
                    raw_data TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT,
                    file_path TEXT,
                    analysis_date TEXT,
                    packet_count INTEGER,
                    threats_detected INTEGER
                )
            ''')
            
            self.db_connection.commit()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")
    
    def create_gui(self):
        """Create the main GUI interface"""
        # Main title
        title_frame = tk.Frame(self.root, bg='#f0f8ff')
        title_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(title_frame, 
                              text="Network Security Traffic Analyzer", 
                              font=('Arial', 24, 'bold'), 
                              bg='#f0f8ff', 
                              fg='#2c3e50')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, 
                                 text="CSC662 - Computer Security Project", 
                                 font=('Arial', 12), 
                                 bg='#f0f8ff', 
                                 fg='#7f8c8d')
        subtitle_label.pack()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Create tabs
        self.create_capture_tab()
        self.create_filter_tab()
        self.create_analysis_tab()
        self.create_results_tab()
        
        # Status bar
        self.create_status_bar()
        
    def create_capture_tab(self):
        """Create packet capture and file loading tab"""
        capture_frame = ttk.Frame(self.notebook)
        self.notebook.add(capture_frame, text="📁 Capture Traffic")
        
        # File operations frame
        file_frame = tk.LabelFrame(capture_frame, text="File Operations", 
                                  font=('Arial', 12, 'bold'), 
                                  bg='white', fg='#2c3e50', padx=10, pady=10)
        file_frame.pack(fill='x', padx=20, pady=10)
        
        # Load file button
        load_btn = tk.Button(file_frame, 
                           text="📂 Load PCAPNG File", 
                           command=self.load_pcap_file,
                           font=('Arial', 12, 'bold'),
                           bg='#3498db', fg='white',
                           relief='flat', padx=20, pady=10)
        load_btn.pack(side='left', padx=10)
        
        # File info label
        self.file_info_label = tk.Label(file_frame, 
                                       text="No file loaded", 
                                       font=('Arial', 10),
                                       bg='white', fg='#7f8c8d')
        self.file_info_label.pack(side='left', padx=20)
        
        # Packet decode frame
        decode_frame = tk.LabelFrame(capture_frame, text="Packet Decode Information", 
                                    font=('Arial', 12, 'bold'), 
                                    bg='white', fg='#2c3e50', padx=10, pady=10)
        decode_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Create treeview for packet list
        columns = ('ID', 'Time', 'Source IP', 'Destination IP', 'Protocol', 'Port', 'Length', 'Flags', 'Threat Level')
        self.packet_tree = ttk.Treeview(decode_frame, columns=columns, show='headings', height=15)
        
        # Configure columns with appropriate widths
        column_config = {
            'ID': 50,
            'Time': 100,
            'Source IP': 130,
            'Destination IP': 130,
            'Protocol': 80,
            'Port': 80,
            'Length': 70,
            'Flags': 80,
            'Threat Level': 100
        }
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_config[col], anchor='center')
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(decode_frame, orient='vertical', command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(decode_frame, orient='horizontal', command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        decode_frame.grid_rowconfigure(0, weight=1)
        decode_frame.grid_columnconfigure(0, weight=1)
        
    def create_filter_tab(self):
        """Create traffic filtering tab"""
        filter_frame = ttk.Frame(self.notebook)
        self.notebook.add(filter_frame, text="🔍 Filter Traffic")
        
        # Filter controls frame
        controls_frame = tk.LabelFrame(filter_frame, text="Filter Parameters", 
                                      font=('Arial', 12, 'bold'), 
                                      bg='white', fg='#2c3e50', padx=10, pady=10)
        controls_frame.pack(fill='x', padx=20, pady=10)
        
        # IP Version filter
        ip_frame = tk.Frame(controls_frame, bg='white')
        ip_frame.pack(fill='x', pady=5)
        
        tk.Label(ip_frame, text="IP Version:", font=('Arial', 10, 'bold'), 
                bg='white', fg='#2c3e50').pack(side='left')
        
        self.ip_version_var = tk.StringVar(value="All")
        ip_combo = ttk.Combobox(ip_frame, textvariable=self.ip_version_var, 
                               values=["All", "IPv4", "IPv6"], state="readonly", width=15)
        ip_combo.pack(side='left', padx=10)
        
        # Network type filter
        network_frame = tk.Frame(controls_frame, bg='white')
        network_frame.pack(fill='x', pady=5)
        
        tk.Label(network_frame, text="Network Type:", font=('Arial', 10, 'bold'), 
                bg='white', fg='#2c3e50').pack(side='left')
        
        self.network_type_var = tk.StringVar(value="All")
        network_combo = ttk.Combobox(network_frame, textvariable=self.network_type_var, 
                                    values=["All", "Wired", "Wireless"], state="readonly", width=15)
        network_combo.pack(side='left', padx=10)
        
        # Protocol filter
        protocol_frame = tk.Frame(controls_frame, bg='white')
        protocol_frame.pack(fill='x', pady=5)
        
        tk.Label(protocol_frame, text="Protocol:", font=('Arial', 10, 'bold'), 
                bg='white', fg='#2c3e50').pack(side='left')
        
        self.protocol_var = tk.StringVar(value="All")
        protocol_combo = ttk.Combobox(protocol_frame, textvariable=self.protocol_var, 
                                     values=["All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS"], 
                                     state="readonly", width=15)
        protocol_combo.pack(side='left', padx=10)
        
        # Apply filter button
        filter_btn = tk.Button(controls_frame, 
                             text="🔍 Apply Filters", 
                             command=self.apply_filters,
                             font=('Arial', 11, 'bold'),
                             bg='#27ae60', fg='white',
                             relief='flat', padx=20, pady=8)
        filter_btn.pack(pady=10)
        
        # Filtered results frame
        results_frame = tk.LabelFrame(filter_frame, text="Filtered Results", 
                                     font=('Arial', 12, 'bold'), 
                                     bg='white', fg='#2c3e50', padx=10, pady=10)
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Results text widget
        self.filter_results_text = tk.Text(results_frame, height=15, 
                                          font=('Courier', 9), 
                                          bg='#f8f9fa', fg='#2c3e50')
        results_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', 
                                         command=self.filter_results_text.yview)
        self.filter_results_text.configure(yscrollcommand=results_scrollbar.set)
        
        self.filter_results_text.pack(side='left', fill='both', expand=True)
        results_scrollbar.pack(side='right', fill='y')
        
    def create_analysis_tab(self):
        """Create security analysis tab"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="🛡️ Security Analysis")
        
        # Analysis controls
        controls_frame = tk.LabelFrame(analysis_frame, text="Security Analysis Controls", 
                                      font=('Arial', 12, 'bold'), 
                                      bg='white', fg='#2c3e50', padx=10, pady=10)
        controls_frame.pack(fill='x', padx=20, pady=10)
        
        # Analysis buttons
        btn_frame = tk.Frame(controls_frame, bg='white')
        btn_frame.pack(fill='x', pady=10)
        
        analyze_btn = tk.Button(btn_frame, 
                               text="🔍 Analyze Threats", 
                               command=self.analyze_security_threats,
                               font=('Arial', 11, 'bold'),
                               bg='#e74c3c', fg='white',
                               relief='flat', padx=20, pady=8)
        analyze_btn.pack(side='left', padx=5)
        
        dos_btn = tk.Button(btn_frame, 
                           text="⚠️ Detect DoS", 
                           command=self.detect_dos_attacks,
                           font=('Arial', 11, 'bold'),
                           bg='#f39c12', fg='white',
                           relief='flat', padx=20, pady=8)
        dos_btn.pack(side='left', padx=5)
        
        intrusion_btn = tk.Button(btn_frame, 
                                 text="🚨 Detect Intrusions", 
                                 command=self.detect_intrusions,
                                 font=('Arial', 11, 'bold'),
                                 bg='#9b59b6', fg='white',
                                 relief='flat', padx=20, pady=8)
        intrusion_btn.pack(side='left', padx=5)
        
        # Threat summary frame
        summary_frame = tk.LabelFrame(analysis_frame, text="Threat Summary", 
                                     font=('Arial', 12, 'bold'), 
                                     bg='white', fg='#2c3e50', padx=10, pady=10)
        summary_frame.pack(fill='x', padx=20, pady=10)
        
        # Threat counters
        self.threat_vars = {
            'dos_attacks': tk.StringVar(value="0"),
            'intrusions': tk.StringVar(value="0"),
            'suspicious_traffic': tk.StringVar(value="0"),
            'malformed_packets': tk.StringVar(value="0")
        }
        
        counter_frame = tk.Frame(summary_frame, bg='white')
        counter_frame.pack(fill='x', pady=10)
        
        threats = [
            ("DoS Attacks", self.threat_vars['dos_attacks'], '#e74c3c'),
            ("Intrusions", self.threat_vars['intrusions'], '#9b59b6'),
            ("Suspicious Traffic", self.threat_vars['suspicious_traffic'], '#f39c12'),
            ("Malformed Packets", self.threat_vars['malformed_packets'], '#34495e')
        ]
        
        for i, (label, var, color) in enumerate(threats):
            threat_frame = tk.Frame(counter_frame, bg=color, relief='raised', bd=2)
            threat_frame.pack(side='left', fill='both', expand=True, padx=5)
            
            tk.Label(threat_frame, text=label, font=('Arial', 10, 'bold'), 
                    bg=color, fg='white').pack(pady=5)
            tk.Label(threat_frame, textvariable=var, font=('Arial', 16, 'bold'), 
                    bg=color, fg='white').pack(pady=5)
        
        # Analysis results
        results_frame = tk.LabelFrame(analysis_frame, text="Analysis Results", 
                                     font=('Arial', 12, 'bold'), 
                                     bg='white', fg='#2c3e50', padx=10, pady=10)
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.analysis_text = tk.Text(results_frame, height=12, 
                                    font=('Courier', 9), 
                                    bg='#f8f9fa', fg='#2c3e50')
        analysis_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', 
                                          command=self.analysis_text.yview)
        self.analysis_text.configure(yscrollcommand=analysis_scrollbar.set)
        
        self.analysis_text.pack(side='left', fill='both', expand=True)
        analysis_scrollbar.pack(side='right', fill='y')
        
    def create_results_tab(self):
        """Create results and visualization tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Results & Analysis")
        
        # Chart controls
        chart_controls = tk.LabelFrame(results_frame, text="Visualization Controls", 
                                      font=('Arial', 12, 'bold'), 
                                      bg='white', fg='#2c3e50', padx=10, pady=10)
        chart_controls.pack(fill='x', padx=20, pady=10)
        
        btn_frame = tk.Frame(chart_controls, bg='white')
        btn_frame.pack(fill='x', pady=10)
        
        protocol_chart_btn = tk.Button(btn_frame, 
                                      text="📈 Protocol Distribution", 
                                      command=self.show_protocol_chart,
                                      font=('Arial', 10, 'bold'),
                                      bg='#3498db', fg='white',
                                      relief='flat', padx=15, pady=6)
        protocol_chart_btn.pack(side='left', padx=5)

        # Add IP Distribution button
        ip_dist_btn = tk.Button(btn_frame, 
                                text="🥧 IP Distribution", 
                                command=self.show_ip_distribution_chart,
                                font=('Arial', 10, 'bold'),
                                bg='#8e44ad', fg='white',
                                relief='flat', padx=15, pady=6)
        ip_dist_btn.pack(side='left', padx=5)
        
        traffic_chart_btn = tk.Button(btn_frame, 
                                     text="📊 Traffic Timeline", 
                                     command=self.show_traffic_timeline,
                                     font=('Arial', 10, 'bold'),
                                     bg='#27ae60', fg='white',
                                     relief='flat', padx=15, pady=6)
        traffic_chart_btn.pack(side='left', padx=5)
        
        threat_chart_btn = tk.Button(btn_frame, 
                                    text="🚨 Threat Analysis", 
                                    command=self.show_threat_chart,
                                    font=('Arial', 10, 'bold'),
                                    bg='#e74c3c', fg='white',
                                    relief='flat', padx=15, pady=6)
        threat_chart_btn.pack(side='left', padx=5)
        
        # Matplotlib canvas
        self.fig, self.ax = plt.subplots(figsize=(12, 6))
        self.fig.patch.set_facecolor('#f0f8ff')
        self.canvas = FigureCanvasTkAgg(self.fig, results_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True, padx=20, pady=10)
        
        # Export options
        export_frame = tk.LabelFrame(results_frame, text="Export Options", 
                                    font=('Arial', 12, 'bold'), 
                                    bg='white', fg='#2c3e50', padx=10, pady=10)
        export_frame.pack(fill='x', padx=20, pady=10)
        
        export_btn_frame = tk.Frame(export_frame, bg='white')
        export_btn_frame.pack(fill='x', pady=10)
        
        export_json_btn = tk.Button(export_btn_frame, 
                                   text="💾 Export JSON", 
                                   command=self.export_json,
                                   font=('Arial', 10, 'bold'),
                                   bg='#34495e', fg='white',
                                   relief='flat', padx=15, pady=6)
        export_json_btn.pack(side='left', padx=5)
        
        export_csv_btn = tk.Button(export_btn_frame, 
                                  text="📄 Export CSV", 
                                  command=self.export_csv,
                                  font=('Arial', 10, 'bold'),
                                  bg='#16a085', fg='white',
                                  relief='flat', padx=15, pady=6)
        export_csv_btn.pack(side='left', padx=5)
        
    def create_status_bar(self):
        """Create status bar"""
        self.status_frame = tk.Frame(self.root, bg='#ecf0f1', relief='sunken', bd=1)
        self.status_frame.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(self.status_frame, 
                                    text="Ready - Load a PCAPNG file to begin analysis", 
                                    bg='#ecf0f1', fg='#2c3e50', 
                                    font=('Arial', 10))
        self.status_label.pack(side='left', padx=10, pady=5)
        
        self.packet_count_label = tk.Label(self.status_frame, 
                                          text="Packets: 0", 
                                          bg='#ecf0f1', fg='#2c3e50', 
                                          font=('Arial', 10))
        self.packet_count_label.pack(side='right', padx=10, pady=5)
        
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
        self.root.update()
        
    def load_pcap_file(self):
        """Load and parse PCAPNG file"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy library is required. Install with: pip install scapy")
            return
            
        file_path = filedialog.askopenfilename(
            title="Select PCAPNG File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        
        if file_path:
            self.current_file = file_path
            self.update_status("Loading packets...")
            
            # Load in separate thread to prevent GUI freezing
            thread = threading.Thread(target=self._load_packets_thread, args=(file_path,))
            thread.daemon = True
            thread.start()
            
    def _load_packets_thread(self, file_path):
        """Load packets in separate thread"""
        try:
            self.packets = rdpcap(file_path)
            self.root.after(0, self._packets_loaded)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load file: {str(e)}"))
            
    def _packets_loaded(self):
        """Called after packets are loaded"""
        self.file_info_label.config(text=f"Loaded: {os.path.basename(self.current_file)} ({len(self.packets)} packets)")
        self.packet_count_label.config(text=f"Packets: {len(self.packets)}")
        self.update_status(f"Successfully loaded {len(self.packets)} packets")
        
        # Populate packet tree
        self.populate_packet_tree()
        
        # Store in database
        self.store_packets_in_db()
        

    def _get_tcp_flags(self, flags):
        """Convert TCP flags to readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return ",".join(flag_names) if flag_names else "-"

    def _is_threat_packet(self, packet):
        """Enhanced threat detection for packet coloring"""
        try:
            if IP in packet:
                # Check for suspicious ports
                if TCP in packet:
                    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 5900, 4444, 6667]
                    if packet[TCP].dport in suspicious_ports or packet[TCP].sport in suspicious_ports:
                        return True
                    # Check for port scanning (SYN without ACK)
                    if packet[TCP].flags == 2:  # SYN only
                        return True
                elif UDP in packet:
                    # Check for DNS amplification
                    if packet[UDP].dport == 53 and len(packet) > 512:
                        return True
                
                # Check for large packets (potential DoS)
                if len(packet) > 1500:
                    return True
                
                # Check for private IP communication (potential lateral movement)
                private_ranges = ['10.', '172.16.', '192.168.']
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
            return False
        except:
            return True  # Treat malformed packets as threats

    def populate_packet_tree(self):
        """Populate the packet treeview"""
        # Clear existing items
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # Configure tags for coloring
        self.packet_tree.tag_configure('threat_high', background='#ffcccc', foreground='#cc0000')    # Red
        self.packet_tree.tag_configure('threat_medium', background='#fff7cc', foreground='#b8860b')  # Yellow
        self.packet_tree.tag_configure('threat_low', background='#ccffcc', foreground='#006600')      # Green

        for i, packet in enumerate(self.packets[:100000]):
            try:
                timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3]

                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    ip_version = "IPv4"

                    if TCP in packet:
                        proto_name = "TCP"
                        port_info = f"{packet[TCP].sport}→{packet[TCP].dport}"
                        flags = self._get_tcp_flags(packet[TCP].flags)
                    elif UDP in packet:
                        proto_name = "UDP"
                        port_info = f"{packet[UDP].sport}→{packet[UDP].dport}"
                        flags = "-"
                    elif ICMP in packet:
                        proto_name = "ICMP"
                        port_info = f"Type {packet[ICMP].type}"
                        flags = "-"
                    else:
                        proto_name = f"Proto {packet[IP].proto}"
                        port_info = "-"
                        flags = "-"

                elif IPv6 in packet:
                    src_ip = packet[IPv6].src[:20] + "..."
                    dst_ip = packet[IPv6].dst[:20] + "..."
                    proto_name = "IPv6"
                    port_info = "-"
                    flags = "-"
                else:
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    proto_name = "Unknown"
                    port_info = "-"
                    flags = "-"

                length = len(packet)
                threat_level = "HIGH" if self._is_threat_packet(packet) else "LOW"
                tag = 'threat_high' if threat_level == "HIGH" else 'threat_low'

                item = self.packet_tree.insert(
                    '', 'end',
                    values=(i+1, timestamp, src_ip, dst_ip, proto_name, port_info, length, flags, threat_level),
                    tags=(tag,)
                )

            except Exception as e:
                continue  # Skip problematic packets
                
    def store_packets_in_db(self):
        """Store packets in database for analysis"""
        if not self.db_connection:
            return
            
        cursor = self.db_connection.cursor()
        
        # Clear existing packets
        cursor.execute("DELETE FROM packets")
        
        for i, packet in enumerate(self.packets):
            try:
                timestamp = datetime.fromtimestamp(float(packet.time)).isoformat()
                
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    ip_version = "IPv4"
                    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
                elif IPv6 in packet:
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst
                    ip_version = "IPv6"
                    protocol = "IPv6"
                else:
                    src_ip = "Unknown"
                    dst_ip = "Unknown"
                    ip_version = "Unknown"
                    protocol = "Unknown"
                    
                # Simple heuristic for network type (this would need more sophisticated detection)
                network_type = "Wired"  # Default assumption
                
                packet_size = len(packet)
                threat_level = "Low"  # Will be updated by analysis
                threat_type = "None"
                
                cursor.execute('''
                    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, ip_version, 
                                       network_type, packet_size, threat_level, threat_type, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, src_ip, dst_ip, protocol, ip_version, network_type, 
                     packet_size, threat_level, threat_type, str(packet)))
                     
            except Exception as e:
                continue
                
        self.db_connection.commit()
        
    def apply_filters(self):
        """Apply selected filters to packets"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        ip_filter = self.ip_version_var.get()
        network_filter = self.network_type_var.get()
        protocol_filter = self.protocol_var.get()
        
        self.filtered_packets = []
        results_text = f"Filter Applied:\nIP Version: {ip_filter}\nNetwork Type: {network_filter}\nProtocol: {protocol_filter}\n\n"
        results_text += "Filtered Packets:\n" + "="*50 + "\n"
        
        for i, packet in enumerate(self.packets):
            include_packet = True
            
            # IP Version filter
            if ip_filter != "All":
                if ip_filter == "IPv4" and IP not in packet:
                    include_packet = False
                elif ip_filter == "IPv6" and IPv6 not in packet:
                    include_packet = False
                    
            # Protocol filter
            if include_packet and protocol_filter != "All":
                if protocol_filter == "TCP" and TCP not in packet:
                    include_packet = False
                elif protocol_filter == "UDP" and UDP not in packet:
                    include_packet = False
                elif protocol_filter == "ICMP" and ICMP not in packet:
                    include_packet = False
                    
            if include_packet:
                self.filtered_packets.append(packet)
                
                # Add packet info to results
                try:
                    timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S')
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
                    elif IPv6 in packet:
                        src_ip = packet[IPv6].src[:20] + "..."  # Truncate IPv6
                        dst_ip = packet[IPv6].dst[:20] + "..."
                        proto = "IPv6"
                    else:
                        src_ip = "Unknown"
                        dst_ip = "Unknown"
                        proto = "Unknown"
                        
                    results_text += f"{i+1:4d} | {timestamp} | {src_ip:15s} → {dst_ip:15s} | {proto:6s} | {len(packet):4d} bytes\n"
                except:
                    results_text += f"{i+1:4d} | Error parsing packet\n"
                    
        results_text += f"\nTotal filtered packets: {len(self.filtered_packets)}"
        
        self.filter_results_text.delete(1.0, tk.END)
        self.filter_results_text.insert(1.0, results_text)
        
        self.update_status(f"Filter applied: {len(self.filtered_packets)} packets match criteria")
        
    def analyze_security_threats(self):
        """Analyze packets for security threats"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        self.update_status("Analyzing security threats...")
        
        # Reset threat counters
        dos_count = 0
        intrusion_count = 0
        suspicious_count = 0
        malformed_count = 0
        
        analysis_results = "SECURITY THREAT ANALYSIS\n" + "="*50 + "\n\n"
        
        # Analyze each packet
        src_ip_counts = {}
        dst_port_counts = {}
        
        for i, packet in enumerate(self.packets):
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Count packets per source IP (potential DoS detection)
                    src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
                    
                    # Check for suspicious ports
                    if TCP in packet:
                        dst_port = packet[TCP].dport
                        dst_port_counts[dst_port] = dst_port_counts.get(dst_port, 0) + 1
                        
                        # Check for suspicious ports (common attack vectors)
                        suspicious_ports = [23, 135, 139, 445, 1433, 3389, 5900]
                        if dst_port in suspicious_ports:
                            suspicious_count += 1
                            analysis_results += f"SUSPICIOUS: Connection to port {dst_port} from {src_ip} to {dst_ip}\n"
                            
                        # Check for potential port scanning
                        if packet[TCP].flags == 2:  # SYN flag
                            analysis_results += f"Port scan detected: SYN to {dst_ip}:{dst_port} from {src_ip}\n"
                            intrusion_count += 1
                            
                    elif UDP in packet:
                        dst_port = packet[UDP].dport
                        # Check for DNS amplification attacks
                        if dst_port == 53 and len(packet) > 512:
                            suspicious_count += 1
                            analysis_results += f"SUSPICIOUS: Large DNS query from {src_ip}\n"
                            
                # Check packet size anomalies
                if len(packet) > 1500:  # Jumbo frame or fragmented
                    malformed_count += 1
                elif len(packet) < 64:  # Too small
                    malformed_count += 1
                    
            except Exception as e:
                malformed_count += 1
                analysis_results += f"MALFORMED: Packet {i+1} parsing error\n"
                
        # Detect DoS attacks based on IP frequency
        for src_ip, count in src_ip_counts.items():
            if count > 100:  # Threshold for potential DoS
                dos_count += 1
                analysis_results += f"POTENTIAL DoS: {src_ip} sent {count} packets\n"
                
        # Update threat counters
        self.threat_vars['dos_attacks'].set(str(dos_count))
        self.threat_vars['intrusions'].set(str(intrusion_count))
        self.threat_vars['suspicious_traffic'].set(str(suspicious_count))
        self.threat_vars['malformed_packets'].set(str(malformed_count))
        
        # Generate recommendations
        analysis_results += "\n" + "="*50 + "\n"
        analysis_results += "SECURITY RECOMMENDATIONS:\n\n"
        
        if dos_count > 0:
            analysis_results += "• Implement rate limiting to prevent DoS attacks\n"
            analysis_results += "• Consider using DDoS protection services\n"
            
        if intrusion_count > 0:
            analysis_results += "• Block suspicious source IPs\n"
            analysis_results += "• Implement intrusion detection systems\n"
            
        if suspicious_count > 0:
            analysis_results += "• Monitor traffic to suspicious ports\n"
            analysis_results += "• Implement application-layer filtering\n"
            
        if malformed_count > 0:
            analysis_results += "• Check network equipment for errors\n"
            analysis_results += "• Implement packet validation\n"
            
        analysis_results += f"\nAnalysis completed on {len(self.packets)} packets"
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, analysis_results)
        
        self.update_status("Security analysis completed")
        
    def detect_dos_attacks(self):
        """Specific DoS attack detection"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        self.update_status("Detecting DoS attacks...")
        
        dos_results = "DoS ATTACK DETECTION\n" + "="*40 + "\n\n"
        
        # Track connection attempts per IP
        syn_counts = {}
        packet_rates = {}
        
        for packet in self.packets:
            try:
                if IP in packet and TCP in packet:
                    src_ip = packet[IP].src
                    
                    # Count SYN packets (potential SYN flood)
                    if packet[TCP].flags == 2:  # SYN flag
                        syn_counts[src_ip] = syn_counts.get(src_ip, 0) + 1
                        
                    # Track packet rate
                    packet_rates[src_ip] = packet_rates.get(src_ip, 0) + 1
                    
            except:
                continue
                
        # Analyze results
        dos_detected = False
        
        for src_ip, syn_count in syn_counts.items():
            if syn_count > 50:  # Threshold for SYN flood
                dos_results += f"SYN FLOOD DETECTED: {src_ip} sent {syn_count} SYN packets\n"
                dos_results += f"  Recommendation: Block IP {src_ip} immediately\n\n"
                dos_detected = True
                
        for src_ip, packet_count in packet_rates.items():
            if packet_count > 200:  # High packet rate threshold
                dos_results += f"HIGH TRAFFIC RATE: {src_ip} sent {packet_count} packets\n"
                dos_results += f"  Recommendation: Implement rate limiting for {src_ip}\n\n"
                dos_detected = True
                
        if not dos_detected:
            dos_results += "No DoS attacks detected in current traffic.\n"
            dos_results += "Network appears to be operating normally.\n"
            
        dos_results += "\nDoS PREVENTION MEASURES:\n"
        dos_results += "• Configure SYN flood protection\n"
        dos_results += "• Implement connection rate limiting\n"
        dos_results += "• Use load balancers with DoS protection\n"
        dos_results += "• Monitor bandwidth utilization\n"
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, dos_results)
        
        self.update_status("DoS detection completed")
        
    def detect_intrusions(self):
        """Detect intrusion attempts"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        self.update_status("Detecting intrusions...")
        
        intrusion_results = "INTRUSION DETECTION ANALYSIS\n" + "="*40 + "\n\n"
        
        # Track various intrusion indicators
        port_scans = {}
        failed_connections = {}
        privilege_escalation = 0
        
        for packet in self.packets:
            try:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    if TCP in packet:
                        dst_port = packet[TCP].dport
                        flags = packet[TCP].flags
                        
                        # Detect port scanning (multiple ports from same IP)
                        if src_ip not in port_scans:
                            port_scans[src_ip] = set()
                        port_scans[src_ip].add(dst_port)
                        
                        # Detect failed connections (RST packets)
                        if flags & 0x04:  # RST flag
                            failed_connections[src_ip] = failed_connections.get(src_ip, 0) + 1
                            
                        # Check for privilege escalation attempts
                        if dst_port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
                            privilege_escalation += 1
                            
            except:
                continue
                
        # Analyze port scanning
        intrusion_detected = False
        
        for src_ip, ports in port_scans.items():
            if len(ports) > 10:  # Scanning many ports
                intrusion_results += f"PORT SCAN DETECTED: {src_ip} scanned {len(ports)} ports\n"
                intrusion_results += f"  Ports: {', '.join(map(str, sorted(list(ports))[:10]))}...\n"
                intrusion_results += f"  Recommendation: Block {src_ip} and investigate\n\n"
                intrusion_detected = True
                
        # Analyze failed connections
        for src_ip, failures in failed_connections.items():
            if failures > 20:
                intrusion_results += f"BRUTE FORCE DETECTED: {src_ip} had {failures} failed connections\n"
                intrusion_results += f"  Recommendation: Implement account lockout for {src_ip}\n\n"
                intrusion_detected = True
                
        if privilege_escalation > 50:
            intrusion_results += f"PRIVILEGE ESCALATION: {privilege_escalation} attempts to admin services\n"
            intrusion_results += "  Recommendation: Monitor admin access closely\n\n"
            intrusion_detected = True
            
        if not intrusion_detected:
            intrusion_results += "No clear intrusion attempts detected.\n"
            intrusion_results += "Network security appears adequate.\n"
            
        intrusion_results += "\nINTRUSION PREVENTION MEASURES:\n"
        intrusion_results += "• Implement fail2ban or similar tools\n"
        intrusion_results += "• Use strong authentication mechanisms\n"
        intrusion_results += "• Monitor failed login attempts\n"
        intrusion_results += "• Keep systems updated and patched\n"
        intrusion_results += "• Implement network segmentation\n"
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, intrusion_results)
        
        self.update_status("Intrusion detection completed")
        
    def show_protocol_chart(self):
        """Show protocol distribution as bar chart"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return

        protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

        for packet in self.packets:
            if TCP in packet:
                protocol_counts['TCP'] += 1
            elif UDP in packet:
                protocol_counts['UDP'] += 1
            elif ICMP in packet:
                protocol_counts['ICMP'] += 1
            else:
                protocol_counts['Other'] += 1

        self.ax.clear()
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        self.ax.bar(protocols, counts, color='#2980b9')
        self.ax.set_title('Protocol Distribution', fontsize=16, fontweight='bold')
        self.ax.set_xlabel('Protocol')
        self.ax.set_ylabel('Packet Count')
        self.ax.grid(True, axis='y', alpha=0.3)

        # Add labels
        for i, count in enumerate(counts):
            if count > 0:
                self.ax.text(i, count + 0.5, str(count), ha='center', va='bottom', fontweight='bold')

        self.canvas.draw()
        self.update_status("Protocol distribution chart generated")

    def show_ip_distribution_chart(self):
        """Show IP version distribution as a bar chart"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return

        ip_versions = self._get_ip_version_summary()
        labels = list(ip_versions.keys())
        counts = list(ip_versions.values())

        self.ax.clear()
        bars = self.ax.bar(labels, counts, color='#8e44ad')
        self.ax.set_title('IP Version Distribution', fontsize=16, fontweight='bold')
        self.ax.set_xlabel('IP Version')
        self.ax.set_ylabel('Packet Count')
        self.ax.grid(True, axis='y', alpha=0.3)

        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            self.ax.text(bar.get_x() + bar.get_width()/2, height + 0.5, str(int(height)), 
                         ha='center', va='bottom', fontweight='bold')

        self.canvas.draw()
        self.update_status("IP version distribution chart generated")
        
    def show_traffic_timeline(self):
        """Show traffic timeline chart"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        # Group packets by time intervals
        timestamps = []
        packet_counts = []
        
        try:
            # Get time range
            start_time = float(self.packets[0].time)
            end_time = float(self.packets[-1].time)
            
            # Create 1-second intervals
            interval = 1.0  # 1 second
            current_time = start_time
            
            while current_time < end_time:
                count = 0
                for packet in self.packets:
                    packet_time = float(packet.time)
                    if current_time <= packet_time < current_time + interval:
                        count += 1
                        
                timestamps.append(datetime.fromtimestamp(current_time))
                packet_counts.append(count)
                current_time += interval
                
            # Create line chart
            self.ax.clear()
            self.ax.plot(timestamps, packet_counts, color='#3498db', linewidth=2)
            self.ax.set_title('Traffic Timeline', fontsize=16, fontweight='bold')
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Packets per Second')
            self.ax.grid(True, alpha=0.3)
            
            # Format x-axis
            self.fig.autofmt_xdate()
            
        except Exception as e:
            self.ax.clear()
            self.ax.text(0.5, 0.5, f'Error generating timeline: {str(e)}', 
                        ha='center', va='center', transform=self.ax.transAxes, fontsize=14)
            
        self.canvas.draw()
        self.update_status("Traffic timeline chart generated")
        
    def show_threat_chart(self):
        """Show threat analysis as horizontal bar chart"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return

        threats = ['DoS Attacks', 'Intrusions', 'Suspicious Traffic', 'Malformed Packets']
        counts = [
            int(self.threat_vars['dos_attacks'].get()),
            int(self.threat_vars['intrusions'].get()),
            int(self.threat_vars['suspicious_traffic'].get()),
            int(self.threat_vars['malformed_packets'].get())
        ]

        self.ax.clear()
        y_pos = range(len(threats))
        self.ax.barh(y_pos, counts, color='#e74c3c')
        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(threats)
        self.ax.set_xlabel('Number of Threats')
        self.ax.set_title('Security Threat Analysis', fontsize=16, fontweight='bold')
        self.ax.grid(True, axis='x', alpha=0.3)

        for i, count in enumerate(counts):
            self.ax.text(count + 0.2, i, str(count), va='center', fontweight='bold')

        self.canvas.draw()
        self.update_status("Threat analysis chart generated")


        
    def export_json(self):
        """Export analysis results to JSON"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export JSON Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Prepare data
                export_data = {
                    'analysis_info': {
                        'file_name': os.path.basename(self.current_file) if self.current_file else "Unknown",
                        'total_packets': len(self.packets),
                        'analysis_date': datetime.now().isoformat(),
                        'threats_detected': {
                            'dos_attacks': int(self.threat_vars['dos_attacks'].get()),
                            'intrusions': int(self.threat_vars['intrusions'].get()),
                            'suspicious_traffic': int(self.threat_vars['suspicious_traffic'].get()),
                            'malformed_packets': int(self.threat_vars['malformed_packets'].get())
                        }
                    },
                    'packet_summary': {
                        'protocols': self._get_protocol_summary(),
                        'ip_versions': self._get_ip_version_summary()
                    }
                }
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
                messagebox.showinfo("Success", f"Report exported to {file_path}")
                self.update_status(f"JSON report exported to {os.path.basename(file_path)}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export JSON: {str(e)}")
                
    def export_csv(self):
        """Export packet data to CSV"""
        if not self.packets:
            messagebox.showwarning("Warning", "No packets loaded")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export CSV Data",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                import csv
                
                with open(file_path, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Write header
                    writer.writerow(['Packet_ID', 'Timestamp', 'Source_IP', 'Destination_IP', 
                                   'Protocol', 'IP_Version', 'Packet_Size', 'Flags'])
                    
                    # Write packet data
                    for i, packet in enumerate(self.packets):
                        try:
                            timestamp = datetime.fromtimestamp(float(packet.time)).isoformat()
                            
                            if IP in packet:
                                src_ip = packet[IP].src
                                dst_ip = packet[IP].dst
                                ip_version = "IPv4"
                                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
                                flags = packet[TCP].flags if TCP in packet else ""
                            elif IPv6 in packet:
                                src_ip = packet[IPv6].src
                                dst_ip = packet[IPv6].dst
                                ip_version = "IPv6"
                                protocol = "IPv6"
                                flags = ""
                            else:
                                src_ip = "Unknown"
                                dst_ip = "Unknown"
                                ip_version = "Unknown"
                                protocol = "Unknown"
                                flags = ""
                                
                            writer.writerow([i+1, timestamp, src_ip, dst_ip, protocol, 
                                           ip_version, len(packet), flags])
                                           
                        except Exception as e:
                            continue
                            
                messagebox.showinfo("Success", f"Data exported to {file_path}")
                self.update_status(f"CSV data exported to {os.path.basename(file_path)}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")
                
    def _get_protocol_summary(self):
        """Get protocol distribution summary"""
        protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        
        for packet in self.packets:
            if TCP in packet:
                protocols['TCP'] += 1
            elif UDP in packet:
                protocols['UDP'] += 1
            elif ICMP in packet:
                protocols['ICMP'] += 1
            else:
                protocols['Other'] += 1
                
        return protocols
        
    def _get_ip_version_summary(self):
        """Get IP version distribution summary"""
        versions = {'IPv4': 0, 'IPv6': 0, 'Other': 0}
        
        for packet in self.packets:
            if IP in packet:
                versions['IPv4'] += 1
            elif IPv6 in packet:
                versions['IPv6'] += 1
            else:
                versions['Other'] += 1
                
        return versions
        
    def __del__(self):
        """Cleanup database connection"""
        if self.db_connection:
            self.db_connection.close()

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = NetworkSecurityAnalyzer(root)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()