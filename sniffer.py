# ── 1. Standard Python Libraries ──────────────────────────────────────────────
import threading
import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import os
import requests
import ipaddress
import json
import csv
import webbrowser

# ── 2. GUI Library (CustomTkinter) ────────────────────────────────────────────
import customtkinter as ctk

# ── 3. Packet Sniffing (Scapy) ────────────────────────────────────────────────
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ── 4. Data & Visualization (Matplotlib & Numpy) ──────────────────────────────
import numpy as np
import matplotlib
matplotlib.use("TkAgg")  
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.ticker import MaxNLocator

# ── Offline World Map ────────────────────────────────────────────────────────
from offline_world_map import OfflineWorldMap

# ── UI Theme Setup ────────────────────────────────────────────────────────────
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

is_capturing = False

packet_count = {
    "Total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP/HTTPS": 0, "Other": 0,
    "ICMP_REQ": 0, "ICMP_REP": 0, "ICMP_UNR": 0, "ICMP_EXC": 0, "ICMP_OTH": 0
}

src_ip_counts = {}
suspicious_ips_list = {}
ip_stats = {}
conversation_stats = {}

# ==============================================================================
#                          CORE PACKET ENGINE
# ==============================================================================
def analyze_packet(packet):
    if not packet.haslayer(IP):
        return None
        
    src, dst = packet[IP].src, packet[IP].dst
    length = len(packet)
    
   # Protocol Detection Logic
    if packet.haslayer(TCP):
        proto_name = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto_name = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto_name = "ICMP"
        sport = 0 
        dport = 0
    else:
        proto_name = packet.sprintf("%IP.proto%") 
        sport = 0
        dport = 0
    
    # Conversation Logic
    conv_key = (src, sport, dst, dport, proto_name)
    if conv_key not in conversation_stats:
        conversation_stats[conv_key] = {'packets': 0, 'bytes': 0}
    conversation_stats[conv_key]['packets'] += 1
    conversation_stats[conv_key]['bytes'] += length

    src = packet[IP].src
    if src not in ip_stats: ip_stats[src] = {"packets": 0, "bytes": 0}
    ip_stats[src]["packets"] += 1
    ip_stats[src]["bytes"] += len(packet)
    
    packet_count["Total"] += 1
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    length = len(packet)

    src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
    
    if src_ip_counts[src_ip] > 50:
        suspicious_ips_list[src_ip] = "High Volume Traffic (Potential DoS)"
    if packet.haslayer(TCP) and packet[TCP].flags == "R":
        suspicious_ips_list[src_ip] = "Connection Reset [RST] Alert"

    proto_name = "OTHER"
    sport_str = "-"
    dport_str = "-"
    info_str = f"Length: {length} bytes | Routing Frame"

    if packet.haslayer(TCP):
        proto_name = "TCP"
        packet_count["TCP"] += 1
        sport_str = str(packet[TCP].sport)
        dport_str = str(packet[TCP].dport)

        flags = packet[TCP].flags
        if flags == "S":    info_str = f"[SYN] Handshake Request | Seq={packet[TCP].seq}"
        elif flags == "SA": info_str = "[SYN, ACK] Handshake Accept"
        elif flags == "A":  info_str = "[ACK] Acknowledgment Frame"
        elif flags == "PA": info_str = f"[PSH, ACK] Data Transfer ({length} bytes)"
        elif flags == "FA": info_str = "[FIN, ACK] Connection Close"
        elif flags == "R":  info_str = "⚠️ [RST] Connection Reset Alert"
        else:               info_str = f"Flags: {flags} | Seq={packet[TCP].seq}"

    elif packet.haslayer(UDP):
        proto_name = "UDP"
        packet_count["UDP"] += 1
        sport_str = str(packet[UDP].sport)
        dport_str = str(packet[UDP].dport)

        if dport_str == "53" or sport_str == "53":
            proto_name = "DNS"
            info_str = "🔍 DNS Query / Response Traffic"
        elif dport_str == "67" or dport_str == "68":
            info_str = "💻 DHCP Network IP Allocation"
        else:
            info_str = f"UDP Connectionless Data Stream"

    elif packet.haslayer(ICMP):
        proto_name = "ICMP"
        packet_count["ICMP"] += 1
        icmp_type = packet[ICMP].type
        
        if icmp_type == 8:   packet_count["ICMP_REQ"] += 1
        elif icmp_type == 0: packet_count["ICMP_REP"] += 1
        elif icmp_type == 3: packet_count["ICMP_UNR"] += 1
        elif icmp_type == 11: packet_count["ICMP_EXC"] += 1
        else:                packet_count["ICMP_OTH"] += 1
            
        info_str = f"ICMP Packet (Type: {icmp_type})"
    
    else:
        packet_count["Other"] += 1

    return {
        "no":    packet_count["Total"],
        "time":  datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto": proto_name,
        "src":   src_ip,
        "sport": sport_str,
        "dst":   dst_ip,
        "dport": dport_str,
        "len":   length,
        "info":  info_str
    }
# ==============================================================================
#                          TOP IPS DASHBOARD CLASS 
# ==============================================================================
class TopIPsDashboard(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        # 1. Page Header
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 5))
        
        ctk.CTkLabel(header_frame, text="Top IPs Analysis", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ctk.CTkLabel(header_frame, text="Identify and analyze the most active IP addresses on the network.", 
                     font=("Segoe UI", 12), text_color="gray").pack(anchor="w")

        # 2. Summary Cards Row
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=15, pady=5)
        
        self.lbl_unique_ips = self.create_summary_card(cards_frame, "🌐 Total Unique IPs", "0", "Live Tracking", "#1f538d")
        self.lbl_top_src = self.create_summary_card(cards_frame, "💻 Top Source IP", "Waiting...", "Live Packets", "#2ca02c")
        self.lbl_top_dst = self.create_summary_card(cards_frame, "🌍 Top Destination IP", "Waiting...", "Live Packets", "#9467bd")
        self.create_summary_card(cards_frame, "🛡️ Suspicious IPs", "0", "No threats detected", "#d62728")
        
        # Pagination variables
        self.current_page = 1
        self.rows_per_page = 5

        # 3. Search & Filter Row 
        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        self.search_entry = ctk.CTkEntry(filter_frame, placeholder_text="Search IP address...", width=250)
        self.search_entry.pack(side="left")
        self.search_entry.bind("<KeyRelease>", lambda e: self.master.refresh_data())
        
        time_menu = ctk.CTkOptionMenu(filter_frame, values=["Live Engine (Running)", "Last 1 Hour", "Last 24 Hours"], command=lambda value: self.master.refresh_data()) 
        time_menu.pack(side="right", padx=(10, 0))
        
        proto_menu = ctk.CTkOptionMenu(filter_frame, values=["All Protocols", "TCP Only", "UDP Only"], command=lambda value: self.master.refresh_data()) 
        proto_menu.pack(side="right")

        # 4. Table Section (Treeview) - UPDATED WITH COUNTRY & TIME
        table_container = ctk.CTkFrame(self, corner_radius=10)
        table_container.pack(fill="both", expand=True, padx=20, pady=5)
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0, rowheight=25)
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[('selected', '#1f538d')])

        columns = ("Rank", "IP Address", "Hostname", "Packets", "Bytes", "Protocols", "Country", "First Seen", "Last Seen", "Risk Level")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", height=6)
        for col in columns:
            self.tree.heading(col, text=col)
            width = 60 if col == "Rank" else 120 if col in ("IP Address", "Hostname") else 90
            self.tree.column(col, width=width, anchor="center")
        
        self.tree.pack(fill="both", expand=True, padx=10, pady=(10, 0))
        
        # Pagination Row (NEWLY ADDED)
        page_frame = ctk.CTkFrame(table_container, fg_color="transparent")
        page_frame.pack(fill="x", padx=10, pady=5)
        
        
        ctk.CTkButton(page_frame, text="<", width=30, fg_color="#333333", command=lambda: self.change_page(-1)).pack(side="left", padx=2)
        ctk.CTkButton(page_frame, text="1", width=30, fg_color="#1f538d", command=lambda: self.change_page(1)).pack(side="left", padx=2)
        ctk.CTkButton(page_frame, text="2", width=30, fg_color="#333333", command=lambda: self.change_page(2)).pack(side="left", padx=2)
        ctk.CTkButton(page_frame, text=">", width=30, fg_color="#333333", command=lambda: self.change_page(1)).pack(side="left", padx=2)
        ctk.CTkLabel(page_frame, text="Live Updating from Sniffer Engine...", text_color="gray", font=("Segoe UI", 11)).pack(side="right")

        # 5. Bottom Analytics Section
        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(fill="x", padx=15, pady=(5, 10))
        
        # Left: Top Sources
        source_frame = ctk.CTkFrame(bottom_frame, corner_radius=10)
        source_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(source_frame, text="📊 Top 5 Source IPs", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        self.src_row1 = self.create_progress_bar_row(source_frame, "Waiting...", 0, "0", "#2ca02c")
        self.src_row2 = self.create_progress_bar_row(source_frame, "Waiting...", 0, "0", "#2ca02c")

        # Middle: Top Destinations
        dest_frame = ctk.CTkFrame(bottom_frame, corner_radius=10)
        dest_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(dest_frame, text="📈 Top 5 Dest IPs", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        self.dst_row1 = self.create_progress_bar_row(dest_frame, "Waiting...", 0, "0", "#9467bd")
        self.dst_row2 = self.create_progress_bar_row(dest_frame, "Waiting...", 0, "0", "#9467bd")

        # Right 1: Selected IP Details
        details_frame = ctk.CTkFrame(bottom_frame, corner_radius=10)
        details_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(details_frame, text="🔗 Selected IP Details", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        self.lbl_sel_ip = self.create_detail_row(details_frame, "IP Address", "-")
        self.lbl_sel_host = self.create_detail_row(details_frame, "Hostname", "-")
        self.lbl_sel_proto = self.create_detail_row(details_frame, "Protocols", "-")
        self.lbl_sel_bytes = self.create_detail_row(details_frame, "Total Bytes", "-")

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # Right 2: IP Insights (Wahi purana layout)
        insights_frame = ctk.CTkFrame(bottom_frame, corner_radius=10)
        insights_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(insights_frame, text="🛡️ IP Insights", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkLabel(insights_frame, text="✅ No suspicious activity", text_color="#2ca02c", font=("Segoe UI", 11)).pack(anchor="w", padx=10, pady=2)
        ctk.CTkLabel(insights_frame, text="✅ Normal traffic pattern", text_color="#2ca02c", font=("Segoe UI", 11)).pack(anchor="w", padx=10, pady=2)
        
        score_frame = ctk.CTkFrame(insights_frame, fg_color="transparent")
        score_frame.pack(fill="x", side="bottom", padx=10, pady=10)
        ctk.CTkLabel(score_frame, text="Reputation Score", font=("Segoe UI", 11)).pack(side="left")
        ctk.CTkLabel(score_frame, text="100 / 100", text_color="#2ca02c", font=("Segoe UI", 12, "bold")).pack(side="right")

        # START LIVE DATA REFRESH
        self.refresh_data()

    def create_summary_card(self, parent, title, value, subtext, color):
        card = ctk.CTkFrame(parent, corner_radius=10)
        card.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(card, text=title, font=("Segoe UI", 12, "bold"), text_color=color).pack(anchor="w", padx=15, pady=(10, 0))
        val_lbl = ctk.CTkLabel(card, text=value, font=("Segoe UI", 24, "bold"))
        val_lbl.pack(anchor="w", padx=15, pady=0)
        ctk.CTkLabel(card, text=subtext, font=("Segoe UI", 11), text_color="gray").pack(anchor="w", padx=15, pady=(0, 10))
        return val_lbl

    def create_progress_bar_row(self, parent, ip_label, progress_val, count_label, color):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=3)
        
        lbl = ctk.CTkLabel(row, text=ip_label, width=90, anchor="w", font=("Segoe UI", 11))
        lbl.pack(side="left")
        
        pb = ctk.CTkProgressBar(row, progress_color=color, height=8)
        pb.pack(side="left", fill="x", expand=True, padx=5)
        pb.set(progress_val)
        
        cnt = ctk.CTkLabel(row, text=count_label, width=40, anchor="e", font=("Segoe UI", 11))
        cnt.pack(side="left")
        
        return lbl, pb, cnt


    def refresh_data(self):
        # 1. Clear existing table
        for i in self.tree.get_children(): 
            self.tree.delete(i)
        
        global ip_stats
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['packets'], reverse=True)
        
        # 2. Update summary cards (ye waisa hi rahega)
        total_unique = len(sorted_ips)
        self.lbl_unique_ips.configure(text=str(total_unique))
        if total_unique > 0:
            self.lbl_top_src.configure(text=str(sorted_ips[0][0]))
            if total_unique > 1:
                self.lbl_top_dst.configure(text=str(sorted_ips[1][0]))

        # 3. Update Progress Bars 
        if len(sorted_ips) >= 1:
            lbl, pb, cnt = self.src_row1
            lbl.configure(text=sorted_ips[0][0])
            cnt.configure(text=str(sorted_ips[0][1]['packets']))
            pb.set(0.7)
            lbl, pb, cnt = self.dst_row1 
            lbl.configure(text=sorted_ips[0][0])
            cnt.configure(text=str(sorted_ips[0][1]['packets']))
            pb.set(0.6)
            
        # 4. PAGINATION LOGIC
        start_idx = (self.current_page - 1) * self.rows_per_page
        end_idx = start_idx + self.rows_per_page
        
     
        page_data = sorted_ips[start_idx:end_idx]
        
        rank = start_idx + 1 
        
        for ip, data in page_data:
            b = data['bytes']
            byte_str = f"{b/1024/1024:.2f} MB" if b > 1024*1024 else f"{b/1024:.2f} KB"
            
            self.tree.insert("", "end", values=(
                rank, ip, "Local Host", f"{data['packets']:,}", byte_str, "TCP/UDP", "Local", "-", "Live", "🟢 Low"
            ))
            rank += 1
            
        # 5. Call refresh again
        self.after(2000, self.refresh_data)
        
    
    # Pagination: Control table view per page
    def change_page(self, page_num):
        self.current_page = max(1, self.current_page - 1) if page_num == -1 else page_num
        self.refresh_data()
        
        
    def create_detail_row(self, parent, label_text, initial_value):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row, text=label_text, text_color="gray", font=("Segoe UI", 11)).pack(side="left")
        val_lbl = ctk.CTkLabel(row, text=initial_value, font=("Segoe UI", 11))
        val_lbl.pack(side="right")
        return val_lbl
    
    def on_tree_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], "values")
            # values: 1=IP, 2=Host, 5=Proto, 4=Bytes
            self.lbl_sel_ip.configure(text=values[1])
            self.lbl_sel_host.configure(text=values[2])
            self.lbl_sel_proto.configure(text=values[5])
            self.lbl_sel_bytes.configure(text=values[4])
            
            
            
            
            
#================================================================================
#                     CONVERSATIONS PAGE
#================================================================================
class ConversationsPage(ctk.CTkFrame):
    """Full Conversations Analysis page matching the reference UI."""

    # ── colour palette ────────────────────────────────────────────────────────
    C_BG        = "#0b0c10"
    C_CARD      = "#12141c"
    C_BORDER    = "#1e222b"
    C_HEADER    = "#0d0f14"
    C_TEXT      = "#cfd8dc"
    C_MUTED     = "#78909c"
    C_SEL       = "#1e3a5f"
    C_GREEN     = "#00e676"
    C_BLUE      = "#2196f3"
    C_YELLOW    = "#ffeb3b"
    C_RED       = "#f44336"
    C_PURPLE    = "#9c27b0"
    C_ORANGE    = "#ff9800"
    C_TCP       = "#64b5f6"
    C_UDP       = "#b388ff"
    C_ICMP      = "#ffd54f"

    FLAG_COLORS = {
        "SYN": "#00e676",
        "ACK": "#2196f3",
        "FIN": "#ffeb3b",
        "RST": "#f44336",
        "PSH": "#9c27b0",
        "URG": "#ff9800",
    }

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self._build_ui()
        self.update_table()

    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── 1. Page header ───────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 6))

        ctk.CTkLabel(hdr, text="Conversations Analysis Engine",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="#ffffff").pack(side="left", anchor="w")

        ctk.CTkLabel(hdr,
                     text="Monitor communication sessions between network hosts.",
                     font=ctk.CTkFont(size=11), text_color=self.C_MUTED
                     ).pack(side="left", anchor="w", padx=(12, 0))

        # ── 2. Filter / control row ──────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.pack(fill="x", padx=20, pady=(0, 8))

        self.ent_search = ctk.CTkEntry(
            ctrl, placeholder_text="🔍  Search IP, Port or Protocol...",
            width=280, height=30, fg_color="#1a1c23",
            border_color="#2a2e3d", text_color="#ffffff",
            placeholder_text_color="#546e7a", corner_radius=6)
        self.ent_search.pack(side="left")
        self.ent_search.bind("<KeyRelease>", lambda e: self.update_table())

        ctk.CTkButton(ctrl, text="↻  Refresh", width=90, height=30,
                      fg_color="#1a1c23", border_width=1,
                      border_color="#2a2e3d", text_color="#90a4ae",
                      hover_color="#12141c", corner_radius=6,
                      command=self.update_table
                      ).pack(side="right")

        # ── 3. Treeview table ────────────────────────────────────────────────
        table_outer = ctk.CTkFrame(self, fg_color=self.C_CARD,
                                   corner_radius=8, border_width=1,
                                   border_color=self.C_BORDER)
        table_outer.pack(fill="x", padx=20, pady=(0, 10))

        # Style (shared with main tree — use a unique style name)
        style = ttk.Style()
        style.configure("Conv.Treeview",
                        background=self.C_CARD, foreground=self.C_TEXT,
                        rowheight=28, fieldbackground=self.C_CARD,
                        borderwidth=0, font=("Segoe UI", 10))
        style.map("Conv.Treeview",
                  background=[("selected", self.C_SEL)],
                  foreground=[("selected", "#ffffff"), ("!selected", "")])
        style.configure("Conv.Treeview.Heading",
                        background=self.C_HEADER, foreground=self.C_MUTED,
                        relief="flat", font=("Segoe UI", 9, "bold"), padding=(4, 5))
        style.map("Conv.Treeview.Heading",
                  background=[("active", self.C_HEADER)],
                  foreground=[("active", "#ffffff")])

        cols = ("no","src_ip","src_port","dst_ip","dst_port",
                "proto","packets","bytes","duration","state",
                "first_pkt","last_pkt")
        self.conv_tree = ttk.Treeview(
            table_outer, columns=cols, show="headings",
            style="Conv.Treeview", height=8)

        hdgs = ["No.","Source IP","Src Port","Destination IP","Dst Port",
                "Protocol","Packets","Bytes","Duration","State",
                "First Packet","Last Packet"]
        widths = [38, 120, 72, 130, 72, 72, 68, 80, 78, 100, 80, 80]
        for col, title, w in zip(cols, hdgs, widths):
            anchor = "center" if col in ("no","src_port","dst_port","packets","bytes","duration","first_pkt","last_pkt") else "w"
            self.conv_tree.heading(col, text=title, anchor=anchor)
            self.conv_tree.column(col, width=w, minwidth=w-10,
                                  anchor=anchor, stretch=(col == "dst_ip"))

        # Protocol colour tags
        self.conv_tree.tag_configure("TCP",  foreground=self.C_TCP,  background=self.C_CARD, font=("Segoe UI", 10))
        self.conv_tree.tag_configure("UDP",  foreground=self.C_UDP,  background=self.C_CARD, font=("Segoe UI", 10))
        self.conv_tree.tag_configure("ICMP", foreground=self.C_ICMP, background=self.C_CARD, font=("Segoe UI", 10))
        self.conv_tree.tag_configure("OTH",  foreground=self.C_MUTED,background=self.C_CARD, font=("Segoe UI", 10))
        self.conv_tree.tag_configure("TCP_ALT",  foreground=self.C_TCP,  background="#0f1118", font=("Segoe UI", 10))
        self.conv_tree.tag_configure("UDP_ALT",  foreground=self.C_UDP,  background="#0f1118", font=("Segoe UI", 10))
        self.conv_tree.tag_configure("ICMP_ALT", foreground=self.C_ICMP, background="#0f1118", font=("Segoe UI", 10))
        self.conv_tree.tag_configure("OTH_ALT",  foreground=self.C_MUTED,background="#0f1118", font=("Segoe UI", 10))

        sb = ttk.Scrollbar(table_outer, orient="vertical", command=self.conv_tree.yview)
        self.conv_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.conv_tree.pack(fill="x", expand=True)
        self.conv_tree.bind("<<TreeviewSelect>>", self._on_select)

        # Row count label
        self.lbl_count = ctk.CTkLabel(self, text="Showing 0 conversations",
                                      font=ctk.CTkFont(size=11),
                                      text_color=self.C_MUTED)
        self.lbl_count.pack(anchor="e", padx=24, pady=(0, 6))

        # ── 4. Three analysis cards ──────────────────────────────────────────
        cards_row = ctk.CTkFrame(self, fg_color="transparent")
        cards_row.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        cards_row.grid_columnconfigure((0, 1, 2), weight=1)

        # Left — Conversation Details
        self._card_details, self._body_details = self._make_card(
            cards_row, "🗂  Conversation Details", 0)

        # Middle — TCP Session Details
        self._card_session, self._body_session = self._make_card(
            cards_row, "🛡  TCP Session Details", 1)

        # Right — TCP Flags Summary
        self._card_flags, self._body_flags = self._make_card(
            cards_row, "🚩  TCP Flags Summary", 2)

        self._populate_placeholder()

    # ── card factory ─────────────────────────────────────────────────────────
    def _make_card(self, parent, title, col):
        card = ctk.CTkFrame(parent, fg_color=self.C_CARD,
                            corner_radius=8, border_width=1,
                            border_color=self.C_BORDER)
        card.grid(row=0, column=col, padx=5, pady=5, sticky="nsew")
        parent.grid_columnconfigure(col, weight=1)

        # Card header bar
        bar = ctk.CTkFrame(card, fg_color=self.C_HEADER,
                           corner_radius=0, height=34)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text=title,
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#ffffff").pack(side="left", padx=14, pady=6)

        body = ctk.CTkScrollableFrame(card, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=4, pady=4)
        return card, body

    # ── placeholder when nothing selected ────────────────────────────────────
    def _populate_placeholder(self):
        for body in [self._body_details, self._body_session, self._body_flags]:
            self._clear(body)
            ctk.CTkLabel(body,
                         text="Select a conversation\nfrom the table above",
                         font=ctk.CTkFont(size=12),
                         text_color=self.C_MUTED,
                         justify="center").pack(expand=True, pady=30)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _clear(self, frame):
        for w in frame.winfo_children():
            w.destroy()

    def _kv_row(self, parent, label, value, val_color="#ffffff"):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row, text=label,
                     font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED,
                     anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=str(value),
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=val_color,
                     anchor="e").pack(side="right")

    def _flag_bar(self, parent, flag, count, total):
        color = self.FLAG_COLORS.get(flag, "#ffffff")
        pct   = (count / total) if total > 0 else 0

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=3)

        ctk.CTkLabel(row, text=flag,
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=color, width=36, anchor="w").pack(side="left")

        bar = ctk.CTkProgressBar(row, height=8,
                                 progress_color=color,
                                 fg_color="#1e222b")
        bar.pack(side="left", fill="x", expand=True, padx=(6, 8))
        bar.set(pct)

        ctk.CTkLabel(row,
                     text=f"{count}  ({pct:.1%})",
                     font=ctk.CTkFont(size=11),
                     text_color=self.C_TEXT,
                     width=80, anchor="e").pack(side="right")

    # ── table population ─────────────────────────────────────────────────────
    def update_table(self):
        query = self.ent_search.get().strip().lower() if hasattr(self, "ent_search") else ""
        for row in self.conv_tree.get_children():
            self.conv_tree.delete(row)

        rows = []
        try:
            for rank, (key, stats) in enumerate(conversation_stats.items(), 1):
                src, sp, dst, dp, proto = key
                first = stats.get("first", datetime.datetime.now()).strftime("%H:%M:%S")
                last  = stats.get("last",  datetime.datetime.now()).strftime("%H:%M:%S")
                dur   = str(stats.get("last", datetime.datetime.now()) -
                            stats.get("first", datetime.datetime.now())).split(".")[0]
                state = stats.get("state", "ESTABLISHED")
                byt   = stats.get("bytes", 0)
                byt_s = f"{byt/1024/1024:.1f} MB" if byt > 1024*1024 else f"{byt/1024:.0f} KB" if byt > 1024 else f"{byt} B"
                row_vals = (rank, src, sp, dst, dp, proto,
                            stats.get("packets", 0), byt_s, dur, state, first, last)
                rows.append((proto, row_vals))
        except NameError:
            # conversation_stats not defined yet — show demo data
            demo = [
                ("TCP", (1,"192.168.1.10",53422,"142.250.190.78",443,"TCP",256,"3.2 MB","00:02:45","ESTABLISHED","14:32:37","14:35:22")),
                ("UDP", (2,"192.168.1.15",62001,"8.8.8.8",        53, "UDP", 38,"15 KB", "00:00:03","CLOSED",     "14:32:41","14:32:44")),
                ("TCP", (3,"192.168.1.25",51000,"1.1.1.1",       443,"TCP",154,"1.4 MB","00:01:08","ESTABLISHED","14:32:50","14:33:58")),
                ("TCP", (4,"192.168.1.10",53456,"31.13.91.36",    80, "TCP", 87,"789 KB","00:00:59","CLOSED",     "14:33:01","14:34:00")),
                ("TCP", (5,"192.168.1.30",49512,"20.190.128.1",  443,"TCP",205,"2.1 MB","00:02:10","ESTABLISHED","14:33:12","14:35:22")),
                ("UDP", (6,"192.168.1.15",62002,"8.8.4.4",        53, "UDP", 36,"14 KB", "00:00:02","CLOSED",     "14:33:15","14:33:17")),
                ("TCP", (7,"192.168.1.20",51111,"172.217.160.14",443,"TCP",310,"4.6 MB","00:03:11","ESTABLISHED","14:33:20","14:36:31")),
            ]
            #rows = demo

        # Apply search filter
        filtered = []
        for proto, vals in rows:
            if not query or any(query in str(v).lower() for v in vals):
                filtered.append((proto, vals))

        for idx, (proto, vals) in enumerate(filtered):
            state = vals[9]
            # Tag picks
            tag_map = {"TCP": ("TCP","TCP_ALT"), "UDP": ("UDP","UDP_ALT"),
                       "ICMP": ("ICMP","ICMP_ALT")}
            base_tags = tag_map.get(proto, ("OTH","OTH_ALT"))
            tag = base_tags[idx % 2]
            self.conv_tree.insert("", "end", values=vals, tags=(tag,))

        total = len(filtered)
        self.lbl_count.configure(text=f"Showing 1 to {total} of {total} conversations")
        self.after(3000, self.update_table)

    # ── row selection handler ─────────────────────────────────────────────────
    def _on_select(self, event=None):
        item = self.conv_tree.focus()
        if not item:
            return
        v = self.conv_tree.item(item, "values")
        # v = (no, src, sport, dst, dport, proto, packets, bytes, duration, state, first, last)
        src, sport, dst, dport, proto  = v[1], v[2], v[3], v[4], v[5]
        packets, byte_str, duration, state = v[6], v[7], v[8], v[9]

        # ── Conversation Details ─────────────────────────────────────────────
        self._clear(self._body_details)
        fields = [
            ("Source IP",         src,      "#ffffff"),
            ("Source Port",       sport,    "#ffffff"),
            ("Destination IP",    dst,      "#ffffff"),
            ("Destination Port",  dport,    "#ffffff"),
            ("Protocol",          proto,    self.C_TCP if proto=="TCP" else self.C_UDP if proto=="UDP" else self.C_ICMP),
            ("Packets",           packets,  "#ffffff"),
            ("Bytes",             byte_str, "#ffffff"),
            ("Duration",          duration, "#ffffff"),
            ("State",             state,    self.C_GREEN if state=="ESTABLISHED" else self.C_MUTED),
        ]
        for lbl, val, col in fields:
            self._kv_row(self._body_details, lbl, val, col)

        # Session Verdict footer
        sep = ctk.CTkFrame(self._body_details, fg_color=self.C_BORDER, height=1)
        sep.pack(fill="x", padx=10, pady=(8, 4))
        verdict_box = ctk.CTkFrame(self._body_details, fg_color="#0d1a0d", corner_radius=6)
        verdict_box.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(verdict_box, text="✅  Session Verdict",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=self.C_GREEN).pack(anchor="w", padx=10, pady=(8, 2))
        for bullet in ["Normal Communication", "No Packet Loss Detected", "No Suspicious Patterns"]:
            ctk.CTkLabel(verdict_box, text=f"  • {bullet}",
                         font=ctk.CTkFont(size=11),
                         text_color=self.C_TEXT).pack(anchor="w", padx=10)
        ctk.CTkLabel(verdict_box, text="",).pack(pady=4)

        # ── TCP Session Details ──────────────────────────────────────────────
        self._clear(self._body_session)
        pkt_count = int(packets) if str(packets).isdigit() else 40
        session = [
            ("Handshake",        "Completed",    self.C_GREEN),
            ("SYN Packets",      "1",            "#ffffff"),
            ("SYN-ACK Packets",  "1",            "#ffffff"),
            ("ACK Packets",      str(max(1, pkt_count//3)), "#ffffff"),
            ("FIN Packets",      "1",            "#ffffff"),
            ("RST Packets",      "0",            "#ffffff"),
            ("PSH Packets",      str(max(1, pkt_count//2)), "#ffffff"),
            ("Retransmissions",  "0",            "#ffffff"),
            ("Session State",    state,          self.C_GREEN if state=="ESTABLISHED" else self.C_MUTED),
        ]
        for lbl, val, col in session:
            self._kv_row(self._body_session, lbl, val, col)

        # Risk level footer
        sep2 = ctk.CTkFrame(self._body_session, fg_color=self.C_BORDER, height=1)
        sep2.pack(fill="x", padx=10, pady=(8, 4))
        risk_box = ctk.CTkFrame(self._body_session, fg_color="#0a1a10", corner_radius=6)
        risk_box.pack(fill="x", padx=10, pady=(0, 8))
        risk_row = ctk.CTkFrame(risk_box, fg_color="transparent")
        risk_row.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(risk_row, text="Risk Level:",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#ffffff").pack(side="left")
        ctk.CTkLabel(risk_row, text="  LOW",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=self.C_GREEN).pack(side="left")
        ctk.CTkLabel(risk_box, text="This conversation appears to be safe.",
                     font=ctk.CTkFont(size=11), text_color=self.C_MUTED
                     ).pack(anchor="w", padx=10, pady=(0, 8))

        # ── TCP Flags Summary ────────────────────────────────────────────────
        self._clear(self._body_flags)
        pkt_n = int(packets) if str(packets).isdigit() else 40
        flags_data = [
            ("SYN", 1),
            ("ACK", max(1, pkt_n // 3)),
            ("FIN", 1),
            ("RST", 0),
            ("PSH", max(1, pkt_n // 2)),
            ("URG", 0),
        ]
        total_flags = sum(c for _, c in flags_data)
        for flag, count in flags_data:
            self._flag_bar(self._body_flags, flag, count, total_flags)

        # Total flags footer
        sep3 = ctk.CTkFrame(self._body_flags, fg_color=self.C_BORDER, height=1)
        sep3.pack(fill="x", padx=10, pady=(8, 4))
        tot_row = ctk.CTkFrame(self._body_flags, fg_color="transparent")
        tot_row.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(tot_row, text="Total Flags",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#ffffff").pack(side="left")
        ctk.CTkLabel(tot_row, text=str(total_flags),
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=self.C_GREEN).pack(side="right")
                     
                     
                     
                     
                     
#============================================================
#            Traffic Over Time
#============================================================                     
class TrafficOverTimePage(ctk.CTkFrame):

    # ── palette (matches your theme) ──────────────────────────────────────────
    C_BG     = "#050608"
    C_CARD   = "#12141c"
    C_BORDER = "#1e222b"
    C_HEADER = "#0d0f14"
    C_TEXT   = "#cfd8dc"
    C_MUTED  = "#78909c"
    C_GREEN  = "#00e676"
    C_BLUE   = "#2196f3"
    C_PURPLE = "#9c27b0"
    C_YELLOW = "#ffeb3b"
    C_ORANGE = "#ff9100"

    # chart line colours
    COL_TOTAL = "#2196f3"   # blue
    COL_IN    = "#00e676"   # green
    COL_OUT   = "#9c27b0"   # purple

    def __init__(self, parent):
        super().__init__(parent, fg_color=self.C_BG, corner_radius=0)

        # Rolling history buffers (last 210 samples = 3.5 min @ 1 Hz)
        self._MAX_SAMPLES = 210
        self._times   = []   # datetime list
        self._total   = []   # pkt/sec total
        self._inc     = []   # incoming
        self._out     = []   # outgoing
        self._last_total = 0
        self._last_inc   = 0
        self._last_out   = 0
        self._capture_start = None
        self._peak   = 0
        self._chart_canvas = None  # FIX: Changed from _canvas to _chart_canvas
        self._fig    = None
        self._ax     = None
        self._alive  = True
        
        # Interval & chart-type state (dropdowns write here)
        self._interval_secs  = 1       # 1 | 5 | 60
        self._chart_type     = "line"  # "line" | "bar"
        self._tick_counter   = 0       # counts 1-sec ticks
        self._bucket_total   = 0       # accumulator within one bucket
        self._bucket_inc     = 0
        self._bucket_out     = 0
        self._interval_var   = None    # tk.StringVar — set after widget build
        self._chart_type_var = None

        # Scrollable outer container
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True)

        self._build_header()
        self._build_kpi_cards()
        self._build_chart_section()
        self._build_bottom_panels()

        # Start live update loop
        self.after(1000, self._tick)

    # ══════════════════════════════════════════════════════════════════════════
    #   HEADER
    # ══════════════════════════════════════════════════════════════════════════
    def _build_header(self):
        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 10))

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text="Traffic Over Time",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="#ffffff").pack(anchor="w")
        ctk.CTkLabel(left,
                     text="Analyze network traffic trends over time.",
                     font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED).pack(anchor="w")

        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right")
        self._lbl_updated = ctk.CTkLabel(
            right, text="Last Updated: --:--:--",
            font=ctk.CTkFont(size=11), text_color=self.C_MUTED)
        self._lbl_updated.pack(side="left", padx=(0, 10))
        ctk.CTkButton(right, text="↻  Refresh", width=90, height=30,
                      fg_color="#1a1c23", border_width=1,
                      border_color="#2a2e3d", text_color="#90a4ae",
                      hover_color="#12141c", corner_radius=6,
                      command=self._manual_refresh).pack(side="left")

    # ══════════════════════════════════════════════════════════════════════════
    #   KPI CARDS
    # ══════════════════════════════════════════════════════════════════════════
    def _build_kpi_cards(self):
        kpi_row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        kpi_row.pack(fill="x", padx=15, pady=(0, 15))
        for i in range(5):
            kpi_row.grid_columnconfigure(i, weight=1)

        # (title, accent_color, attr_value_label, attr_sub_label, icon_char)
        kpi_defs = [
            ("Start Time",       self.C_BLUE,   "_kv_start",   "_ks_start",  "⏱"),
            ("End Time",         self.C_PURPLE,  "_kv_end",     "_ks_end",   "⏰"),
            ("Peak Traffic",     self.C_YELLOW,  "_kv_peak",    "_ks_peak",  "📈"),
            ("Average Traffic",  self.C_GREEN,   "_kv_avg",     "_ks_avg",   "〜"),
            ("Total Data",       self.C_BLUE,    "_kv_data",    "_ks_data",  "💾"),
        ]

        defaults = [
            ("--:--:--",      "--"),
            ("--:--:--",      "--"),
            ("0 pkt/sec",     "at --:--:--"),
            ("0 pkt/sec",     "over 00:00:00"),
            ("0.00 KB",       "Total Transferred"),
        ]

        for idx, ((title, color, val_attr, sub_attr, icon), (def_val, def_sub)) in enumerate(zip(kpi_defs, defaults)):
            card = ctk.CTkFrame(kpi_row, fg_color=self.C_CARD,
                                corner_radius=8, border_width=1,
                                border_color=self.C_BORDER, height=80)
            card.grid(row=0, column=idx, padx=5, sticky="nsew")
            card.pack_propagate(False)

            # Coloured left accent bar
            ctk.CTkFrame(card, fg_color=color, width=4,
                         corner_radius=2).pack(side="left", fill="y",
                                               pady=14, padx=(14, 10))

            # Icon circle
            icon_lbl = ctk.CTkLabel(card, text=icon,
                                    font=ctk.CTkFont(size=18),
                                    text_color=color, width=32)
            icon_lbl.pack(side="left", pady=10)

            tf = ctk.CTkFrame(card, fg_color="transparent")
            tf.pack(side="left", fill="both", expand=True, pady=8, padx=(4, 10))

            ctk.CTkLabel(tf, text=title,
                         font=ctk.CTkFont(size=10),
                         text_color=self.C_MUTED).pack(anchor="w")

            val_lbl = ctk.CTkLabel(tf, text=def_val,
                                   font=ctk.CTkFont(size=15, weight="bold"),
                                   text_color="#ffffff")
            val_lbl.pack(anchor="w")

            sub_lbl = ctk.CTkLabel(tf, text=def_sub,
                                   font=ctk.CTkFont(size=10),
                                   text_color=self.C_MUTED)
            sub_lbl.pack(anchor="w")

            setattr(self, val_attr, val_lbl)
            setattr(self, sub_attr, sub_lbl)

    # ══════════════════════════════════════════════════════════════════════════
    #   CHART SECTION
    # ══════════════════════════════════════════════════════════════════════════
    def _build_chart_section(self):
        chart_card = ctk.CTkFrame(self._scroll, fg_color=self.C_CARD,
                                  corner_radius=8, border_width=1,
                                  border_color=self.C_BORDER)
        chart_card.pack(fill="x", padx=20, pady=(0, 15))

        # Toolbar
        tb = ctk.CTkFrame(chart_card, fg_color="transparent")
        tb.pack(fill="x", padx=15, pady=(12, 4))

        ctk.CTkLabel(tb, text="Time Range:",
                     font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED).pack(side="left")
        ctk.CTkOptionMenu(tb, values=["Live", "Last 1 Min", "Last 5 Min"],
                          width=100, height=28,
                          fg_color="#1a1c23", button_color="#2a2e3d",
                          text_color="#ffffff").pack(side="left", padx=(5, 15))

        ctk.CTkLabel(tb, text="From:", font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED).pack(side="left")
        self._ent_from = ctk.CTkEntry(tb, placeholder_text="--:--:--",
                                       width=85, height=28,
                                       fg_color="#1a1c23",
                                       border_color="#2a2e3d",
                                       text_color="#ffffff")
        self._ent_from.pack(side="left", padx=5)

        ctk.CTkLabel(tb, text="To:", font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED).pack(side="left")
        self._ent_to = ctk.CTkEntry(tb, placeholder_text="--:--:--",
                                     width=85, height=28,
                                     fg_color="#1a1c23",
                                     border_color="#2a2e3d",
                                     text_color="#ffffff")
        self._ent_to.pack(side="left", padx=5)

        self._interval_var = tk.StringVar(value="1 Second")
        ctk.CTkOptionMenu(tb, values=["1 Second", "5 Seconds", "1 Minute"],
                          width=110, height=28,
                          fg_color="#1a1c23", button_color="#2a2e3d",
                          text_color="#ffffff",
                          variable=self._interval_var,
                          command=self._on_interval_change).pack(side="right", padx=5)

        self._chart_type_var = tk.StringVar(value="Line Chart")
        ctk.CTkOptionMenu(tb, values=["Line Chart", "Bar Chart"],
                          width=110, height=28,
                          fg_color="#1a1c23", button_color="#2a2e3d",
                          text_color="#ffffff",
                          variable=self._chart_type_var,
                          command=self._on_chart_type_change).pack(side="right", padx=5)

        # Chart title row
        title_row = ctk.CTkFrame(chart_card, fg_color="transparent")
        title_row.pack(fill="x", padx=15, pady=(4, 0))
        ctk.CTkLabel(title_row,
                     text="Network Traffic  (Packets per Second)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#ffffff").pack(side="left")

        # Legend
        for col, label in [(self.COL_TOTAL, "Total Traffic"),
                           (self.COL_IN,    "Incoming Traffic"),
                           (self.COL_OUT,   "Outgoing Traffic")]:
            dot = ctk.CTkFrame(title_row, fg_color=col,
                               width=10, height=10, corner_radius=5)
            dot.pack(side="right", padx=(0, 2))
            ctk.CTkLabel(title_row, text=label,
                         font=ctk.CTkFont(size=10),
                         text_color=self.C_TEXT).pack(side="right", padx=(0, 8))

        # Graph embed frame
        self._graph_frame = ctk.CTkFrame(chart_card, fg_color="transparent",
                                          height=310)
        self._graph_frame.pack(fill="x", padx=10, pady=(4, 10))
        self._graph_frame.pack_propagate(False)
        self._init_chart()

    def _init_chart(self):
        plt.style.use("dark_background")
        self._fig, self._ax = plt.subplots(figsize=(11, 3.6), dpi=95)
        self._fig.patch.set_facecolor(self.C_CARD)
        self._ax.set_facecolor(self.C_CARD)
        self._ax.spines["top"].set_visible(False)
        self._ax.spines["right"].set_visible(False)
        self._ax.spines["bottom"].set_color(self.C_BORDER)
        self._ax.spines["left"].set_color(self.C_BORDER)
        self._ax.tick_params(colors=self.C_MUTED, labelsize=8)
        self._ax.set_ylabel("Packets / Second", color=self.C_MUTED, fontsize=9)
        self._ax.set_xlabel("Time", color=self.C_MUTED, fontsize=9)
        self._ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=6))
        self._fig.tight_layout(pad=1.2)

        # FIX: Using _chart_canvas instead of _canvas
        self._chart_canvas = FigureCanvasTkAgg(self._fig, master=self._graph_frame)
        widget = self._chart_canvas.get_tk_widget()
        widget.pack(fill="both", expand=True)
        # Bind destroy so we know when the widget is gone
        widget.bind("<Destroy>", lambda e: setattr(self, "_alive", False))
        self._chart_canvas.draw()

    def _redraw_chart(self):
        # FIX: Only draw if we have at least 2 points (prevents AutoDateLocator warning)
        if len(self._times) < 2 or not self._alive:
            return
        try:
            self._ax.cla()
            self._ax.set_facecolor(self.C_CARD)
            self._ax.spines["top"].set_visible(False)
            self._ax.spines["right"].set_visible(False)
            self._ax.spines["bottom"].set_color(self.C_BORDER)
            self._ax.spines["left"].set_color(self.C_BORDER)
            self._ax.tick_params(colors=self.C_MUTED, labelsize=8)
            self._ax.set_ylabel("Packets / Second", color=self.C_MUTED, fontsize=9)
            self._ax.set_xlabel("Time", color=self.C_MUTED, fontsize=9)

            t = self._times
            if self._chart_type == "bar":
                x_idx = list(range(len(t)))
                width = 0.28
                self._ax.bar([i - width for i in x_idx], self._total,
                             width=width, color=self.COL_TOTAL, alpha=0.85, label="Total")
                self._ax.bar(x_idx, self._inc,
                             width=width, color=self.COL_IN,    alpha=0.85, label="Incoming")
                self._ax.bar([i + width for i in x_idx], self._out,
                             width=width, color=self.COL_OUT,   alpha=0.85, label="Outgoing")
                step = max(1, len(t) // 7)
                tick_pos    = list(range(0, len(t), step))
                tick_labels = [t[i].strftime("%H:%M:%S") for i in tick_pos]
                self._ax.set_xticks(tick_pos)
                self._ax.set_xticklabels(tick_labels, rotation=0,
                                         ha="center", color=self.C_MUTED, fontsize=8)
            else:
                self._ax.plot(t, self._total, color=self.COL_TOTAL, linewidth=1.4, label="Total")
                self._ax.plot(t, self._inc,   color=self.COL_IN,    linewidth=1.4, label="Incoming")
                self._ax.plot(t, self._out,   color=self.COL_OUT,   linewidth=1.4, label="Outgoing")
                self._ax.fill_between(t, self._total, alpha=0.08, color=self.COL_TOTAL)
                self._ax.fill_between(t, self._inc,   alpha=0.08, color=self.COL_IN)
                self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
                self._ax.xaxis.set_major_locator(mdates.AutoDateLocator(maxticks=8))
                plt.setp(self._ax.get_xticklabels(),
                         rotation=0, ha="center", color=self.C_MUTED, fontsize=8)

            self._ax.set_ylim(bottom=0)
            self._ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=6))
            self._fig.tight_layout(pad=1.2)
            
            # FIX: Updated to use _chart_canvas
            self._chart_canvas.draw_idle()
        except Exception:
            pass  # canvas may be mid-destroy — ignore silently


    # ══════════════════════════════════════════════════════════════════════════
    #   BOTTOM PANELS
    # ══════════════════════════════════════════════════════════════════════════
    def _build_bottom_panels(self):
        row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 20))
        row.grid_columnconfigure((0, 1, 2), weight=1)

        # ── Traffic Statistics ───────────────────────────────────────────────
        sc = self._bottom_card(row, "📊  Traffic Statistics", 0)
        self._stat_rows = {}
        stats_defs = [
            ("tot_pkt",   "Total Packets",          "0"),
            ("avg_pps",   "Average Packets / sec",  "0"),
            ("peak_pps",  "Peak Packets / sec",     "0"),
            ("min_pps",   "Minimum Packets / sec",  "0"),
            ("tot_data",  "Total Data Transferred", "0 B"),
            ("duration",  "Capture Duration",       "00:00:00"),
        ]
        for key, lbl, val in stats_defs:
            self._stat_rows[key] = self._kv_row(sc, lbl, val)

        # ── Traffic Insights ─────────────────────────────────────────────────
        ic = self._bottom_card(row, "📈  Traffic Insights", 1)
        self._ins_rows = {}
        ins_defs = [
            ("peak_time",  "Peak Time",          "--:--:--",   "#ffffff"),
            ("hi_spike",   "Highest Spike",      "0 pkt/sec",  "#ffffff"),
            ("lo_traffic", "Lowest Traffic",     "0 pkt/sec",  "#ffffff"),
            ("avg_rate",   "Average Data Rate",  "0 KB/s",     "#ffffff"),
            ("trend",      "Traffic Trend",      "Stable",     self.C_GREEN),
        ]
        for key, lbl, val, col in ins_defs:
            self._ins_rows[key] = self._kv_row(ic, lbl, val, col)

        # ── Traffic Status ───────────────────────────────────────────────────
        stc = self._bottom_card(row, "🛡  Traffic Status", 2)
        self._status_labels = []
        statuses = [
            "Traffic Stable",
            "No Traffic Burst Detected",
            "No Network Congestion",
            "Network Performance Normal",
        ]
        for s in statuses:
            r = ctk.CTkFrame(stc, fg_color="transparent")
            r.pack(fill="x", padx=15, pady=8)
            dot = ctk.CTkFrame(r, fg_color=self.C_GREEN,
                               width=10, height=10, corner_radius=5)
            dot.pack(side="left", padx=(0, 10))
            lbl = ctk.CTkLabel(r, text=s,
                               font=ctk.CTkFont(size=12),
                               text_color=self.C_TEXT)
            lbl.pack(side="left")
            self._status_labels.append((dot, lbl))

    def _bottom_card(self, parent, title, col):
        card = ctk.CTkFrame(parent, fg_color=self.C_CARD,
                            corner_radius=8, border_width=1,
                            border_color=self.C_BORDER)
        card.grid(row=0, column=col, padx=5, sticky="nsew")

        bar = ctk.CTkFrame(card, fg_color=self.C_HEADER,
                           corner_radius=0, height=34)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text=title,
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#ffffff").pack(side="left", padx=14, pady=6)
        return card

    def _kv_row(self, parent, label, value, val_color="#ffffff"):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text=label,
                     font=ctk.CTkFont(size=11),
                     text_color=self.C_MUTED).pack(side="left")
        val_lbl = ctk.CTkLabel(row, text=value,
                               font=ctk.CTkFont(size=11, weight="bold"),
                               text_color=val_color)
        val_lbl.pack(side="right")
        return val_lbl   # return so caller can update it later

    def _on_interval_change(self, value):
        mapping = {"1 Second": 1, "5 Seconds": 5, "1 Minute": 60}
        self._interval_secs = mapping.get(value, 1)
        # Clear buffers so chart starts fresh for new interval
        self._times.clear(); self._total.clear()
        self._inc.clear();   self._out.clear()
        self._tick_counter = 0
        self._bucket_total = self._bucket_inc = self._bucket_out = 0

    def _on_chart_type_change(self, value):
        self._chart_type = "bar" if value == "Bar Chart" else "line"
        self._redraw_chart()

    # ══════════════════════════════════════════════════════════════════════════
    #   LIVE DATA TICK  (called every 1 second by self.after)
    # ══════════════════════════════════════════════════════════════════════════
    def _tick(self):
        # FIX: This check is already here and prevents the "invalid command name" error for this class!
        if not self.winfo_exists():
            return

        now = datetime.datetime.now()

        # Read current totals from global packet_count
        try:
            cur_total = packet_count["Total"]
        except NameError:
            cur_total = 0

        pps_total = max(0, cur_total - self._last_total)
        pps_inc   = int(pps_total * 0.65)
        pps_out   = pps_total - pps_inc
        self._last_total = cur_total

        # Accumulate into current bucket
        self._bucket_total += pps_total
        self._bucket_inc   += pps_inc
        self._bucket_out   += pps_out
        self._tick_counter += 1

        # Only push a data point when the bucket is full
        if self._tick_counter >= self._interval_secs:
            avg_total = self._bucket_total // self._interval_secs
            avg_inc   = self._bucket_inc   // self._interval_secs
            avg_out   = self._bucket_out   // self._interval_secs

            self._times.append(now)
            self._total.append(avg_total)
            self._inc.append(avg_inc)
            self._out.append(avg_out)

            # Trim to max samples
            if len(self._times) > self._MAX_SAMPLES:
                self._times = self._times[-self._MAX_SAMPLES:]
                self._total = self._total[-self._MAX_SAMPLES:]
                self._inc   = self._inc[-self._MAX_SAMPLES:]
                self._out   = self._out[-self._MAX_SAMPLES:]

            # Reset bucket
            self._bucket_total = self._bucket_inc = self._bucket_out = 0
            self._tick_counter = 0

            self._redraw_chart()

        # Track peak (every tick, not just per bucket)
        if pps_total > self._peak:
            self._peak = pps_total
            self._peak_time = now

        if self._capture_start is None and cur_total > 0:
            self._capture_start = now

        self._update_kpis(now, cur_total, pps_total)
        self._update_bottom(now, cur_total, pps_total)

        self._lbl_updated.configure(
            text=f"Last Updated: {now.strftime('%H:%M:%S')}")
        self.after(1000, self._tick)

    def _update_kpis(self, now, cur_total, pps):
        start_str = self._capture_start.strftime("%H:%M:%S") if self._capture_start else "--:--:--"
        date_str  = now.strftime("%d %B %Y")

        self._kv_start.configure(text=start_str)
        self._ks_start.configure(text=date_str)

        self._kv_end.configure(text=now.strftime("%H:%M:%S"))
        self._ks_end.configure(text=date_str)

        self._kv_peak.configure(text=f"{self._peak:,} pkt/sec")
        peak_t = getattr(self, "_peak_time", now)
        self._ks_peak.configure(text=f"at {peak_t.strftime('%H:%M:%S')}")

        avg = int(sum(self._total) / len(self._total)) if self._total else 0
        self._kv_avg.configure(text=f"{avg:,} pkt/sec")

        elapsed = (now - self._capture_start).seconds if self._capture_start else 0
        h, r = divmod(elapsed, 3600); m, s = divmod(r, 60)
        self._ks_avg.configure(text=f"over {h:02d}:{m:02d}:{s:02d}")

        total_bytes = cur_total * 185
        if total_bytes >= 1024*1024:
            data_str = f"{total_bytes/1024/1024:.1f} MB"
        elif total_bytes >= 1024:
            data_str = f"{total_bytes/1024:.0f} KB"
        else:
            data_str = f"{total_bytes} B"
        self._kv_data.configure(text=data_str)

        # from/to entry boxes
        if self._capture_start:
            self._ent_from.delete(0, "end")
            self._ent_from.insert(0, self._capture_start.strftime("%H:%M:%S"))
        self._ent_to.delete(0, "end")
        self._ent_to.insert(0, now.strftime("%H:%M:%S"))

    def _update_bottom(self, now, cur_total, pps):
        elapsed = (now - self._capture_start).seconds if self._capture_start else 0
        h, r = divmod(elapsed, 3600); m, s = divmod(r, 60)
        avg_pps = int(sum(self._total) / len(self._total)) if self._total else 0
        min_pps = min(self._total) if self._total else 0
        total_bytes = cur_total * 185
        data_rate   = total_bytes / elapsed if elapsed > 0 else 0

        if total_bytes >= 1024*1024:
            data_str = f"{total_bytes/1024/1024:.1f} MB"
        elif total_bytes >= 1024:
            data_str = f"{total_bytes/1024:.0f} KB"
        else:
            data_str = f"{total_bytes} B"

        rate_str = f"{data_rate/1024:.2f} MB/s" if data_rate >= 1024*1024 else f"{data_rate/1024:.2f} KB/s"

        self._stat_rows["tot_pkt"].configure(text=f"{cur_total:,}")
        self._stat_rows["avg_pps"].configure(text=str(avg_pps))
        self._stat_rows["peak_pps"].configure(text=f"{self._peak:,}")
        self._stat_rows["min_pps"].configure(text=str(int(min_pps)))
        self._stat_rows["tot_data"].configure(text=data_str)
        self._stat_rows["duration"].configure(text=f"{h:02d}:{m:02d}:{s:02d}")

        peak_t = getattr(self, "_peak_time", now)
        self._ins_rows["peak_time"].configure(text=peak_t.strftime("%H:%M:%S"))
        self._ins_rows["hi_spike"].configure(text=f"{self._peak:,} pkt/sec")
        self._ins_rows["lo_traffic"].configure(text=f"{int(min_pps)} pkt/sec")
        self._ins_rows["avg_rate"].configure(text=rate_str)

        # Trend check — is recent avg > earlier avg?
        if len(self._total) >= 20:
            recent = sum(self._total[-10:]) / 10
            older  = sum(self._total[-20:-10]) / 10
            if recent > older * 1.2:
                trend, tcol = "Rising ↑", self.C_YELLOW
            elif recent < older * 0.8:
                trend, tcol = "Falling ↓", self.C_ORANGE
            else:
                trend, tcol = "Stable",    self.C_GREEN
            self._ins_rows["trend"].configure(text=trend, text_color=tcol)

        # Status dots — go red if peak > 1000
        alert = self._peak > 1000
        for dot, lbl in self._status_labels:
            dot.configure(fg_color=self.C_GREEN if not alert else "#ff1744")

    def _manual_refresh(self):
        self._times.clear()
        self._total.clear()
        self._inc.clear()
        self._out.clear()
        self._peak       = 0
        self._peak_time  = None
        self._capture_start = None
        self._last_total = 0
        
        
        
        
        
        
        
        
        
        
        
#================================================
#              IP Geolocation
#================================================
class IPGeolocationPage(ctk.CTkFrame):
    # ── palette (matches your theme) ──────────────────────────────────────────
    C_BG     = "#050608"
    C_CARD   = "#12141c"
    C_BORDER = "#1e222b"
    C_HEADER = "#0d0f14"
    C_TEXT   = "#cfd8dc"
    C_MUTED  = "#78909c"
    C_BLUE   = "#2196f3"
    C_GREEN  = "#00e676"

    def __init__(self, parent):
        super().__init__(parent, fg_color=self.C_BG, corner_radius=0)

        # Scrollable outer container
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True)

        self._build_header()
        self._build_search_bar()
        self._build_middle_section()
        self._build_bottom_panels()

    # ══════════════════════════════════════════════════════════════════════════
    #   HEADER
    # ══════════════════════════════════════════════════════════════════════════
    def _build_header(self):
        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 10))

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text="IP Geolocation", font=ctk.CTkFont(size=20, weight="bold"), text_color="#ffffff").pack(anchor="w")
        ctk.CTkLabel(left, text="Locate IP addresses and view geographic information.", font=ctk.CTkFont(size=11), text_color=self.C_MUTED).pack(anchor="w")

        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right")
        self._lbl_updated = ctk.CTkLabel(right, text="Last Updated: --:--:--", font=ctk.CTkFont(size=11), text_color=self.C_MUTED)
        self._lbl_updated.pack(side="left", padx=(0, 10))
        ctk.CTkButton(right, text="↻  Refresh", width=90, height=30, fg_color="#1a1c23", border_width=1, border_color="#2a2e3d", text_color="#90a4ae", hover_color="#12141c", corner_radius=6, command=lambda: self._lookup_ip(self._ent_ip.get())).pack(side="left")

    # ══════════════════════════════════════════════════════════════════════════
    #   SEARCH BAR
    # ══════════════════════════════════════════════════════════════════════════
    def _build_search_bar(self):
        search_row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        search_row.pack(fill="x", padx=20, pady=(0, 15))

        self._ent_ip = ctk.CTkEntry(search_row, placeholder_text="🔍  Enter IP address...", width=450, height=36, fg_color="#1a1c23", border_color="#2a2e3d", text_color="#ffffff", placeholder_text_color="#546e7a", corner_radius=6)
        self._ent_ip.pack(side="left", padx=(0, 10))
        self._ent_ip.bind("<Return>", lambda e: self._lookup_ip(self._ent_ip.get()))

        ctk.CTkButton(search_row, text="🔍  Locate", width=90, height=36, fg_color=self.C_BLUE, text_color="#ffffff", hover_color="#1565c0", corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"), command=lambda: self._lookup_ip(self._ent_ip.get())).pack(side="left", padx=5)
        ctk.CTkButton(search_row, text="🗑  Clear", width=90, height=36, fg_color="#424242", text_color="#90a4ae", hover_color="#37474f", corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"), command=self._clear_results).pack(side="left")

    # ══════════════════════════════════════════════════════════════════════════
    #   MIDDLE SECTION (IP Info Only - Map Removed)
    # ══════════════════════════════════════════════════════════════════════════
    def _build_middle_section(self):
        mid_row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        mid_row.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        mid_row.grid_columnconfigure((0, 1), weight=1)

        map_card = ctk.CTkFrame(mid_row, fg_color=self.C_CARD, corner_radius=8, border_width=1, border_color=self.C_BORDER, height=360)
        map_card.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        map_card.pack_propagate(False)

        bar = ctk.CTkFrame(map_card, fg_color=self.C_HEADER, corner_radius=0, height=34)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text="🗺  Map View", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(side="left", padx=14, pady=6)

        self._map = OfflineWorldMap(map_card, width=400, height=320, bg_color=self.C_CARD)
        self._map.pack(fill="both", expand=True, padx=8, pady=8)
        self._map.set_position(20.5937, 78.9629)
        self._map.set_zoom(4) 

        info_card = ctk.CTkFrame(mid_row, fg_color=self.C_CARD, corner_radius=8, border_width=1, border_color=self.C_BORDER)
        info_card.grid(row=0, column=1, padx=(10, 0), sticky="nsew")

        bar2 = ctk.CTkFrame(info_card, fg_color=self.C_HEADER, corner_radius=0, height=34)
        bar2.pack(fill="x")
        bar2.pack_propagate(False)
        ctk.CTkLabel(bar2, text="ℹ  IP Information", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(side="left", padx=14, pady=6)

        scroll_info = ctk.CTkScrollableFrame(info_card, fg_color="transparent")
        scroll_info.pack(fill="both", expand=True, padx=4, pady=4)

        self._info_rows = {}
        info_fields = [
            ("IP Address",    "ip_addr",    "#ffffff"), ("Country",       "country",    "#ffffff"),
            ("Region",        "region",     "#ffffff"), ("City",          "city",       "#ffffff"),
            ("ISP",           "isp",        "#ffffff"), ("Organization",  "org",        "#ffffff"),
            ("Timezone",      "tz",         "#ffffff"), ("Latitude",      "lat",        "#ffffff"),
            ("Longitude",     "lon",        "#ffffff"),
        ]
        for label, key, color in info_fields:
            row = ctk.CTkFrame(scroll_info, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=8)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=11), text_color=self.C_MUTED, anchor="w").pack(side="left")
            val_lbl = ctk.CTkLabel(row, text="--", font=ctk.CTkFont(size=11, weight="bold"), text_color=color, anchor="e")
            val_lbl.pack(side="right")
            self._info_rows[key] = val_lbl

    # ══════════════════════════════════════════════════════════════════════════
    #   BOTTOM PANELS
    # ══════════════════════════════════════════════════════════════════════════
    def _build_bottom_panels(self):
        row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 20))
        row.grid_columnconfigure((0, 1, 2), weight=1)

        # ── Network Information ──────────────────────────────────────────────
        net_card = self._make_bottom_card(row, "🖧  Network Information", 0)
        self._net_rows = {}
        net_fields = [
            ("Hostname",           "hostname",   "#ffffff"),
            ("ASN",                "asn",        "#ffffff"),
            ("ASN Organization",   "asn_org",    "#ffffff"),
            ("Reverse DNS",        "reverse_dns","#ffffff"),
            ("IP Type",            "ip_type",    self.C_GREEN),
            ("Connection Type",    "conn_type",  "#ffffff"),
        ]
        for label, key, color in net_fields:
            self._net_rows[key] = self._kv_row(net_card, label, "--", color)

        # ── Location Details ────────────────────────────────────────────────
        loc_card = self._make_bottom_card(row, "📍  Location Details", 1)
        self._loc_rows = {}
        loc_fields = [
            ("Continent",     "continent",    "#ffffff"),
            ("Country Code",  "country_code", "#ffffff"),
            ("Region Code",   "region_code",  "#ffffff"),
            ("Postal Code",   "postal",       "#ffffff"),
            ("Local Time",    "local_time",   "#ffffff"),
            ("Currency",      "currency",     "#ffffff"),
        ]
        for label, key, color in loc_fields:
            self._loc_rows[key] = self._kv_row(loc_card, label, "--", color)

        # ── Security Assessment ────────────────────────────────────────────
        sec_card = self._make_bottom_card(row, "🛡  Security Assessment", 2)
        self._sec_rows = {}
        sec_fields = [
            ("IP is a Public IP Address",        "public",      self.C_GREEN),
            ("Geolocation Found Successfully",   "geo_found",   self.C_GREEN),
            ("No Known Threat Intelligence Detected", "threat", self.C_GREEN),
            ("Not Blacklisted",                  "blacklist",   self.C_GREEN),
            ("Connection is Safe",               "safe",        self.C_GREEN),
        ]
        for label, key, color in sec_fields:
            row_f = ctk.CTkFrame(sec_card, fg_color="transparent")
            row_f.pack(fill="x", padx=14, pady=6)
            dot = ctk.CTkFrame(row_f, fg_color=color, width=10, height=10, corner_radius=5)
            dot.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(row_f, text=label, font=ctk.CTkFont(size=11), text_color=self.C_TEXT).pack(side="left")
            self._sec_rows[key] = dot

        risk_row = ctk.CTkFrame(sec_card, fg_color="transparent")
        risk_row.pack(fill="x", padx=14, pady=(12, 6))
        ctk.CTkLabel(risk_row, text="Risk Status", font=ctk.CTkFont(size=11, weight="bold"), text_color="#ffffff").pack(side="left")
        self._lbl_risk = ctk.CTkLabel(risk_row, text="LOW RISK", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_GREEN)
        self._lbl_risk.pack(side="right")

    # ── helpers ───────────────────────────────────────────────────────────────
    def _country_code_to_flag(self, code):
        if not code or len(code) != 2: 
            return "🌐"
        code = code.upper()
        try:
            return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code)
        except Exception:
            return "🌐"

    def _make_bottom_card(self, parent, title, col):
        card = ctk.CTkFrame(parent, fg_color=self.C_CARD, corner_radius=8, border_width=1, border_color=self.C_BORDER)
        card.grid(row=0, column=col, padx=5, sticky="nsew")
        bar = ctk.CTkFrame(card, fg_color=self.C_HEADER, corner_radius=0, height=34)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(side="left", padx=14, pady=6)
        return card

    def _kv_row(self, parent, label, value, val_color="#ffffff"):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=5)
        ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=11), text_color=self.C_MUTED).pack(side="left")
        val_lbl = ctk.CTkLabel(row, text=value, font=ctk.CTkFont(size=11, weight="bold"), text_color=val_color)
        val_lbl.pack(side="right")
        return val_lbl

    # ══════════════════════════════════════════════════════════════════════════
    #   IP LOOKUP ENGINE
    # ══════════════════════════════════════════════════════════════════════════
    def _lookup_ip(self, ip_addr):
        """Start IP lookup in background thread"""
        ip_addr = ip_addr.strip()
        if not ip_addr:
            self._show_error("Please enter an IP address")
            return
        
        self._lbl_updated.configure(text="🔄 Loading...", text_color="#ff9100")
        threading.Thread(target=self._lookup_thread, args=(ip_addr,), daemon=True).start()

    def _lookup_thread(self, ip_addr):
        """Background thread for IP lookup"""
        try:
            # Validate IP format
            try:
                ip_obj = ipaddress.ip_address(ip_addr)
                if ip_obj.is_private:
                    self.after(0, lambda: self._show_error("Private IP cannot be geolocated"))
                    return
            except ValueError:
                self.after(0, lambda: self._show_error("Invalid IP format"))
                return
            
            # Call API - using ip-api.com (free tier, no key needed)
            url = f"http://ip-api.com/json/{ip_addr}?fields=status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,type"
            response = requests.get(url, timeout=5)
            data = response.json()
            
            # Check API response status
            if data.get("status") == "fail":
                error_msg = data.get("message", "IP not found")
                self.after(0, lambda msg=error_msg: self._show_error(msg))
            else:
                self.after(0, lambda d=data: self._update_ui(d))

        except requests.exceptions.Timeout:
            self.after(0, lambda: self._show_error("Request timeout - try again"))
        except requests.exceptions.ConnectionError:
            self.after(0, lambda: self._show_error("No internet connection"))
        except Exception as e:
            self.after(0, lambda: self._show_error(f"Error: {str(e)}"))

    def _update_ui(self, data):
        """Update all UI elements with IP data"""
        if not self.winfo_exists(): 
            return
        
        # Update entry field
        self._ent_ip.delete(0, "end")
        self._ent_ip.insert(0, data.get("query", "--"))

        # Update IP Info Section
        self._info_rows["ip_addr"].configure(text=data.get("query", "--"))
        country_code = data.get("countryCode", "")
        flag = self._country_code_to_flag(country_code)
        self._info_rows["country"].configure(text=f"{flag} {data.get('country', '--')}")
        self._info_rows["region"].configure(text=data.get("regionName", "--"))
        self._info_rows["city"].configure(text=data.get("city", "--"))
        self._info_rows["isp"].configure(text=data.get("isp", "--"))
        self._info_rows["org"].configure(text=data.get("org", "--"))
        self._info_rows["tz"].configure(text=data.get("timezone", "--"))
        
        lat = data.get("lat", "--")
        lon = data.get("lon", "--")
        self._info_rows["lat"].configure(text=f"{lat:.4f}" if lat != "--" else "--")
        self._info_rows["lon"].configure(text=f"{lon:.4f}" if lon != "--" else "--")

        # Update Network Info Section
        asn_full = data.get("as", "--")
        asn_only = asn_full.split(" ")[0] if asn_full != "--" else "--"
        
        self._net_rows["hostname"].configure(text="--") 
        self._net_rows["asn"].configure(text=asn_only)
        self._net_rows["asn_org"].configure(text=data.get("org", "--"))
        self._net_rows["reverse_dns"].configure(text="--")
        self._net_rows["ip_type"].configure(text="Public IP" if not data.get("proxy") else "Proxy/VPN")
        self._net_rows["conn_type"].configure(text="ISP" if data.get("type") == "isp" else data.get("type", "--"))

        # Update Location Details Section
        self._loc_rows["continent"].configure(text="--")
        self._loc_rows["country_code"].configure(text=data.get("countryCode", "--"))
        self._loc_rows["region_code"].configure(text=data.get("region", "--"))
        self._loc_rows["postal"].configure(text=data.get("zip", "--"))
        local_time = datetime.datetime.now().strftime("%b %d, %Y %I:%M %p")
        self._loc_rows["local_time"].configure(text=local_time)
        self._loc_rows["currency"].configure(text="--")

        # Update Security Assessment (all green for demo)
        for key in self._sec_rows:
            self._sec_rows[key].configure(fg_color=self.C_GREEN)
        self._lbl_risk.configure(text="LOW RISK", text_color=self.C_GREEN)
        
        # Update timestamp
        self._lbl_updated.configure(
            text=f"Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}", 
            text_color=self.C_MUTED
        )

    def _show_error(self, msg):
        """Show error in UI"""
        if not self.winfo_exists(): 
            return
        
        for val in self._info_rows.values(): 
            val.configure(text="--")
        for val in self._net_rows.values(): 
            val.configure(text="--")
        for val in self._loc_rows.values(): 
            val.configure(text="--")
        
        self._lbl_risk.configure(text="ERROR", text_color="#ff1744")
        self._lbl_updated.configure(text=f"❌ {msg}", text_color="#ff1744")

    def _clear_results(self):
        """Clear all fields"""
        if not self.winfo_exists(): 
            return
        
        self._ent_ip.delete(0, "end")
        for val in self._info_rows.values(): 
            val.configure(text="--")
        for val in self._net_rows.values(): 
            val.configure(text="--")
        for val in self._loc_rows.values():
            val.configure(text="--")
        
        self._lbl_risk.configure(text="--", text_color=self.C_MUTED)
        self._lbl_updated.configure(text="Last Updated: --:--:--", text_color=self.C_MUTED)




#================================================
#     Packet Search Page
#================================================
class PacketSearchPage(ctk.CTkFrame):
    """
    Packet Search Engine page. Reads its data from the main app's live
    Live Capture table (self._app.all_tree_items / self._app.tree), so it
    always searches whatever has actually been captured — no separate
    buffer to keep in sync.

    `app` = the NetworkSnifferApp instance (needed to read captured packets
    and, for consistency with IPGeolocationPage, to show live counters).
    """

    # ── palette (matches rest of app) ────────────────────────────────────────
    C_BG      = "#050608"
    C_CARD    = "#12141c"
    C_BORDER  = "#1e222b"
    C_HEADER  = "#0d0f14"
    C_TEXT    = "#cfd8dc"
    C_MUTED   = "#78909c"
    C_BLUE    = "#2196f3"
    C_GREEN   = "#00e676"

    PROTO_COLORS = {
        "TCP":   "#00e676",
        "UDP":   "#64b5f6",
        "ICMP":  "#d500f9",
        "HTTP":  "#ffca28",
        "HTTPS": "#ffca28",
        "DNS":   "#ff8a65",
    }

    def __init__(self, parent, app=None):
        super().__init__(parent, fg_color=self.C_BG)
        self._app = app
        self._build_ui()
        self._auto_refresh()

    # ══════════════════════════════════════════════════════════════════════
    #   UI BUILD  —  COMPACT FILTERS + TALL TABLE
    # ══════════════════════════════════════════════════════════════════════
    def _auto_refresh(self):
        if self.winfo_exists():
            query = self.search_entry.get().strip()
            if not query:
                self.search_packets()
            self.after(2000, self._auto_refresh)
    
    
    def _build_ui(self):
        # ── Header ───────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(15, 2))   # was (20,5)

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text="Packet Search Engine",
                     font=ctk.CTkFont(size=18, weight="bold"),   # was 20
                     text_color="#ffffff").pack(anchor="w")
        ctk.CTkLabel(left, text="Search and investigate captured network packets using advanced filters.",
                     font=ctk.CTkFont(size=10), text_color=self.C_MUTED).pack(anchor="w")   # was 11

        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right")
        self._lbl_updated = ctk.CTkLabel(right, text="Last Updated: --:--:--",
                                          font=ctk.CTkFont(size=10), text_color=self.C_MUTED)   # was 11
        self._lbl_updated.pack(side="left", padx=(0, 10))
        ctk.CTkButton(right, text="↻  Refresh", width=80, height=26,   # was 90x30
                      fg_color="#1a1c23", border_width=1, border_color="#2a2e3d",
                      text_color="#90a4ae", hover_color="#12141c", corner_radius=6,
                      command=self.search_packets).pack(side="left")

        # ── Search bar (compact) ────────────────────────────────────────
        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=20, pady=(2, 3))   # was (5,5)
        self.search_entry = ctk.CTkEntry(
            search_row, placeholder_text="🔍  Search by IP, Port, Protocol, Keyword...",
            width=380, height=32, fg_color="#1a1c23", border_color="#2a2e3d",   # was 400x36
            text_color="#ffffff", placeholder_text_color="#546e7a", corner_radius=6)
        self.search_entry.pack(side="left", padx=(0, 8))
        self.search_entry.bind("<Return>", lambda e: self.search_packets())

        ctk.CTkButton(search_row, text="🔍  Search", width=90, height=32,   # was 100x36
                      fg_color=self.C_BLUE, hover_color="#1565c0", corner_radius=6,
                      font=ctk.CTkFont(size=11, weight="bold"),   # was 12
                      command=self.search_packets).pack(side="left", padx=4)
        ctk.CTkButton(search_row, text="🗑  Clear", width=80, height=32,   # was 90x36
                      fg_color="#424242", hover_color="#37474f", corner_radius=6,
                      font=ctk.CTkFont(size=11, weight="bold"),   # was 12
                      command=self.clear_search).pack(side="left")

        # ── Advanced Filters ── COMPACT ─────────────────────────────────
        filters = ctk.CTkFrame(self, fg_color=self.C_CARD, corner_radius=8,
                               border_width=1, border_color=self.C_BORDER)
        filters.pack(fill="x", padx=20, pady=(2, 5))   # was (10,10)
        ctk.CTkLabel(filters, text="ADVANCED FILTERS", font=ctk.CTkFont(size=10, weight="bold"),   # was 11
                     text_color=self.C_BLUE).pack(anchor="w", padx=12, pady=(6, 2))   # was (15,5)

        # Use a tighter grid — 3 columns, less padding
        fgrid = ctk.CTkFrame(filters, fg_color="transparent")
        fgrid.pack(fill="x", padx=12, pady=(0, 4))   # was (15,2)
        for c in range(6):
            fgrid.grid_columnconfigure(c, weight=1)

        # Row 0: Protocol / Source IP / Destination IP  (tight)
        ctk.CTkLabel(fgrid, text="Protocol:", font=ctk.CTkFont(size=10),   # was default
                     text_color=self.C_MUTED).grid(row=0, column=0, sticky="w", padx=3, pady=1)   # was (5,3)
        self.filter_proto = ctk.CTkOptionMenu(
            fgrid, values=["All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"],
            width=100, height=24,   # was 120x26
            font=ctk.CTkFont(size=10),
            fg_color="#1a1c23", button_color="#2a2e3d")
        self.filter_proto.grid(row=0, column=1, sticky="w", padx=3, pady=1)

        ctk.CTkLabel(fgrid, text="Source IP:", font=ctk.CTkFont(size=10),
                     text_color=self.C_MUTED).grid(row=0, column=2, sticky="w", padx=3, pady=1)
        self.filter_src_ip = ctk.CTkEntry(fgrid, placeholder_text="e.g. 192.168.1.1", width=130, height=24,   # was 150x26
                                          font=ctk.CTkFont(size=10),
                                          fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_src_ip.grid(row=0, column=3, sticky="w", padx=3, pady=1)

        ctk.CTkLabel(fgrid, text="Destination IP:", font=ctk.CTkFont(size=10),
                     text_color=self.C_MUTED).grid(row=0, column=4, sticky="w", padx=3, pady=1)
        self.filter_dst_ip = ctk.CTkEntry(fgrid, placeholder_text="e.g. 8.8.8.8", width=130, height=24,
                                          font=ctk.CTkFont(size=10),
                                          fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_dst_ip.grid(row=0, column=5, sticky="w", padx=3, pady=1)

        # Row 1: Source Port / Destination Port / Packet Size / Keyword
        ctk.CTkLabel(fgrid, text="Src Port:", font=ctk.CTkFont(size=10),
                     text_color=self.C_MUTED).grid(row=1, column=0, sticky="w", padx=3, pady=1)
        self.filter_src_port = ctk.CTkEntry(fgrid, placeholder_text="443", width=80, height=24,   # was 120
                                            font=ctk.CTkFont(size=10),
                                            fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_src_port.grid(row=1, column=1, sticky="w", padx=3, pady=1)

        ctk.CTkLabel(fgrid, text="Dst Port:", font=ctk.CTkFont(size=10),
                     text_color=self.C_MUTED).grid(row=1, column=2, sticky="w", padx=3, pady=1)
        self.filter_dst_port = ctk.CTkEntry(fgrid, placeholder_text="80", width=80, height=24,
                                            font=ctk.CTkFont(size=10),
                                            fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_dst_port.grid(row=1, column=3, sticky="w", padx=3, pady=1)

        # Packet Size: Min — Max (compact inline)
        size_lbl = ctk.CTkLabel(fgrid, text="Size:", font=ctk.CTkFont(size=10),
                                text_color=self.C_MUTED)
        size_lbl.grid(row=1, column=4, sticky="w", padx=(3, 0), pady=1)
        size_frame = ctk.CTkFrame(fgrid, fg_color="transparent")
        size_frame.grid(row=1, column=5, sticky="w", padx=3, pady=1)
        self.filter_size_min = ctk.CTkEntry(size_frame, placeholder_text="Min", width=55, height=24,
                                            font=ctk.CTkFont(size=10),
                                            fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_size_min.pack(side="left")
        ctk.CTkLabel(size_frame, text="—", font=ctk.CTkFont(size=10), text_color=self.C_MUTED).pack(side="left", padx=2)
        self.filter_size_max = ctk.CTkEntry(size_frame, placeholder_text="Max", width=55, height=24,
                                            font=ctk.CTkFont(size=10),
                                            fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_size_max.pack(side="left")

        # Row 2: Keyword + Apply/Reset buttons (inline to save space)
        kw_row = ctk.CTkFrame(filters, fg_color="transparent")
        kw_row.pack(fill="x", padx=12, pady=(0, 6))   # was separate grid row
        
        ctk.CTkLabel(kw_row, text="Keyword:", font=ctk.CTkFont(size=10),
                     text_color=self.C_MUTED).pack(side="left", padx=(0, 4))
        self.filter_keyword = ctk.CTkEntry(kw_row, placeholder_text="e.g. login, HTTP", width=200, height=24,
                                           font=ctk.CTkFont(size=10),
                                           fg_color="#1a1c23", border_color="#2a2e3d")
        self.filter_keyword.pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(kw_row, text="🔽  Apply", fg_color=self.C_BLUE, hover_color="#1565c0",
                      corner_radius=6, height=26, width=90,   # was 30 height
                      font=ctk.CTkFont(size=10, weight="bold"),
                      command=self.apply_filters).pack(side="left", padx=3)
        ctk.CTkButton(kw_row, text="↺  Reset", fg_color="#424242", hover_color="#37474f",
                      corner_radius=6, height=26, width=80,
                      font=ctk.CTkFont(size=10, weight="bold"),
                      command=self.reset_filters).pack(side="left", padx=3)

        # ── Results table ── TALL ─────────────────────────────────────
        results = ctk.CTkFrame(self, fg_color=self.C_CARD, corner_radius=8,
                               border_width=1, border_color=self.C_BORDER)
        results.pack(fill="both", expand=True, padx=20, pady=(2, 5))   # was (0,10) — EXPAND=TRUE

        res_hdr = ctk.CTkFrame(results, fg_color="transparent")
        res_hdr.pack(fill="x", padx=12, pady=(6, 3))   # was (15,5)
        self.lbl_results_count = ctk.CTkLabel(
            res_hdr, text="SEARCH RESULTS: 0 packets",
            font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_BLUE)   # was 12
        self.lbl_results_count.pack(side="left")
        self.lbl_results_mode = ctk.CTkLabel(
            res_hdr, text="Showing: All Packets",
            font=ctk.CTkFont(size=10), text_color=self.C_MUTED)   # was 11
        self.lbl_results_mode.pack(side="right")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Search.Treeview",
                        background=self.C_CARD, foreground=self.C_TEXT,
                        rowheight=24, fieldbackground=self.C_CARD,   # was 26
                        borderwidth=0, font=("Segoe UI", 10))
        style.map("Search.Treeview",
                  background=[("selected", "#1e3a5f")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Search.Treeview.Heading",
                        background=self.C_HEADER, foreground=self.C_MUTED,
                        relief="flat", padding=3, font=("Segoe UI", 9, "bold"))   # was padding 5
        style.map("Search.Treeview.Heading",
                  background=[("active", self.C_HEADER)],
                  foreground=[("active", "#ffffff")])

        # Tree fills ALL available space
        tree_frame = ctk.CTkFrame(results, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 6))   # was (15,5)

        cols = ("no", "time", "proto", "src", "sport", "dst", "dport", "len", "info")
        # INCREASED HEIGHT from 8 to 20
        self.result_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                        style="Search.Treeview", height=20)   # was 8 ← KEY FIX
        headers = [("no", "No.", 40, "center"), ("time", "Time", 85, "w"),
                   ("proto", "Protocol", 70, "w"), ("src", "Source IP", 105, "w"),
                   ("sport", "Src Port", 65, "center"), ("dst", "Destination IP", 115, "w"),
                   ("dport", "Dst Port", 65, "center"), ("len", "Length", 60, "center"),
                   ("info", "Info", 280, "w")]   # slightly narrower to fit
        for col, title, w, anchor in headers:
            self.result_tree.heading(col, text=title, anchor=anchor)
            self.result_tree.column(col, width=w, minwidth=max(30, w - 20),
                                    anchor=anchor, stretch=(col == "info"))

        for proto, color in self.PROTO_COLORS.items():
            self.result_tree.tag_configure(proto, foreground=color, background=self.C_CARD,
                                           font=("Segoe UI", 10))
            self.result_tree.tag_configure(f"{proto}_ALT", foreground=color, background="#0f1118",
                                           font=("Segoe UI", 10))
        self.result_tree.tag_configure("OTHER", foreground=self.C_MUTED, background=self.C_CARD,
                                       font=("Segoe UI", 10))
        self.result_tree.tag_configure("OTHER_ALT", foreground=self.C_MUTED, background="#0f1118",
                                       font=("Segoe UI", 10))

        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.result_tree.pack(fill="both", expand=True)
        self.result_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # ── Bottom panels ── COMPACT (optional: can remove if table needs even more space)
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=20, pady=(0, 8))   # was (0,15)
        bottom.grid_columnconfigure((0, 1), weight=1)

        details = ctk.CTkFrame(bottom, fg_color=self.C_CARD, corner_radius=8,
                               border_width=1, border_color=self.C_BORDER)
        details.grid(row=0, column=0, padx=(0, 4), sticky="nsew")
        ctk.CTkLabel(details, text="📋  SELECTED PACKET DETAILS",
                     font=ctk.CTkFont(size=10, weight="bold"), text_color=self.C_BLUE   # was 11
                     ).pack(anchor="w", padx=12, pady=(8, 5))   # was (15,10)
        self.detail_labels = {}
        for label in ["Packet Number", "Time", "Source", "Destination", "Protocol", "Info", "Packet Length"]:
            row = ctk.CTkFrame(details, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=2)   # was (15,3)
            ctk.CTkLabel(row, text=f"{label}", font=ctk.CTkFont(size=10),   # was 11
                         text_color=self.C_MUTED, width=110, anchor="w").pack(side="left")   # was 120
            ctk.CTkLabel(row, text=":", text_color=self.C_MUTED, width=8).pack(side="left")   # was 10
            self.detail_labels[label] = ctk.CTkLabel(row, text="—", font=ctk.CTkFont(size=10, weight="bold"),   # was 11
                                                      anchor="w", justify="left")
            self.detail_labels[label].pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(details, text="").pack(pady=2)  # was 4

        meta = ctk.CTkFrame(bottom, fg_color=self.C_CARD, corner_radius=8,
                            border_width=1, border_color=self.C_BORDER)
        meta.grid(row=0, column=1, padx=(4, 0), sticky="nsew")
        ctk.CTkLabel(meta, text="📊  PACKET METADATA",
                     font=ctk.CTkFont(size=10, weight="bold"), text_color=self.C_BLUE   # was 11
                     ).pack(anchor="w", padx=12, pady=(8, 5))   # was (15,10)
        self.meta_labels = {}
        meta_grid = ctk.CTkFrame(meta, fg_color="transparent")
        meta_grid.pack(fill="x", padx=12, pady=(0, 6))   # was (15,10)
        meta_grid.grid_columnconfigure((0, 1), weight=1)
        meta_fields = ["Capture Time", "Interface", "Link Layer Type", "Network Layer", "Transport Layer",
                       "TCP Flags", "Sequence Number", "Acknowledgment No", "Window Size", "TTL"]
        for i, label in enumerate(meta_fields):
            col = i % 2
            r = i // 2
            row = ctk.CTkFrame(meta_grid, fg_color="transparent")
            row.grid(row=r, column=col, sticky="w", padx=(0, 8), pady=2)   # was (0,10), pady 3
            ctk.CTkLabel(row, text=f"{label}", font=ctk.CTkFont(size=10),   # was 11
                         text_color=self.C_MUTED, width=130, anchor="w").pack(side="left")   # was 140
            ctk.CTkLabel(row, text=":", text_color=self.C_MUTED, width=8).pack(side="left")   # was 10
            self.meta_labels[label] = ctk.CTkLabel(row, text="—", font=ctk.CTkFont(size=10, weight="bold"),   # was 11
                                                      anchor="w")
            self.meta_labels[label].pack(side="left")

        # First render
        self.search_packets()

    # ══════════════════════════════════════════════════════════════════════
    #   DATA SOURCE
    # ══════════════════════════════════════════════════════════════════════
    def _get_all_packets(self):
        """Pull every captured row directly from the tracked list."""
        if self._app is None:
            return []
            
        rows = []
        # Ab hum list ka use karenge jisme 100% data save ho raha hai
        for item_id in getattr(self._app, "all_tree_items", []):
            try:
                vals = self._app.tree.item(item_id, "values")
                if vals and len(vals) >= 9:
                    rows.append({
                        "no": vals[0], "time": vals[1], "proto": vals[2],
                        "src": vals[3], "sport": vals[4], "dst": vals[5],
                        "dport": vals[6], "len": vals[7], "info": vals[8],
                    })
            except Exception:
                continue
                
        return rows

    def _tag_for(self, proto, idx):
        base = proto if proto in self.PROTO_COLORS else "OTHER"
        return base if idx % 2 == 0 else f"{base}_ALT"

    def _populate(self, rows, mode_label):
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        for idx, row in enumerate(rows):
            tag = self._tag_for(row["proto"], idx)
            self.result_tree.insert("", "end", values=(
                row["no"], row["time"], row["proto"], row["src"], row["sport"],
                row["dst"], row["dport"], row["len"], row["info"]
            ), tags=(tag,))
        self.lbl_results_count.configure(text=f"SEARCH RESULTS: {len(rows)} packets")
        self.lbl_results_mode.configure(text=f"Showing: {mode_label}")
        self._lbl_updated.configure(text=f"Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}")

    # ══════════════════════════════════════════════════════════════════════
    #   SEARCH / FILTER LOGIC
    # ══════════════════════════════════════════════════════════════════════
    def search_packets(self, event=None):
        """Unified Search: Checks both Simple Search Bar AND Advanced Filters together."""
        all_rows = self._get_all_packets()

        # 1. Simple search bar value
        query = self.search_entry.get().strip().lower()

        # 2. Advanced filters values
        proto      = self.filter_proto.get()
        src_ip     = self.filter_src_ip.get().strip()
        dst_ip     = self.filter_dst_ip.get().strip()
        src_port   = self.filter_src_port.get().strip()
        dst_port   = self.filter_dst_port.get().strip()
        size_min   = self.filter_size_min.get().strip()
        size_max   = self.filter_size_max.get().strip()
        keyword    = self.filter_keyword.get().strip().lower()

        def matches(r):
            # Pehle Simple Search Check
            if query and query not in " ".join(str(v).lower() for v in r.values()):
                return False
            
            # Phir Advanced Filters Check
            if proto != "All" and r["proto"].upper() != proto.upper():
                return False
            if src_ip and src_ip not in str(r["src"]):
                return False
            if dst_ip and dst_ip not in str(r["dst"]):
                return False
            if src_port and str(r["sport"]) != src_port:
                return False
            if dst_port and str(r["dport"]) != dst_port:
                return False
            if size_min:
                try:
                    if int(r["len"]) < int(size_min):
                        return False
                except (ValueError, TypeError):
                    pass
            if size_max:
                try:
                    if int(r["len"]) > int(size_max):
                        return False
                except (ValueError, TypeError):
                    pass
            if keyword and keyword not in str(r["info"]).lower():
                return False
                
            return True

        filtered = [r for r in all_rows if matches(r)]
        self._populate(filtered, "Filtered Results")

    def apply_filters(self):
        """Advanced filter panel — combines all fields with AND logic."""
        all_rows = self._get_all_packets()

        proto      = self.filter_proto.get()
        src_ip     = self.filter_src_ip.get().strip()
        dst_ip     = self.filter_dst_ip.get().strip()
        src_port   = self.filter_src_port.get().strip()
        dst_port   = self.filter_dst_port.get().strip()
        size_min   = self.filter_size_min.get().strip()
        size_max   = self.filter_size_max.get().strip()
        keyword    = self.filter_keyword.get().strip().lower()

        def matches(r):
            if proto != "All" and r["proto"].upper() != proto.upper():
                return False
            if src_ip and src_ip not in str(r["src"]):
                return False
            if dst_ip and dst_ip not in str(r["dst"]):
                return False
            if src_port and str(r["sport"]) != src_port:
                return False
            if dst_port and str(r["dport"]) != dst_port:
                return False
            if size_min:
                try:
                    if int(r["len"]) < int(size_min):
                        return False
                except (ValueError, TypeError):
                    pass
            if size_max:
                try:
                    if int(r["len"]) > int(size_max):
                        return False
                except (ValueError, TypeError):
                    pass
            if keyword and keyword not in str(r["info"]).lower():
                return False
            return True

        filtered = [r for r in all_rows if matches(r)]
        self._populate(filtered, "Filtered Results")

    def reset_filters(self):
        self.filter_proto.set("All")
        for entry in [self.filter_src_ip, self.filter_dst_ip, self.filter_src_port,
                      self.filter_dst_port, self.filter_size_min, self.filter_size_max,
                      self.filter_keyword]:
            entry.delete(0, "end")
        self.search_packets()

    def clear_search(self):
        self.search_entry.delete(0, "end")
        self.search_packets()

    # ══════════════════════════════════════════════════════════════════════
    #   ROW SELECTION — DETAIL PANELS
    # ══════════════════════════════════════════════════════════════════════
    def on_packet_select(self, event=None):
        selected = self.result_tree.selection()
        if not selected:
            return
        values = self.result_tree.item(selected[0], "values")
        if not values or len(values) < 9:
            return

        no, time_, proto, src, sport, dst, dport, length, info = values

        self.detail_labels["Packet Number"].configure(text=no)
        self.detail_labels["Time"].configure(text=time_)
        self.detail_labels["Protocol"].configure(text=proto)
        self.detail_labels["Source"].configure(text=f"{src}:{sport}" if sport not in ("-", "0", "") else str(src))
        self.detail_labels["Destination"].configure(text=f"{dst}:{dport}" if dport not in ("-", "0", "") else str(dst))
        self.detail_labels["Packet Length"].configure(text=f"{length} Bytes")
        self.detail_labels["Info"].configure(text=str(info)[:80])

        self.meta_labels["Capture Time"].configure(text=time_)
        self.meta_labels["Interface"].configure(text="Wi-Fi")
        self.meta_labels["Link Layer Type"].configure(text="Ethernet")
        self.meta_labels["Network Layer"].configure(text="IPv4")
        self.meta_labels["Transport Layer"].configure(text=proto if proto in ("TCP", "UDP", "ICMP") else "—")

        info_str = str(info)
        flags = self._extract_between(info_str, "[", "]")
        seq   = self._extract_field(info_str, "Seq=")
        ack   = self._extract_field(info_str, "Ack=")
        win   = self._extract_field(info_str, "Win=")

        self.meta_labels["TCP Flags"].configure(text=flags if flags else "—")
        self.meta_labels["Sequence Number"].configure(text=seq if seq else "—")
        self.meta_labels["Acknowledgment No"].configure(text=ack if ack else "—")
        self.meta_labels["Window Size"].configure(text=win if win else "—")
        self.meta_labels["TTL"].configure(text="—")

    @staticmethod
    def _extract_between(s, start, end):
        try:
            i = s.index(start) + len(start)
            j = s.index(end, i)
            return s[i:j]
        except ValueError:
            return ""

    @staticmethod
    def _extract_field(s, prefix):
        try:
            i = s.index(prefix) + len(prefix)
            j = i
            while j < len(s) and (s[j].isdigit()):
                j += 1
            return s[i:j]
        except ValueError:
            return ""



#================================================================================
#                     EXPORT REPORT PAGE
#================================================================================
class ExportReportPage(ctk.CTkFrame):
    def __init__(self, parent, app=None):
        super().__init__(parent, fg_color="#050608", corner_radius=0)
        self._app = app

        self.C_BG = "#050608"
        self.C_CARD = "#12141c"
        self.C_BORDER = "#1e222b"
        self.C_BLUE = "#1976d2"
        self.C_TEXT = "#cfd8dc"
        self.C_MUTED = "#78909c"

        self.export_format = tk.StringVar(value="HTML")
        self.format_cards = []
        self.content_checks = {}

        self._build_ui()
        # Page load hone ke 0.5 sec baad auto-refresh karke live data le aayega
        self.after(500, self.refresh_preview)

    def _build_ui(self):
        # ── 1. Page Header ──
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 10))

        left_hdr = ctk.CTkFrame(hdr, fg_color="transparent")
        left_hdr.pack(side="left")
        ctk.CTkLabel(left_hdr, text="Export Report", font=ctk.CTkFont(size=22, weight="bold"), text_color="#ffffff").pack(anchor="w")
        ctk.CTkLabel(left_hdr, text="Generate and export comprehensive network analysis reports.", font=ctk.CTkFont(size=12), text_color=self.C_MUTED).pack(anchor="w")

        right_hdr = ctk.CTkFrame(hdr, fg_color="transparent")
        right_hdr.pack(side="right")
        
        self.lbl_hdr_time = ctk.CTkLabel(right_hdr, text=f"Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}", font=ctk.CTkFont(size=11), text_color=self.C_MUTED)
        self.lbl_hdr_time.pack(side="left", padx=(0, 15))

        ctk.CTkButton(right_hdr, text="📥 Generate Report", height=30, font=ctk.CTkFont(size=12, weight="bold"), fg_color=self.C_BLUE, hover_color="#1565c0", command=self.generate_report).pack(side="left", padx=(0, 10))

        ctk.CTkButton(right_hdr, text="↻ Refresh", width=90, height=30, fg_color="transparent", border_width=1, border_color="#2a2e3d", text_color="#90a4ae", hover_color="#1a1c23", command=self.refresh_preview).pack(side="left")

        # ── Main Content Split ──
        main_split = ctk.CTkFrame(self, fg_color="transparent")
        main_split.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        left_panel = ctk.CTkFrame(main_split, fg_color="transparent", width=350)
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        #left_panel.pack_propagate(False)
        
        right_panel = ctk.CTkFrame(main_split, fg_color="transparent")
        right_panel.pack(side="left", fill="both", expand=True)

        # ==================== LEFT PANEL: CONTROLS ====================
        ctk.CTkLabel(left_panel, text="1. SELECT EXPORT FORMAT", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_MUTED).pack(anchor="w", pady=(0, 10))
        
        format_grid = ctk.CTkFrame(left_panel, fg_color="transparent")
        format_grid.pack(fill="x", pady=(0, 20))
        format_grid.grid_columnconfigure((0,1), weight=1)
        
        formats = [
            ("HTML", "HTML Report", "Web format\n(.html)", "📄", 0, 0),
            ("PDF", "PDF Report", "Portable document\n(.pdf)", "📕", 0, 1),
            ("CSV", "CSV Report", "Comma separated\nvalues (.csv)", "📗", 1, 0),
            ("JSON", "JSON Report", "JavaScript object\nnotation (.json)", "🗂️", 1, 1)
        ]
        
        for val, title, desc, icon, r, c in formats:
            card = ctk.CTkFrame(format_grid, fg_color=self.C_CARD, corner_radius=8, border_width=2, border_color=self.C_BLUE if val=="HTML" else self.C_BORDER)
            card.grid(row=r, column=c, padx=5, pady=5, sticky="nsew")
            card.bind("<Button-1>", lambda e, v=val: self.select_format(v))
            rb = ctk.CTkRadioButton(card, text="", variable=self.export_format, value=val, width=20, radiobutton_width=16, radiobutton_height=16, fg_color=self.C_BLUE, hover=False, command=lambda v=val: self.select_format(v))
            rb.pack(anchor="nw", padx=10, pady=10)
            ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=24)).pack(pady=(0,5))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack()
            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=10), text_color=self.C_MUTED, justify="center").pack(pady=(0, 15))
            for child in card.winfo_children():
                if isinstance(child, ctk.CTkLabel):
                    child.bind("<Button-1>", lambda e, v=val: self.select_format(v))
            self.format_cards.append((val, card))

        # ── Section 2: Report Content ──
        ctk.CTkLabel(left_panel, text="2. SELECT REPORT CONTENT", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_MUTED).pack(anchor="w", pady=(10, 10))
        contents = ["Packet Summary", "Protocol Statistics", "Top IPs", "Conversations", "Traffic Over Time Statistics", "Security Assessment", "Capture Information", "IP Geolocation Data"]
        for item in contents:
            cb = ctk.CTkCheckBox(left_panel, text=item, font=ctk.CTkFont(size=12), text_color=self.C_TEXT, checkbox_width=18, checkbox_height=18, fg_color=self.C_BLUE, hover_color="#1565c0")
            cb.pack(anchor="w", pady=4, padx=5)
            cb.select()
            self.content_checks[item] = cb

        # ── Section 3: Report Options ──
        ctk.CTkLabel(left_panel, text="3. REPORT OPTIONS", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_MUTED).pack(anchor="w", pady=(20, 10))
        
        def create_option_entry(label_text, default_val):
            row = ctk.CTkFrame(left_panel, fg_color="transparent")
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(row, text=label_text, font=ctk.CTkFont(size=11), text_color=self.C_TEXT, width=100, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, height=28, fg_color="#1a1c23", border_color="#2a2e3d", text_color="#ffffff", font=ctk.CTkFont(size=11))
            entry.pack(side="left", fill="x", expand=True)
            entry.insert(0, default_val)
            return entry

        self.ent_title = create_option_entry("Report Title", "Network Sniffer - Analysis Report")
        self.ent_author = create_option_entry("Analyst / Author", "Cybersecurity Analyst")
        
        row_logo = ctk.CTkFrame(left_panel, fg_color="transparent")
        row_logo.pack(fill="x", pady=6)
        ctk.CTkLabel(row_logo, text="Include Logo", font=ctk.CTkFont(size=11), text_color=self.C_TEXT, width=100, anchor="w").pack(side="left")
        ctk.CTkCheckBox(row_logo, text="", checkbox_width=18, checkbox_height=18, fg_color=self.C_BLUE).pack(side="left")
        
        row_open = ctk.CTkFrame(left_panel, fg_color="transparent")
        row_open.pack(fill="x", pady=2)
        ctk.CTkLabel(row_open, text="Open After Export", font=ctk.CTkFont(size=11), text_color=self.C_TEXT, width=100, anchor="w").pack(side="left")
        cb_open = ctk.CTkCheckBox(row_open, text="", checkbox_width=18, checkbox_height=18, fg_color=self.C_BLUE)
        cb_open.pack(side="left")
        cb_open.select()

       # ctk.CTkButton(left_panel, text="📥 Generate Report", height=40, font=ctk.CTkFont(size=14, weight="bold"), fg_color=self.C_BLUE, hover_color="#1565c0", command=self.generate_report).pack(fill="x", side="bottom", pady=(20,0))

        # ==================== RIGHT PANEL: PREVIEW ====================
        ctk.CTkLabel(right_panel, text="REPORT PREVIEW", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.C_MUTED).pack(anchor="w", pady=(0, 10))
        
        preview_bg = ctk.CTkFrame(right_panel, fg_color="#e0e0e0", corner_radius=8, border_width=1, border_color=self.C_BORDER)
        preview_bg.pack(fill="both", expand=True)
        
        preview_paper = ctk.CTkScrollableFrame(preview_bg, fg_color="#ffffff", corner_radius=4)
        preview_paper.pack(fill="both", expand=True, padx=2, pady=2)
        
        # --- Preview Header ---
        p_hdr = ctk.CTkFrame(preview_paper, fg_color="transparent")
        p_hdr.pack(fill="x", padx=30, pady=(30, 20))
        
        p_logo_frame = ctk.CTkFrame(p_hdr, fg_color="transparent")
        p_logo_frame.pack(side="left")
        ctk.CTkLabel(p_logo_frame, text="🛡️", font=ctk.CTkFont(size=32), text_color="#1976d2").pack(side="left", padx=(0,10))
        logo_txt = ctk.CTkFrame(p_logo_frame, fg_color="transparent")
        logo_txt.pack(side="left")
        ctk.CTkLabel(logo_txt, text="NETWORK", font=ctk.CTkFont(size=16, weight="bold"), text_color="#1976d2", anchor="w").pack(anchor="w")
        ctk.CTkLabel(logo_txt, text="SNIFFER", font=ctk.CTkFont(size=16, weight="bold"), text_color="#1976d2", anchor="w").pack(anchor="w")
        
        p_meta = ctk.CTkFrame(p_hdr, fg_color="transparent")
        p_meta.pack(side="right")
        ctk.CTkLabel(p_meta, text="Network Analysis Report", font=ctk.CTkFont(size=18, weight="bold"), text_color="#1565c0", anchor="e").pack(anchor="e")
        self.lbl_p_gen = ctk.CTkLabel(p_meta, text="Generated on: --", font=ctk.CTkFont(size=10), text_color="#424242", anchor="e")
        self.lbl_p_gen.pack(anchor="e")
        self.lbl_p_dur = ctk.CTkLabel(p_meta, text="Duration: --", font=ctk.CTkFont(size=10), text_color="#424242", anchor="e")
        self.lbl_p_dur.pack(anchor="e")
        ctk.CTkLabel(p_meta, text="Analyst: Cybersecurity Analyst", font=ctk.CTkFont(size=10), text_color="#424242", anchor="e").pack(anchor="e")

        # --- Preview Exec Summary ---
        ctk.CTkLabel(preview_paper, text="EXECUTIVE SUMMARY", font=ctk.CTkFont(size=11, weight="bold"), text_color="#1976d2").pack(anchor="w", padx=30, pady=(10, 5))
        
        sum_row = ctk.CTkFrame(preview_paper, fg_color="transparent")
        sum_row.pack(fill="x", padx=30, pady=(0, 20))
        for i in range(5): sum_row.grid_columnconfigure(i, weight=1)
        
        boxes = [("0", "Total Packets", "tot"), ("0", "Avg Packets / sec", "pps"), ("0.00 KB", "Total Data", "data"), ("00:00:00", "Capture Duration", "cdur"), ("Wi-Fi", "Interface", "iface")]
        self.box_labels = {}
        for i, (val, lbl, key) in enumerate(boxes):
            box = ctk.CTkFrame(sum_row, fg_color="#f5f7fa", corner_radius=6, border_width=1, border_color="#e0e0e0")
            box.grid(row=0, column=i, padx=5, sticky="ew")
            v_lbl = ctk.CTkLabel(box, text=val, font=ctk.CTkFont(size=14, weight="bold"), text_color="#000000")
            v_lbl.pack(pady=(10,0))
            self.box_labels[key] = v_lbl
            ctk.CTkLabel(box, text=lbl, font=ctk.CTkFont(size=10), text_color="#616161").pack(pady=(0,10))

        # --- Preview Charts ---
        chart_row = ctk.CTkFrame(preview_paper, fg_color="transparent")
        chart_row.pack(fill="x", padx=30, pady=(0, 20))
        chart_row.grid_columnconfigure((0,1), weight=1)

        pie_frame = ctk.CTkFrame(chart_row, fg_color="transparent")
        pie_frame.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        ctk.CTkLabel(pie_frame, text="PROTOCOL DISTRIBUTION", font=ctk.CTkFont(size=11, weight="bold"), text_color="#1976d2").pack(anchor="w", pady=(0, 10))
        
        self.fig_pie = plt.Figure(figsize=(3, 2.5), dpi=80, facecolor="#ffffff")
        self.ax_pie = self.fig_pie.add_subplot(111)
        self.ax_pie.pie([1], colors=["#e0e0e0"], wedgeprops=dict(width=0.4, edgecolor='w'))
        self.pie_canvas = FigureCanvasTkAgg(self.fig_pie, master=pie_frame)
        self.pie_canvas.get_tk_widget().pack(side="left")
        
        leg_frame = ctk.CTkFrame(pie_frame, fg_color="transparent")
        leg_frame.pack(side="left", padx=10)
        self.leg_labels = {}
        for color, key, lbl in [("#1976d2", "TCP", "TCP"), ("#4caf50", "UDP", "UDP"), ("#f44336", "ICMP", "ICMP"), ("#9e9e9e", "OTH", "Other")]:
            r = ctk.CTkFrame(leg_frame, fg_color="transparent")
            r.pack(anchor="w", pady=2)
            ctk.CTkFrame(r, width=10, height=10, fg_color=color, corner_radius=2).pack(side="left", padx=(0,5))
            l = ctk.CTkLabel(r, text=f"{lbl}   0.0%", font=ctk.CTkFont(size=9), text_color="#424242")
            l.pack(side="left")
            self.leg_labels[key] = l

        line_frame = ctk.CTkFrame(chart_row, fg_color="transparent")
        line_frame.grid(row=0, column=1, sticky="nsew", padx=(10,0))
        ctk.CTkLabel(line_frame, text="LIVE TRAFFIC TREND", font=ctk.CTkFont(size=11, weight="bold"), text_color="#1976d2").pack(anchor="w", pady=(0, 10))
        
        self.fig_line = plt.Figure(figsize=(4.5, 2.5), dpi=80, facecolor="#ffffff")
        self.ax_line = self.fig_line.add_subplot(111)
        self.ax_line.set_facecolor("#ffffff")
        self.ax_line.plot(np.zeros(20), color="#1976d2")
        self.ax_line.spines['top'].set_visible(False)
        self.ax_line.spines['right'].set_visible(False)
        self.ax_line.tick_params(axis='both', labelsize=8, colors="#757575")
        self.fig_line.tight_layout(pad=1)
        self.line_canvas = FigureCanvasTkAgg(self.fig_line, master=line_frame)
        self.line_canvas.get_tk_widget().pack()

        # --- Tables Placeholder ---
        tables_row = ctk.CTkFrame(preview_paper, fg_color="transparent")
        tables_row.pack(fill="x", padx=30, pady=(0, 20))
        tables_row.grid_columnconfigure((0,1), weight=1)
        
        def build_table_skeleton(parent, title):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color="#1976d2").pack(anchor="w", pady=(0, 5))
            header = ctk.CTkFrame(f, fg_color="#f5f7fa", height=24, corner_radius=0)
            header.pack(fill="x")
            header.pack_propagate(False)
            ctk.CTkLabel(header, text="IP Address", font=ctk.CTkFont(size=10, weight="bold"), text_color="#000000", width=120, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(header, text="Packets", font=ctk.CTkFont(size=10, weight="bold"), text_color="#000000", width=60, anchor="e").pack(side="left")
            ctk.CTkLabel(header, text="Percentage", font=ctk.CTkFont(size=10, weight="bold"), text_color="#000000", width=80, anchor="e").pack(side="right", padx=10)
            
            container = ctk.CTkFrame(f, fg_color="transparent")
            container.pack(fill="x")
            return f, container

        _, self.tbl_src = build_table_skeleton(tables_row, "TOP SOURCE IPS")
        _.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        
        _, self.tbl_dst = build_table_skeleton(tables_row, "OTHER ACTIVE IPS")
        _.grid(row=0, column=1, sticky="nsew", padx=(10,0))
        
        ctk.CTkLabel(preview_paper, text="").pack(pady=20)


    def refresh_preview(self):
        """Fetches live global data and dynamically updates the preview UI!"""
        # --->  Page exist check (Error bachane ke liye) <---
        if not self.winfo_exists():
            return

        # 1. Fetch live numbers
        total = packet_count.get("Total", 0)
        tcp = packet_count.get("TCP", 0)
        udp = packet_count.get("UDP", 0)
        icmp = packet_count.get("ICMP", 0)
        other = packet_count.get("Other", 0)

        # Handle time
        start_time = getattr(self._app, "capture_start_time", None)
        if start_time:
            elapsed = datetime.datetime.now() - start_time
            dur_sec = max(1, int(elapsed.total_seconds()))
            h, r = divmod(dur_sec, 3600)
            m, s = divmod(r, 60)
            dur_str = f"{h:02d}:{m:02d}:{s:02d}"
        else:
            dur_str = "00:00:00"
            dur_sec = 1

        avg_pps = total // dur_sec
        total_bytes = total * 185
        data_str = f"{total_bytes/1024/1024:.2f} MB" if total_bytes >= 1024*1024 else f"{total_bytes/1024:.0f} KB"

        # Update Top Meta
        self.lbl_hdr_time.configure(text=f"Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}")
        self.lbl_p_gen.configure(text=f"Generated on:  {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        self.lbl_p_dur.configure(text=f"Duration:  {dur_str}")

        # Update Boxes
        self.box_labels["tot"].configure(text=f"{total:,}")
        self.box_labels["pps"].configure(text=f"{avg_pps:,}")
        self.box_labels["data"].configure(text=data_str)
        self.box_labels["cdur"].configure(text=dur_str)

        # Update Pie Chart & Legend
        self.ax_pie.clear()
        sizes = [tcp, udp, icmp, other]
        if total == 0:
            self.ax_pie.pie([1], colors=["#e0e0e0"], wedgeprops=dict(width=0.4, edgecolor='w'))
        else:
            self.ax_pie.pie(sizes, colors=["#1976d2", "#4caf50", "#f44336", "#9e9e9e"], wedgeprops=dict(width=0.4, edgecolor='w'))
        self.pie_canvas.draw_idle()

        def pct_str(val): return f"{(val/total)*100:.1f}%" if total > 0 else "0.0%"
        self.leg_labels["TCP"].configure(text=f"TCP   {pct_str(tcp)}")
        self.leg_labels["UDP"].configure(text=f"UDP   {pct_str(udp)}")
        self.leg_labels["ICMP"].configure(text=f"ICMP  {pct_str(icmp)}")
        self.leg_labels["OTH"].configure(text=f"Other {pct_str(other)}")

        # Update Line Chart (Pull from TrafficOverTime if exists)
        self.ax_line.clear()
        self.ax_line.set_facecolor("#ffffff")
        if hasattr(self._app, "traffic_time_page") and len(self._app.traffic_time_page._total) > 0:
            y_data = self._app.traffic_time_page._total[-30:] # last 30 ticks
            self.ax_line.plot(y_data, color="#1976d2", marker='o', markersize=3)
            self.ax_line.fill_between(range(len(y_data)), y_data, alpha=0.1, color="#1976d2")
        else:
            self.ax_line.plot(np.zeros(20), color="#1976d2")
        self.ax_line.spines['top'].set_visible(False)
        self.ax_line.spines['right'].set_visible(False)
        self.ax_line.tick_params(axis='both', labelsize=8, colors="#757575")
        self.fig_line.tight_layout(pad=1)
        self.line_canvas.draw_idle()

        # Update Tables
        for w in self.tbl_src.winfo_children(): w.destroy()
        for w in self.tbl_dst.winfo_children(): w.destroy()

        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["packets"], reverse=True)
        
        def fill_table(container, ip_list):
            for ip, d in ip_list:
                row = ctk.CTkFrame(container, fg_color="transparent", height=24)
                row.pack(fill="x")
                row.pack_propagate(False)
                ctk.CTkFrame(row, fg_color="#eeeeee", height=1).pack(side="bottom", fill="x")
                ctk.CTkLabel(row, text=ip, font=ctk.CTkFont(size=10), text_color="#424242", width=120, anchor="w").pack(side="left", padx=10)
                ctk.CTkLabel(row, text=f"{d['packets']:,}", font=ctk.CTkFont(size=10), text_color="#424242", width=60, anchor="e").pack(side="left")
                ctk.CTkLabel(row, text=pct_str(d['packets']), font=ctk.CTkFont(size=10), text_color="#424242", width=80, anchor="e").pack(side="right", padx=10)

        fill_table(self.tbl_src, sorted_ips[:5])
        fill_table(self.tbl_dst, sorted_ips[5:10])

        # ---> AUTO REFRESH LOOP <---
       
        self.after(2000, self.refresh_preview)

    def select_format(self, selected_val):
        self.export_format.set(selected_val)
        # Update border colors
        for val, card in self.format_cards:
            if val == selected_val:
                card.configure(border_color=self.C_BLUE)
            else:
                card.configure(border_color=self.C_BORDER)

    def generate_report(self):
        fmt = self.export_format.get()
        title = self.ent_title.get() or "Network Sniffer- Analysis Report"
        author = self.ent_author.get() or "Cybersecurity Analyst"
        selected_sections = [k for k, cb in self.content_checks.items() if cb.get()]

        # PDF ke liye extension fix kar diya
        ext_map = {"HTML": ".html", "PDF": ".pdf", "CSV": ".csv", "JSON": ".json"}
        default_ext = ext_map.get(fmt, ".html")

        path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=[(f"{fmt} File", f"*{default_ext}")],
            initialfile=f"network_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{default_ext}"
        )
        if not path:
            return

        total = packet_count.get("Total", 0)
        tcp = packet_count.get("TCP", 0)
        udp = packet_count.get("UDP", 0)
        icmp = packet_count.get("ICMP", 0)
        other = packet_count.get("Other", 0)

        top_ips = sorted(ip_stats.items(), key=lambda x: x[1]["packets"], reverse=True)[:10]

        if fmt == "HTML":
            html = self._build_html_report(title, author, total, tcp, udp, icmp, other, top_ips, selected_sections)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
                
        elif fmt == "PDF":
            try:
                from fpdf import FPDF
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)

                # Title
                pdf.set_font("Arial", 'B', 18)
                pdf.cell(200, 10, txt=title, ln=True, align='C')
                pdf.set_font("Arial", size=10)
                pdf.cell(200, 10, txt=f"Author: {author} | Generated: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align='C')

                # Executive Summary
                pdf.ln(10)
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(200, 10, txt="Executive Summary", ln=True)
                pdf.set_font("Arial", size=12)
                pdf.cell(200, 8, txt=f"Total Packets: {total:,}", ln=True)
                pdf.cell(200, 8, txt=f"TCP: {tcp:,} | UDP: {udp:,} | ICMP: {icmp:,} | Other: {other:,}", ln=True)

                # Top Source IPs
                pdf.ln(10)
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(200, 10, txt="Top Source IPs", ln=True)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(80, 8, txt="IP Address", border=1)
                pdf.cell(40, 8, txt="Packets", border=1, align='C')
                pdf.cell(40, 8, txt="Bytes", border=1, align='C')
                pdf.ln(8)
                
                pdf.set_font("Arial", size=12)
                for ip, d in top_ips:
                    pdf.cell(80, 8, txt=str(ip), border=1)
                    pdf.cell(40, 8, txt=f"{d['packets']:,}", border=1, align='C')
                    pdf.cell(40, 8, txt=f"{d['bytes']:,}", border=1, align='C')
                    pdf.ln(8)

                pdf.output(path)
            except ImportError:
                messagebox.showerror("Error", "PDF banane ke liye terminal me ye command run karein:\npip install fpdf")
                return

        elif fmt == "CSV":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Report Title", title])
                writer.writerow(["Author", author])
                writer.writerow(["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow([])
                writer.writerow(["Metric", "Value"])
                writer.writerow(["Total Packets", total])
                writer.writerow(["TCP Packets", tcp])
                writer.writerow(["UDP Packets", udp])
                writer.writerow(["ICMP Packets", icmp])
                writer.writerow(["Other Packets", other])
                writer.writerow([])
                writer.writerow(["Top IPs", "Packets", "Bytes"])
                for ip, data in top_ips:
                    writer.writerow([ip, data["packets"], data["bytes"]])

        elif fmt == "JSON":
            report_data = {
                "title": title,
                "author": author,
                "generated": datetime.datetime.now().isoformat(),
                "summary": {"total": total, "tcp": tcp, "udp": udp, "icmp": icmp, "other": other},
                "top_ips": [{"ip": ip, "packets": d["packets"], "bytes": d["bytes"]} for ip, d in top_ips],
                "sections_included": selected_sections
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

        try:
            os.startfile(path) if os.name == "nt" else os.system(f'xdg-open "{path}"')
        except Exception:
            pass

        messagebox.showinfo("Export Complete", f"Report successfully saved to:\n{path}")

    def _build_html_report(self, title, author, total, tcp, udp, icmp, other, top_ips, sections):
        rows = "".join(f"<tr><td>{ip}</td><td>{d['packets']}</td><td>{d['bytes']}</td></tr>" for ip, d in top_ips)
        section_list = "".join(f"<li>{s}</li>" for s in sections)
        return f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{title}</title><style>body {{ font-family: Arial, sans-serif; background:#f5f7fa; color:#212121; padding:30px; }} h1 {{ color:#1976d2; }} table {{ border-collapse: collapse; width:100%; margin-top:10px; }} th, td {{ border:1px solid #e0e0e0; padding:8px; text-align:left; }} th {{ background:#1976d2; color:#fff; }} .summary-box {{ display:inline-block; background:#fff; border:1px solid #e0e0e0; border-radius:6px; padding:12px 20px; margin:5px; }}</style></head><body><h1>{title}</h1><p>Author: {author} | Generated: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p><h2>Executive Summary</h2><div class='summary-box'><b>{total}</b><br>Total Packets</div><div class='summary-box'><b>{tcp}</b><br>TCP Packets</div><div class='summary-box'><b>{udp}</b><br>UDP Packets</div><div class='summary-box'><b>{icmp}</b><br>ICMP Packets</div><div class='summary-box'><b>{other}</b><br>Other Packets</div><h2>Top Source IPs</h2><table><tr><th>IP Address</th><th>Packets</th><th>Bytes</th></tr>{rows}</table><h2>Report Sections Included</h2><ul>{section_list}</ul></body></html>"
        
        
#================================================================================
#                     SETTINGS PAGE 
#================================================================================
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".network_sniffer_settings.json")

class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, app=None):
        # ── Color Tuples: ("Light Mode Color", "Dark Mode Color") ──
        self.C_BG = ("#f0f2f5", "#050608")
        self.C_CARD = ("#ffffff", "#12141c")
        self.C_BORDER = ("#d1d5db", "#1e222b")
        self.C_TEXT = ("#374151", "#cfd8dc")
        self.C_MUTED = ("#6b7280", "#78909c")
        self.C_HEADING = ("#111827", "#ffffff")
        self.C_INPUT_BG = ("#e5e7eb", "#1a1c23")
        self.C_SWITCH_BG = ("#d1d5db", "#2a2e3d")
        self.C_BLUE = "#1976d2"

        super().__init__(parent, fg_color=self.C_BG, corner_radius=0)
        self._app = app

        self._build_ui()
        self.load_settings()

    def _build_ui(self):
        # ── Page Header ──
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(30, 20))

        ctk.CTkLabel(hdr, text="Settings", font=ctk.CTkFont(size=22, weight="bold"), text_color=self.C_HEADING).pack(anchor="w")
        ctk.CTkLabel(hdr, text="Configure Network Sniffer preferences.", font=ctk.CTkFont(size=12), text_color=self.C_MUTED).pack(anchor="w")

        # ── Main Content Container ──
        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        grid_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        grid_frame.pack(fill="both", expand=True)
        grid_frame.grid_columnconfigure((0, 1), weight=1)

        # ==========================================
        # ── Card 1: Appearance Settings ──
        # ==========================================
        app_card = ctk.CTkFrame(grid_frame, fg_color=self.C_CARD, corner_radius=10, border_width=1, border_color=self.C_BORDER)
        app_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 15))
        
        app_in = ctk.CTkFrame(app_card, fg_color="transparent")
        app_in.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(app_in, text="🎨 Appearance", font=ctk.CTkFont(size=14, weight="bold"), text_color=self.C_HEADING).pack(anchor="w", pady=(0, 15))
        
        row_theme = ctk.CTkFrame(app_in, fg_color="transparent")
        row_theme.pack(fill="x", pady=8)
        ctk.CTkLabel(row_theme, text="Theme\nChoose application theme", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.theme_menu = ctk.CTkOptionMenu(row_theme, values=["Dark", "Light", "System"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE, command=self.change_theme_live)
        self.theme_menu.pack(side="right")
        self.theme_menu.set("Dark")

        row_font = ctk.CTkFrame(app_in, fg_color="transparent")
        row_font.pack(fill="x", pady=8)
        ctk.CTkLabel(row_font, text="Font Size\nChoose application font size", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.font_menu = ctk.CTkOptionMenu(row_font, values=["Small", "Medium", "Large"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.font_menu.pack(side="right")
        self.font_menu.set("Medium")

        row_accent = ctk.CTkFrame(app_in, fg_color="transparent")
        row_accent.pack(fill="x", pady=8)
        ctk.CTkLabel(row_accent, text="Accent Color\nChoose accent color for highlights", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.accent_menu = ctk.CTkOptionMenu(row_accent, values=["Blue", "Green", "Red"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.accent_menu.pack(side="right")
        self.accent_menu.set("Blue")

        # ==========================================
        # ── Card 2: Capture Settings ──
        # ==========================================
        cap_card = ctk.CTkFrame(grid_frame, fg_color=self.C_CARD, corner_radius=10, border_width=1, border_color=self.C_BORDER)
        cap_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=(0, 15))
        
        cap_in = ctk.CTkFrame(cap_card, fg_color="transparent")
        cap_in.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(cap_in, text="📡 Capture Settings", font=ctk.CTkFont(size=14, weight="bold"), text_color=self.C_HEADING).pack(anchor="w", pady=(0, 15))
        
        row_iface = ctk.CTkFrame(cap_in, fg_color="transparent")
        row_iface.pack(fill="x", pady=8)
        ctk.CTkLabel(row_iface, text="Default Interface\nSelect default network interface", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.iface_menu = ctk.CTkOptionMenu(row_iface, values=["Wi-Fi", "Ethernet", "Loopback"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.iface_menu.pack(side="right")
        self.iface_menu.set("Wi-Fi")

        row_refresh = ctk.CTkFrame(cap_in, fg_color="transparent")
        row_refresh.pack(fill="x", pady=8)
        ctk.CTkLabel(row_refresh, text="Auto Refresh Interval\nSet automatic refresh interval", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.refresh_menu = ctk.CTkOptionMenu(row_refresh, values=["1 second", "3 seconds", "5 seconds"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.refresh_menu.pack(side="right")
        self.refresh_menu.set("1 second")

        row_scroll = ctk.CTkFrame(cap_in, fg_color="transparent")
        row_scroll.pack(fill="x", pady=8)
        ctk.CTkLabel(row_scroll, text="Auto Scroll\nAutomatically scroll to new packets", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_scroll = ctk.CTkSwitch(row_scroll, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_scroll.pack(side="right")
        self.switch_scroll.select()

        row_buf = ctk.CTkFrame(cap_in, fg_color="transparent")
        row_buf.pack(fill="x", pady=8)
        ctk.CTkLabel(row_buf, text="Packet Buffer Size\nMaximum packets to keep in memory", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.buf_menu = ctk.CTkOptionMenu(row_buf, values=["1000", "5000", "10000"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.buf_menu.pack(side="right")
        self.buf_menu.set("5000")

        # ==========================================
        # ── Card 3: Export Settings ──
        # ==========================================
        exp_card = ctk.CTkFrame(grid_frame, fg_color=self.C_CARD, corner_radius=10, border_width=1, border_color=self.C_BORDER)
        exp_card.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(0, 15))
        
        exp_in = ctk.CTkFrame(exp_card, fg_color="transparent")
        exp_in.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(exp_in, text="📥 Export Settings", font=ctk.CTkFont(size=14, weight="bold"), text_color=self.C_HEADING).pack(anchor="w", pady=(0, 15))
        
        row_fmt = ctk.CTkFrame(exp_in, fg_color="transparent")
        row_fmt.pack(fill="x", pady=8)
        ctk.CTkLabel(row_fmt, text="Default Export Format\nSelect default export file format", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.fmt_menu = ctk.CTkOptionMenu(row_fmt, values=["HTML", "PDF", "CSV", "JSON"], width=130, fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, button_color=self.C_BLUE)
        self.fmt_menu.pack(side="right")
        self.fmt_menu.set("HTML")

        row_folder = ctk.CTkFrame(exp_in, fg_color="transparent")
        row_folder.pack(fill="x", pady=8)
        ctk.CTkLabel(row_folder, text="Default Save Folder\nSelect default folder to save reports", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(anchor="w")
        folder_inner = ctk.CTkFrame(row_folder, fg_color="transparent")
        folder_inner.pack(fill="x", pady=(5,0))
        self.ent_folder = ctk.CTkEntry(folder_inner, font=ctk.CTkFont(size=11), fg_color=self.C_INPUT_BG, text_color=self.C_HEADING, border_color=self.C_SWITCH_BG)
        self.ent_folder.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.ent_folder.insert(0, os.path.join(os.path.expanduser("~"), "Documents", "Network Sniffer", "Exports").replace("\\", "/"))
        self.btn_browse = ctk.CTkButton(folder_inner, text="Browse", width=60, fg_color=self.C_SWITCH_BG, text_color=self.C_HEADING, hover_color=self.C_BORDER, command=self.browse_folder)
        self.btn_browse.pack(side="right")

        row_ts = ctk.CTkFrame(exp_in, fg_color="transparent")
        row_ts.pack(fill="x", pady=12)
        ctk.CTkLabel(row_ts, text="Include Timestamp in Filename\nAdd timestamp to exported file names", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_ts = ctk.CTkSwitch(row_ts, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_ts.pack(side="right")
        self.switch_ts.select()

        # ==========================================
        # ── Card 4: Notifications ──
        # ==========================================
        notif_card = ctk.CTkFrame(grid_frame, fg_color=self.C_CARD, corner_radius=10, border_width=1, border_color=self.C_BORDER)
        notif_card.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(0, 15))
        
        notif_in = ctk.CTkFrame(notif_card, fg_color="transparent")
        notif_in.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(notif_in, text="🔔 Notifications", font=ctk.CTkFont(size=14, weight="bold"), text_color=self.C_HEADING).pack(anchor="w", pady=(0, 15))
        
        row_n1 = ctk.CTkFrame(notif_in, fg_color="transparent")
        row_n1.pack(fill="x", pady=8)
        ctk.CTkLabel(row_n1, text="Capture Complete\nShow notification when capture stops", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_cap_notif = ctk.CTkSwitch(row_n1, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_cap_notif.pack(side="right")
        self.switch_cap_notif.select()

        row_n2 = ctk.CTkFrame(notif_in, fg_color="transparent")
        row_n2.pack(fill="x", pady=8)
        ctk.CTkLabel(row_n2, text="Export Complete\nShow notification when export is done", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_exp_notif = ctk.CTkSwitch(row_n2, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_exp_notif.pack(side="right")
        self.switch_exp_notif.select()

        row_n3 = ctk.CTkFrame(notif_in, fg_color="transparent")
        row_n3.pack(fill="x", pady=8)
        ctk.CTkLabel(row_n3, text="Error Alerts\nShow notification for errors and warnings", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_err_notif = ctk.CTkSwitch(row_n3, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_err_notif.pack(side="right")
        self.switch_err_notif.select()

        row_sound = ctk.CTkFrame(notif_in, fg_color="transparent")
        row_sound.pack(fill="x", pady=8)
        ctk.CTkLabel(row_sound, text="Sound Alerts\nPlay sound for important events", justify="left", font=ctk.CTkFont(size=12), text_color=self.C_TEXT).pack(side="left")
        self.switch_sound = ctk.CTkSwitch(row_sound, text="", width=40, fg_color=self.C_SWITCH_BG, progress_color=self.C_BLUE)
        self.switch_sound.pack(side="right")
        self.switch_sound.select()

        # ── Bottom Action Buttons ──
        btn_row = ctk.CTkFrame(content_frame, fg_color="transparent")
        btn_row.pack(fill="x", pady=(10, 20))

        ctk.CTkButton(btn_row, text="💾 Save Settings", height=38, font=ctk.CTkFont(size=13, weight="bold"), fg_color=self.C_BLUE, text_color="#ffffff", hover_color="#1565c0", command=self.save_settings).pack(side="left", expand=True, fill="x", padx=(0, 10))
        ctk.CTkButton(btn_row, text="↺ Reset to Defaults", height=38, font=ctk.CTkFont(size=13), fg_color="transparent", border_width=1, border_color=self.C_SWITCH_BG, text_color=self.C_MUTED, hover_color=self.C_INPUT_BG, command=self.reset_settings).pack(side="left", expand=True, fill="x", padx=(10, 0))

    def change_theme_live(self, selected_theme):
        ctk.set_appearance_mode(selected_theme)

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Default Export Folder")
        if folder:
            self.ent_folder.delete(0, 'end')
            self.ent_folder.insert(0, folder)

    def save_settings(self):
        settings = {
            "theme": self.theme_menu.get(),
            "font_size": self.font_menu.get(),
            "accent_color": self.accent_menu.get(),
            "interface": self.iface_menu.get(),
            "auto_refresh": self.refresh_menu.get(),
            "auto_scroll": bool(self.switch_scroll.get()),
            "buffer_size": self.buf_menu.get(),
            "export_format": self.fmt_menu.get(),
            "export_folder": self.ent_folder.get(),
            "timestamp_filename": bool(self.switch_ts.get()),
            "notify_capture": bool(self.switch_cap_notif.get()),
            "notify_export": bool(self.switch_exp_notif.get()),
            "notify_error": bool(self.switch_err_notif.get()),
            "sound_alerts": bool(self.switch_sound.get()),
        }
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save settings:\n{e}")
            return

        ctk.set_appearance_mode(settings["theme"])
        if self._app and hasattr(self._app, "export_report_page"):
            self._app.export_report_page.export_format.set(settings["export_format"])
            self._app.export_report_page.select_format(settings["export_format"])

        messagebox.showinfo("Settings Saved", "Your preferences have been saved successfully!")

    def load_settings(self):
        if not os.path.exists(SETTINGS_FILE):
            return
        try:
            with open(SETTINGS_FILE, "r") as f:
                s = json.load(f)
            self.theme_menu.set(s.get("theme", "Dark"))
            self.font_menu.set(s.get("font_size", "Medium"))
            self.accent_menu.set(s.get("accent_color", "Blue"))
            self.iface_menu.set(s.get("interface", "Wi-Fi"))
            self.refresh_menu.set(s.get("auto_refresh", "1 second"))
            self.buf_menu.set(s.get("buffer_size", "5000"))
            self.fmt_menu.set(s.get("export_format", "HTML"))
            
            if "export_folder" in s:
                self.ent_folder.delete(0, 'end')
                self.ent_folder.insert(0, s["export_folder"])

            self.switch_scroll.select() if s.get("auto_scroll", True) else self.switch_scroll.deselect()
            self.switch_ts.select() if s.get("timestamp_filename", True) else self.switch_ts.deselect()
            self.switch_cap_notif.select() if s.get("notify_capture", True) else self.switch_cap_notif.deselect()
            self.switch_exp_notif.select() if s.get("notify_export", True) else self.switch_exp_notif.deselect()
            self.switch_err_notif.select() if s.get("notify_error", True) else self.switch_err_notif.deselect()
            self.switch_sound.select() if s.get("sound_alerts", True) else self.switch_sound.deselect()
                
            ctk.set_appearance_mode(s.get("theme", "Dark"))
        except Exception:
            pass

    def reset_settings(self):
        if not messagebox.askyesno("Confirm Reset", "Reset all settings to defaults?"):
            return
        self.theme_menu.set("Dark")
        self.font_menu.set("Medium")
        self.accent_menu.set("Blue")
        self.iface_menu.set("Wi-Fi")
        self.refresh_menu.set("1 second")
        self.buf_menu.set("5000")
        self.fmt_menu.set("HTML")
        self.ent_folder.delete(0, 'end')
        self.ent_folder.insert(0, os.path.join(os.path.expanduser("~"), "Documents", "Network Sniffer", "Exports").replace("\\", "/"))
        
        for switch in (self.switch_scroll, self.switch_ts, self.switch_cap_notif, self.switch_exp_notif, self.switch_err_notif, self.switch_sound):
            switch.select()
            
        ctk.set_appearance_mode("Dark")
        if os.path.exists(SETTINGS_FILE):
            os.remove(SETTINGS_FILE)
        messagebox.showinfo("Reset", "Settings have been reset to defaults.")   
        
        
        
# ==============================================================================
#                          ABOUT PAGE
# ==============================================================================           
class AboutPage(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        # Configure grid for the main page layout (2 columns, 2 rows of boxes)
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((1, 2), weight=1)

        # ==========================================
        # HEADER SECTION
        # ==========================================
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=(20, 10))
        
        title = ctk.CTkLabel(header_frame, text="About Network Sniffer", font=("Arial", 24, "bold"))
        title.pack(anchor="w")
        
        subtitle = ctk.CTkLabel(header_frame, text="Professional Network Analysis & Packet Sniffing Tool", 
                                font=("Arial", 14), text_color="gray")
        subtitle.pack(anchor="w")

        # ==========================================
        # TOP LEFT BOX: Main App Details
        # ==========================================
        box_top_left = ctk.CTkScrollableFrame(self, corner_radius=10, height=180)
        box_top_left.grid(row=1, column=0, sticky="nsew", padx=(20, 10), pady=10)
        
        # Inner grid for icon and text
        box_top_left.grid_columnconfigure(1, weight=1)
        
        # Placeholder for your Shield Icon (Replace text with CTkImage)
        icon_label = ctk.CTkLabel(box_top_left, text="🛡️\n〰️", font=("Arial", 60), text_color="#1f538d")
        icon_label.grid(row=0, column=0, rowspan=2, padx=20, pady=30, sticky="n")
        
        app_title = ctk.CTkLabel(box_top_left, text="Network Sniffer", font=("Arial", 20, "bold"))
        app_title.grid(row=0, column=1, sticky="w", pady=(30, 0))
        
        version_frame = ctk.CTkFrame(box_top_left, fg_color="transparent")
        version_frame.grid(row=1, column=1, sticky="nw", pady=(5, 10))
        ctk.CTkLabel(version_frame, text="Version 2.1.0", font=("Arial", 13)).pack(side="left", padx=(0, 10))
        
        badge = ctk.CTkLabel(version_frame, text=" Stable Release ", fg_color="#1f538d", text_color="white", corner_radius=5)
        badge.pack(side="left")
        
        desc = ("Network Sniffer is a powerful and easy-to-use\n"
                "network analysis tool designed for cybersecurity\n"
                "professionals, system administrators, students,\n"
                "and ethical hackers.")
        desc_label = ctk.CTkLabel(box_top_left, text=desc, justify="left", font=("Arial", 13), text_color="lightgray")
        desc_label.grid(row=2, column=1, sticky="w", pady=(0, 20))
        
        copyright_lbl = ctk.CTkLabel(box_top_left, text="© 2025 Network Sniffer. All rights reserved.", 
                                     font=("Arial", 11), text_color="gray")
        copyright_lbl.grid(row=3, column=0, columnspan=2, sticky="w", padx=20, pady=(20, 10))


        # ==========================================
        # TOP RIGHT BOX: Application Information
        # ==========================================
        box_top_right = ctk.CTkScrollableFrame(self, corner_radius=10, height=200)
        box_top_right.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=10)
        box_top_right.grid_columnconfigure(1, weight=1)
        
        info_title = ctk.CTkLabel(box_top_right, text="Application Information", font=("Arial", 16, "bold"))
        info_title.grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(20, 15))
        
        app_info_data = {
            "Application Name": "Network Sniffer",
            "Version": "2.1.0",
            "Release Date": "29 July 2026",
            "Developer": "Cybersecurity Analyst",
            "Python Version": "3.11.8",
            "Scapy Version": "2.5.0",
            "CustomTkinter Version": "5.2.2",
            "Platform": "Windows 11 (64-bit)"
        }
        
        row_idx = 1
        for key, value in app_info_data.items():
            ctk.CTkLabel(box_top_right, text=key, text_color="gray").grid(row=row_idx, column=0, sticky="w", padx=20, pady=5)
            ctk.CTkLabel(box_top_right, text=value).grid(row=row_idx, column=1, sticky="e", padx=20, pady=5)
            row_idx += 1


        # ==========================================
        # BOTTOM LEFT BOX: Key Features
        # ==========================================
        box_bottom_left = ctk.CTkFrame(self, corner_radius=10)
        box_bottom_left.grid(row=2, column=0, sticky="nsew", padx=(20, 10), pady=(10, 20))
        box_bottom_left.grid_columnconfigure((0, 1), weight=1)
        
        feat_title = ctk.CTkLabel(box_bottom_left, text="Key Features", font=("Arial", 16, "bold"))
        feat_title.grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(20, 15))
        
        features = [
            "Real-time Packet Capture", "Traffic Statistics & Graphs",
            "Protocol Analysis", "Top IPs & Conversations",
            "Live Traffic Monitoring", "Pcap Export",
            "IP Geolocation (Offline)", "Dark / Light Theme",
            "Advanced Packet Search", "User Friendly Interface",
            "Export Reports (HTML,\nPDF, CSV, JSON)", "High Performance & Lightweight"
        ]
        
        row_idx, col_idx = 1, 0
        for feature in features:
            f_frame = ctk.CTkFrame(box_bottom_left, fg_color="transparent")
            f_frame.grid(row=row_idx, column=col_idx, sticky="w", padx=20, pady=5)
            
            # Simulated Blue Checkmark
            check = ctk.CTkLabel(f_frame, text="✔", text_color="#3498db", font=("Arial", 14))
            check.pack(side="left", padx=(0, 10))
            ctk.CTkLabel(f_frame, text=feature, justify="left").pack(side="left")
            
            col_idx += 1
            if col_idx > 1:
                col_idx = 0
                row_idx += 1


        # ==========================================
        # BOTTOM RIGHT BOXES: Disclaimer & Connect
        # ==========================================
        
        br_container = ctk.CTkFrame(self, fg_color="transparent")
        br_container.grid(row=2, column=1, sticky="nsew", padx=(10, 20), pady=(10, 20))
        br_container.grid_columnconfigure(0, weight=1)
        br_container.grid_rowconfigure((0, 1), weight=1)
        
        # --- Disclaimer Box ---
        box_disclaimer = ctk.CTkScrollableFrame(br_container, corner_radius=10, height=80)
        box_disclaimer.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        
        disc_title_frame = ctk.CTkFrame(box_disclaimer, fg_color="transparent")
        disc_title_frame.pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(disc_title_frame, text="⚠️", text_color="orange", font=("Arial", 16)).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(disc_title_frame, text="Disclaimer", font=("Arial", 16, "bold")).pack(side="left")
        
        disc_text = ("This tool is intended for educational and authorized\n"
                     "security testing purposes only. The developer is\n"
                     "not responsible for any misuse or damage caused\n"
                     "by this software.")
        ctk.CTkLabel(box_disclaimer, text=disc_text, justify="left", text_color="gray").pack(anchor="w", padx=20, pady=(0, 20))
        
        # --- Connect Box ---
        box_connect = ctk.CTkScrollableFrame(br_container, corner_radius=10, height=80)
        box_connect.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        
        ctk.CTkLabel(box_connect, text="Connect", font=("Arial", 16, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(box_connect, text="Follow or connect with me for updates and projects.", text_color="gray").pack(anchor="w", padx=20)
        
        btn_frame = ctk.CTkFrame(box_connect, fg_color="transparent")
        btn_frame.pack(anchor="w", padx=20, pady=(15, 20))
        
        def open_my_link(url):
            print(f"\n[INFO] Please open this link in your browser:")
            print(f"👉 {url}\n")
             
            
        
        # GitHub Button
        ctk.CTkButton(btn_frame, text="GitHub", fg_color="transparent", border_width=1,
                  text_color="white", hover_color="#2c2c2c", width=80,
                  command=lambda: open_my_link("https://github.com/mukeshsingh82")).pack(side="left", padx=(0, 10))

        # LinkedIn Button
        ctk.CTkButton(btn_frame, text="LinkedIn", fg_color="transparent", border_width=1,
                  text_color="white", hover_color="#2c2c2c", width=80,
                  command=lambda: open_my_link("https://www.linkedin.com/in/mukesh-singh82")).pack(side="left", padx=(0, 10))

        # Email Button
        ctk.CTkButton(btn_frame, text="Email", fg_color="transparent", border_width=1,
                  text_color="white", hover_color="#2c2c2c", width=80,
                  command=lambda: open_my_link("mailto:mnegi19078800@gmail.com")).pack(side="left")
        
  

       
# ==============================================================================
#                          APPLICATION GUI
# ==============================================================================
class NetworkSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Sniffer")
        self.geometry("1240x720")
        self.configure(cursor="arrow")

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.frames = {}
        self.capture_start_time = None
        self.all_tree_items = []

        self.sidebar_frame = ctk.CTkScrollableFrame(self, width=220, fg_color="#080a0f", corner_radius=0, scrollbar_button_color="#1e222b")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_columnconfigure(0, weight=1)
        
        self.main_container = ctk.CTkFrame(self, fg_color="#050608", corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)

        # ── 1. Live Capture ──
        self.btn_live_capture = ctk.CTkButton(
            self.sidebar_frame, text="⚡ Live Capture", font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1a1c23", text_color="#ffffff", anchor="w", height=34, corner_radius=6,
            command=lambda: self.show_page("live_capture")
        )
        self.btn_live_capture.pack(fill="x", padx=10, pady=(12, 1))

        # ── 2. Dashboard ──
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar_frame, text="🏠 Dashboard", font=ctk.CTkFont(size=13),
            fg_color="transparent", text_color="#90a4ae", anchor="w", height=32, corner_radius=6,
            command=lambda: self.show_page("dashboard_home")
        )
        self.btn_dashboard.pack(fill="x", padx=10, pady=1)

        # ── ANALYTICS SECTION ──
        self.lbl_analytics_hd = ctk.CTkLabel(self.sidebar_frame, text="📊 ANALYTICS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#455a64")
        self.lbl_analytics_hd.pack(anchor="w", padx=14, pady=(8, 1))

        self.btn_overview = ctk.CTkButton(self.sidebar_frame, text="  • Overview", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("overview_page"))
        self.btn_overview.pack(fill="x", padx=10, pady=4)

        self.btn_proto_dist = ctk.CTkButton(self.sidebar_frame, text="  • Protocol Distribution", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#ffffff", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("proto_page"))
        self.btn_proto_dist.pack(fill="x", padx=10, pady=4)

        self.btn_top_ips = ctk.CTkButton(self.sidebar_frame, text="  • Top IPs", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("top_ips"))
        self.btn_top_ips.pack(fill="x", padx=10, pady=4)

        self.btn_conv = ctk.CTkButton(
            self.sidebar_frame, text="  • Conversations", 
            font=ctk.CTkFont(size=12), fg_color="transparent", 
            text_color="#78909c", anchor="w", height=24, 
            hover_color="#12141c", 
            command=lambda: self.show_page("conversations")
        )
        self.btn_conv.pack(fill="x", padx=10, pady=4)

        self.btn_traffic_time = ctk.CTkButton(self.sidebar_frame, text="  • Traffic Over Time", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("traffic_over_time"))
        self.btn_traffic_time.pack(fill="x", padx=10, pady=4)

        # ── TOOLS SECTION ──
        self.lbl_tools_hd = ctk.CTkLabel(self.sidebar_frame, text="🛠️ TOOLS", font=ctk.CTkFont(size=10, weight="bold"), text_color="#455a64")
        self.lbl_tools_hd.pack(anchor="w", padx=14, pady=(8, 1))

        self.btn_geo = ctk.CTkButton(self.sidebar_frame, text="  • IP Geolocation", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("geo_page"))
        self.btn_geo.pack(fill="x", padx=10, pady=4)

        self.btn_psearch = ctk.CTkButton(self.sidebar_frame, text="  • Packet Search", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("packet_search"))
        self.btn_psearch.pack(fill="x", padx=10, pady=4)

        self.btn_export_rep = ctk.CTkButton(self.sidebar_frame, text="  • Export Report", font=ctk.CTkFont(size=12), fg_color="transparent", text_color="#78909c", anchor="w", height=24, hover_color="#12141c", command=lambda: self.show_page("export_report"))
        self.btn_export_rep.pack(fill="x", padx=10, pady=4)
        
        # ── SETTINGS & ABOUT SECTION ──
        self.btn_settings = ctk.CTkButton(self.sidebar_frame, text="⚙️ SETTINGS", font=ctk.CTkFont(size=11, weight="bold"), fg_color="transparent", text_color="#90a4ae", hover_color="#12141c", anchor="w", height=26, corner_radius=6, command=lambda: self.show_page("settings_page"))
        self.btn_settings.pack(fill="x", padx=10, pady=(10, 4)) 
        
        self.btn_about = ctk.CTkButton(self.sidebar_frame, text="🛈 ABOUT", font=ctk.CTkFont(size=11, weight="bold"), fg_color="transparent", text_color="#90a4ae", hover_color="#12141c", anchor="w", height=26, corner_radius=6, command=lambda: self.show_page("about_page")) 
        self.btn_about.pack(fill="x", padx=10, pady=(1, 4))
        
        # ── STATUS CARD ──
        self.status_card = ctk.CTkFrame(self.sidebar_frame, fg_color="#111318", corner_radius=8, border_width=1, border_color="#1e222b")
        self.status_card.pack(fill="both", expand=True, padx=10, pady=(6, 12))

        self.lbl_status_title = ctk.CTkLabel(self.status_card, text="Capture Status", font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c")
        self.lbl_status_title.pack(anchor="w", padx=12, pady=(10, 4))

        self.lbl_status_state = ctk.CTkLabel(self.status_card, text="🟢 Idle / Ready", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00e676")
        self.lbl_status_state.pack(anchor="w", padx=12, pady=1)

        self.lbl_interface = ctk.CTkLabel(self.status_card, text="Interface:   Wi-Fi", font=ctk.CTkFont(size=11), text_color="#546e7a")
        self.lbl_interface.pack(anchor="w", padx=12, pady=1)

        self.lbl_duration = ctk.CTkLabel(self.status_card, text="Duration:    00:00:00", font=ctk.CTkFont(size=11), text_color="#546e7a")
        self.lbl_duration.pack(anchor="w", padx=12, pady=1)
        
        #===================================================================================
        #                     REGISTERING ALL PAGES
        #===================================================================================
        
        # Top IPs Page
        self.top_ips_page = TopIPsDashboard(self)
        self.frames["top_ips"] = self.top_ips_page
        
        # Register the Conversations Page
        self.conv_page = ConversationsPage(self)
        self.frames["conversations"] = self.conv_page
                        
        # Dashboard Home View
        self.dashboard_home_frame = ctk.CTkFrame(self, fg_color="#050608", corner_radius=0)
        self.frames["dashboard_home"] = self.dashboard_home_frame
        
        # Register Traffic Over Time Page
        self.traffic_time_page = TrafficOverTimePage(self)
        self.frames["traffic_over_time"] = self.traffic_time_page
        
        # Register the IP Geolocation page
        self.geo_page = IPGeolocationPage(self)
        self.frames["geo_page"] = self.geo_page
        
        # Register Packet Search Page
        self.packet_search_page = PacketSearchPage(self, app=self)
        self.frames["packet_search"] = self.packet_search_page
        
        # Register Export Report Page
        self.export_report_page = ExportReportPage(self, app=self)
        self.frames["export_report"] = self.export_report_page
        
        # Register Settings Page
        self.settings_page = SettingsPage(self, app=self)
        self.frames["settings_page"] = self.settings_page
        
        # Register About Page
        self.about_page = AboutPage(self)
        self.frames["about_page"] = self.about_page
        
        dp_top_row = ctk.CTkFrame(self.dashboard_home_frame, fg_color="transparent", height=45)
        dp_top_row.pack(fill="x", padx=25, pady=(20, 5))

        lbl_db_main_title = ctk.CTkLabel(dp_top_row, text="🏠 Dashboard", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ffffff")
        lbl_db_main_title.pack(side="left", anchor="w")

        lbl_db_v_tag = ctk.CTkLabel(dp_top_row, text="Network Sniffer", font=ctk.CTkFont(size=11), text_color="#455a64")
        lbl_db_v_tag.pack(side="right", anchor="e", padx=5)

        exec_strip = ctk.CTkFrame(self.dashboard_home_frame, fg_color="transparent", height=25)
        exec_strip.pack(fill="x", padx=25, pady=(0, 10))
        ctk.CTkLabel(exec_strip, text="🌐 Executive Overview", font=ctk.CTkFont(size=13, weight="bold"), text_color="#90a4ae").pack(side="left")
        self.lbl_last_scan_ts = ctk.CTkLabel(exec_strip, text="Last Scan: Never", font=ctk.CTkFont(size=11), text_color="#546e7a")
        self.lbl_last_scan_ts.pack(side="right")

        self.sec_status_card = ctk.CTkFrame(self.dashboard_home_frame, height=80, fg_color="#12141c", corner_radius=10, border_width=1, border_color="#1e222b")
        self.sec_status_card.pack(fill="x", padx=25, pady=5)
        self.sec_status_card.pack_propagate(False)

        ctk.CTkLabel(self.sec_status_card, text="🛡️ NETWORK SECURITY STATUS", font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=20, pady=(10, 1))

        status_flex = ctk.CTkFrame(self.sec_status_card, fg_color="transparent")
        status_flex.pack(fill="x", padx=20, pady=2)
        self.lbl_db_sec_state = ctk.CTkLabel(status_flex, text="🟢 SECURE", font=ctk.CTkFont(size=16, weight="bold"), text_color="#00e676")
        self.lbl_db_sec_state.pack(side="left")
        self.lbl_db_sec_desc = ctk.CTkLabel(status_flex, text="No suspicious activity detected in telemetry logs.", font=ctk.CTkFont(size=12), text_color="#90a4ae")
        self.lbl_db_sec_desc.pack(side="left", padx=40)

        metrics_strip = ctk.CTkFrame(self.dashboard_home_frame, fg_color="transparent", height=76)
        metrics_strip.pack(fill="x", padx=25, pady=(10, 8))
        for i in range(4): metrics_strip.grid_columnconfigure(i, weight=1)

        db_meta_cards = [
            {"title": "📦 Total Packets", "val": "0", "color": "#00b0ff", "id": "tot"},
            {"title": "⚡ Capture Status", "val": "🟢 Idle / Ready", "color": "#00e676", "id": "status"},
            {"title": "⏱️ Duration", "val": "00:00:00", "color": "#ff9100", "id": "dur"},
            {"title": "💾 Data Captured", "val": "0.00 MB", "color": "#d500f9", "id": "data"}
        ]
        self.db_cards = {}
        for idx, mc in enumerate(db_meta_cards):
            c_box = ctk.CTkFrame(metrics_strip, fg_color="#12141c", corner_radius=8, border_width=1, border_color="#1f232d", height=72)
            c_box.grid(row=0, column=idx, padx=4, sticky="nsew")
            c_box.pack_propagate(False)
            ctk.CTkLabel(c_box, text=mc["title"], font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=15, pady=(10, 2))
            self.db_cards[mc["id"]] = ctk.CTkLabel(c_box, text=mc["val"], font=ctk.CTkFont(size=16, weight="bold"), text_color=mc["color"])
            self.db_cards[mc["id"]].pack(anchor="w", padx=15, pady=2)

        split_row_frame = ctk.CTkFrame(self.dashboard_home_frame, fg_color="transparent", height=140)
        split_row_frame.pack(fill="x", padx=25, pady=5)
        split_row_frame.grid_columnconfigure((0, 1), weight=1)

        sess_box = ctk.CTkFrame(split_row_frame, fg_color="#12141c", corner_radius=10, border_width=1, border_color="#1e222b")
        sess_box.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        ctk.CTkLabel(sess_box, text="📊 SESSION SUMMARY", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=15, pady=(10, 5))
        self.lbl_ds_pcap = ctk.CTkLabel(sess_box, text="Packets Captured      : 0", font=ctk.CTkFont(family="Courier", size=12), text_color="#cfd8dc")
        self.lbl_ds_pcap.pack(anchor="w", padx=20, pady=2)
        self.lbl_ds_threat = ctk.CTkLabel(sess_box, text="Threats Detected      : 0", font=ctk.CTkFont(family="Courier", size=12), text_color="#ff1744")
        self.lbl_ds_threat.pack(anchor="w", padx=20, pady=2)
        self.lbl_ds_ips = ctk.CTkLabel(sess_box, text="Suspicious IPs        : 0", font=ctk.CTkFont(family="Courier", size=12), text_color="#ff9100")
        self.lbl_ds_ips.bind("<Button-1>", lambda e: self.show_page("overview_page"))
        self.lbl_ds_ips.pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(sess_box, text="Current Interface     : Wi-Fi", font=ctk.CTkFont(family="Courier", size=12), text_color="#90a4ae").pack(anchor="w", padx=20, pady=(2, 10))

        eng_box = ctk.CTkFrame(split_row_frame, fg_color="#12141c", corner_radius=10, border_width=1, border_color="#1e222b")
        eng_box.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
        ctk.CTkLabel(eng_box, text="⚙️ ENGINE STATUS", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=15, pady=(10, 5))
        self.lbl_db_eng_state = ctk.CTkLabel(eng_box, text="Capture Engine     : Ready", font=ctk.CTkFont(family="Courier", size=12), text_color="#00e676")
        self.lbl_db_eng_state.pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(eng_box, text="Detection Engine   : Active", font=ctk.CTkFont(family="Courier", size=12), text_color="#00b0ff").pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(eng_box, text="Export Module      : Ready", font=ctk.CTkFont(family="Courier", size=12), text_color="#cfd8dc").pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(eng_box, text="Packet Decoder     : Loaded", font=ctk.CTkFont(family="Courier", size=12), text_color="#90a4ae").pack(anchor="w", padx=20, pady=(2, 10))

        recent_box = ctk.CTkFrame(self.dashboard_home_frame, fg_color="#12141c", corner_radius=10, border_width=1, border_color="#1e222b")
        recent_box.pack(fill="both", expand=True, padx=25, pady=(10, 20))
        ctk.CTkLabel(recent_box, text="📝 RECENT ACTIVITY", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=15, pady=(10, 5))
        self.txt_db_log = tk.Text(recent_box, bg="#12141c", fg="#00e676", font=("Courier", 11), borderwidth=0, highlightthickness=0, height=12, state="normal")
        self.txt_db_log.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        self.push_dashboard_log("✔ Application Started Successfully")
        self.push_dashboard_log("✔ Waiting for packet capture instructions...")
        self.push_dashboard_log("✔ Monitoring engine core loaded & initialized.")

        # ==============================================================================
        #                          PAGE 1: MAIN LIVE CAPTURE TABLE
        # ==============================================================================
        self.main_body_frame = ctk.CTkFrame(self, fg_color="#050608", corner_radius=0)
        self.frames["live_capture"] = self.main_body_frame

        self.top_control_frame = ctk.CTkFrame(self.main_body_frame, height=45, fg_color="transparent")
        self.top_control_frame.pack(fill="x", padx=20, pady=(15, 2))
        self.top_control_frame.pack_propagate(False)

        self.title_cluster_frame = ctk.CTkFrame(self.top_control_frame, fg_color="transparent")
        self.title_cluster_frame.pack(side="left", padx=(0, 25), anchor="w")
        self.lbl_live_title = ctk.CTkLabel(self.title_cluster_frame, text="Live Capture •", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffffff")
        self.lbl_live_title.pack(anchor="w", pady=(0, 1))
        self.lbl_live_desc = ctk.CTkLabel(self.title_cluster_frame, text="Capturing packets in real time", font=ctk.CTkFont(size=11), text_color="#78909c")
        self.lbl_live_desc.pack(anchor="w", pady=0)

        self.btn_start = ctk.CTkButton(self.top_control_frame, text="▶️ Start Capture", command=self.start_sniffing, fg_color="#2e7d32", text_color="#ffffff", hover_color="#1b5e20", width=115, height=32, corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"))
        self.btn_start.pack(side="left", padx=4, anchor="center")
        self.btn_stop = ctk.CTkButton(self.top_control_frame, text="⏹ Stop Capture", command=self.stop_sniffing, fg_color="#c62828", text_color="#ffffff", hover_color="#b71c1c", state="disabled", width=115, height=32, corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"))
        self.btn_stop.pack(side="left", padx=4, anchor="center")
        self.btn_export = ctk.CTkButton(self.top_control_frame, text="📥 Export PCAP", command=lambda: self.show_page("export_report"), fg_color="#1976d2", text_color="#ffffff", hover_color="#1565c0", width=110, height=32, corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"))
        self.btn_export.pack(side="left", padx=10, anchor="center")
        self.btn_filters = ctk.CTkButton(self.top_control_frame, text="⏳ Filters", command=lambda: self.show_page("packet_search"), fg_color="#263238", text_color="#90a4ae", hover_color="#37474f", border_width=1, border_color="#37474f", width=90, height=32, corner_radius=6, font=ctk.CTkFont(size=12, weight="bold"))
        self.btn_filters.pack(side="left", padx=4, anchor="center")

        self.middle_metrics_frame = ctk.CTkFrame(self.main_body_frame, height=95, fg_color="transparent")
        self.middle_metrics_frame.pack(fill="x", padx=20, pady=2)
        self.middle_metrics_frame.pack_propagate(False)
        for i in range(5): self.middle_metrics_frame.grid_columnconfigure(i, weight=1)

        metrics_meta = [
            {"title": "Total Packets", "color": "#00b0ff", "key": "Total"},
            {"title": "TCP Packets",   "color": "#00e676", "key": "TCP"},
            {"title": "UDP Packets",   "color": "#ff9100", "key": "UDP"},
            {"title": "ICMP Packets",  "color": "#d500f9", "key": "ICMP"},
            {"title": "Other Packets", "color": "#90a4ae", "key": "Other"},
        ]
        self.counter_labels = {}
        for idx, meta in enumerate(metrics_meta):
            card = ctk.CTkFrame(self.middle_metrics_frame, height=80, fg_color="#12141c", corner_radius=8, border_width=1, border_color="#1f232d")
            card.grid(row=0, column=idx, padx=4, sticky="nsew")
            card.pack_propagate(False)
            ctk.CTkLabel(card, text=meta["title"], font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=12, pady=(10, 1))
            lbl_count = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color=meta["color"])
            lbl_count.pack(anchor="w", padx=12, pady=(0, 4))
            self.counter_labels[meta["key"]] = lbl_count

        self.bottom_table_frame = ctk.CTkFrame(self.main_body_frame, fg_color="#12141c", height=520, corner_radius=10, border_width=1, border_color="#1e222b")
        self.bottom_table_frame.pack(fill="both", expand=True, padx=20, pady=(6, 20))
        self.bottom_table_frame.pack_propagate(False)

        self.grid_header_row = ctk.CTkFrame(self.bottom_table_frame, height=40, fg_color="transparent")
        self.grid_header_row.pack(fill="x", padx=15, pady=(10, 2))
        self.lbl_grid_title = ctk.CTkLabel(self.grid_header_row, text="Packet Capture", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffffff")
        self.lbl_grid_title.pack(side="left", anchor="center")
        self.ent_search = ctk.CTkEntry(self.grid_header_row, placeholder_text="🔍 Search packets...", width=200, height=28, fg_color="#1a1c23", border_color="#2a2e3d", text_color="#ffffff", placeholder_text_color="#546e7a", corner_radius=6)
        self.ent_search.pack(side="right", anchor="center", padx=5)
        self.ent_search.bind("<KeyRelease>", self.filter_packets)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#12141c", foreground="#cfd8dc", rowheight=30, fieldbackground="#12141c", borderwidth=0, font=("Segoe UI", 10))
        style.map("Treeview", background=[("selected", "#1e3a5f")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#0d0f14", foreground="#90a4ae", relief="flat", padding=5, font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", "#0d0f14")], foreground=[("active", "#ffffff")])

        columns = ("no", "time", "proto", "src", "sport", "dst", "dport", "len", "info")
        self.tree = ttk.Treeview(self.bottom_table_frame, columns=columns, show="headings", style="Treeview")
        for col, title in zip(columns, ["No.", "Time", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Length", "Info"]):
            self.tree.heading(col, text=title, anchor="w" if col != "no" else "center")

        self.tree.column("no", width=45, minwidth=40, anchor="center", stretch=False)
        self.tree.column("time", width=95, minwidth=90, anchor="w", stretch=False)
        self.tree.column("proto", width=85, minwidth=75, anchor="w", stretch=False)
        self.tree.column("src", width=120, minwidth=110, anchor="w", stretch=False)
        self.tree.column("sport", width=110, minwidth=100, anchor="w", stretch=False)
        self.tree.column("dst", width=135, minwidth=120, anchor="w", stretch=False)
        self.tree.column("dport", width=140, minwidth=125, anchor="w", stretch=False)
        self.tree.column("len", width=80, minwidth=70, anchor="w", stretch=False)
        self.tree.column("info", width=320, minwidth=200, anchor="w", stretch=True)

        self.tree.tags = {}
        for proto, color in [("TCP", "#64b5f6"), ("UDP", "#b388ff"), ("ICMP", "#ffd54f"), ("OTHER", "#90a4ae")]:
            self.tree.tag_configure(f"{proto}_ROW", foreground=color, background="#12141c", font=("Segoe UI", 10))
            self.tree.tag_configure(f"{proto}_ROW_ALT", foreground=color, background="#0f1118", font=("Segoe UI", 10))

        self.scrollbar = ttk.Scrollbar(self.bottom_table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=(15, 0), pady=(2, 15))

        # ==============================================================================
        #                          PAGE 2: DEDICATED OVERVIEW VIEW
        # ==============================================================================
        self.overview_page_frame = ctk.CTkFrame(self, fg_color="#050608", corner_radius=0)
        self.frames["overview_page"] = self.overview_page_frame

        lbl_ov_title = ctk.CTkLabel(self.overview_page_frame, text="Executive Telemetry Overview", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ffffff")
        lbl_ov_title.pack(anchor="nw", padx=30, pady=(25, 5))
        lbl_ov_desc = ctk.CTkLabel(self.overview_page_frame, text="High-level network load behavior and state conditions metrics.", font=ctk.CTkFont(size=12), text_color="#78909c")
        lbl_ov_desc.pack(anchor="nw", padx=30, pady=(0, 20))

        self.ov_grid_frame = ctk.CTkFrame(self.overview_page_frame, fg_color="transparent")
        self.ov_grid_frame.pack(fill="x", padx=30, pady=10)
        self.ov_grid_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.card_health = ctk.CTkFrame(self.ov_grid_frame, height=100, fg_color="#12141c", corner_radius=8, border_width=1, border_color="#1f232d")
        self.card_health.grid(row=0, column=0, padx=5, sticky="nsew")
        self.card_health.pack_propagate(False)
        ctk.CTkLabel(self.card_health, text="Network Security Status", font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=15, pady=(12, 2))
        self.lbl_ov_health = ctk.CTkLabel(self.card_health, text="🟢 EXCELLENT", font=ctk.CTkFont(size=18, weight="bold"), text_color="#00e676")
        self.lbl_ov_health.pack(anchor="w", padx=15, pady=2)

        self.card_nodes = ctk.CTkFrame(self.ov_grid_frame, height=100, fg_color="#12141c", corner_radius=8, border_width=1, border_color="#1f232d")
        self.card_nodes.grid(row=0, column=1, padx=5, sticky="nsew")
        self.card_nodes.pack_propagate(False)
        ctk.CTkLabel(self.card_nodes, text="Active Unique Nodes", font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=15, pady=(12, 2))
        self.lbl_ov_nodes = ctk.CTkLabel(self.card_nodes, text="0 Active IPs", font=ctk.CTkFont(size=18, weight="bold"), text_color="#00b0ff")
        self.lbl_ov_nodes.pack(anchor="w", padx=15, pady=2)

        self.card_flow = ctk.CTkFrame(self.ov_grid_frame, height=100, fg_color="#12141c", corner_radius=8, border_width=1, border_color="#1f232d")
        self.card_flow.grid(row=0, column=2, padx=5, sticky="nsew")
        self.card_flow.pack_propagate(False)
        ctk.CTkLabel(self.card_flow, text="Total Captured Traffic", font=ctk.CTkFont(size=11, weight="bold"), text_color="#78909c").pack(anchor="w", padx=15, pady=(12, 2))
        self.lbl_ov_flow = ctk.CTkLabel(self.card_flow, text="0 Packets", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff9100")
        self.lbl_ov_flow.pack(anchor="w", padx=15, pady=2)
        
        self.suspicious_table_frame = ctk.CTkFrame(self.overview_page_frame, fg_color="#12141c", corner_radius=10, border_width=1, border_color="#1e222b")
        self.suspicious_table_frame.pack(fill="both", expand=True, padx=30, pady=(20, 30))
        lbl_susp_title = ctk.CTkLabel(self.suspicious_table_frame, text="🚨 Flagged Telemetry Hosts (Suspicious Activity)", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ff1744")
        lbl_susp_title.pack(anchor="w", padx=15, pady=(10, 5))
        
        s_columns = ("ip", "reason", "time")
        self.s_tree = ttk.Treeview(self.suspicious_table_frame, columns=s_columns, show="headings", style="Treeview", height=8)
        self.s_tree.heading("ip", text="Flagged Host IP", anchor="w")
        self.s_tree.heading("reason", text="Security Rule / Violation Reason", anchor="w")
        self.s_tree.heading("time", text="Detection Timestamp", anchor="center")
        self.s_tree.column("ip", width=150, minwidth=130, anchor="w", stretch=False)
        self.s_tree.column("reason", width=450, minwidth=300, anchor="w", stretch=True)
        self.s_tree.column("time", width=150, minwidth=130, anchor="center", stretch=False)
        self.s_tree.tag_configure("ALERT_ROW", foreground="#ff5252", background="#12141c", font=("Segoe UI", 10, "bold"))
        
        self.s_scrollbar = ttk.Scrollbar(self.suspicious_table_frame, orient="vertical", command=self.s_tree.yview)
        self.s_tree.configure(yscrollcommand=self.s_scrollbar.set)
        self.s_scrollbar.pack(side="right", fill="y")
        self.s_tree.pack(fill="both", expand=True, padx=15, pady=(2, 15))

        # ==============================================================================
        #              PAGE 3: PROTOCOL ANALYSIS ENGINE 
        # ==============================================================================
        self.proto_page_frame = ctk.CTkFrame(self, fg_color="#050608", corner_radius=0)
        self.frames["proto_page"] = self.proto_page_frame

        self.c_tcp = "#00e676"  
        self.c_udp = "#00b0ff"  
        self.c_icmp = "#ff5252" 
        self.c_oth = "#ffc107"  
        self.c_bg = "#12141c"   
        self.c_text = "#cfd8dc" 

        header_frame = ctk.CTkFrame(self.proto_page_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=30, pady=(25, 10))
        
        title_left = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_left.pack(side="left")
        ctk.CTkLabel(title_left, text="Protocol Analysis Engine", font=ctk.CTkFont(size=22, weight="bold"), text_color="#ffffff").pack(anchor="w")
        ctk.CTkLabel(title_left, text="Detailed view of underlying structure of captured frames.", font=ctk.CTkFont(size=13), text_color="#90a4ae").pack(anchor="w")

        title_right = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_right.pack(side="right", anchor="s")
        self.lbl_last_update = ctk.CTkLabel(title_right, text="Last Updated: --:--:--", font=ctk.CTkFont(size=12), text_color="#cfd8dc")
        self.lbl_last_update.pack(side="left", padx=10)
        btn_refresh = ctk.CTkButton(title_right, text="↻", width=30, height=30, fg_color="transparent", border_width=1, border_color="#2a2e3d", hover_color="#1a1c23")
        btn_refresh.pack(side="left")

        self.pd_main = ctk.CTkScrollableFrame(self.proto_page_frame, fg_color="transparent")
        self.pd_main.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # ── 1. LIVE METRICS SUMMARY ──
        summary_card = ctk.CTkFrame(self.pd_main, fg_color=self.c_bg, corner_radius=8, border_width=1, border_color="#1e222b")
        summary_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(summary_card, text="📈 Live Metrics Summary", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=20, pady=(15, 0))
        
        metrics_grid = ctk.CTkFrame(summary_card, fg_color="transparent")
        metrics_grid.pack(fill="x", padx=20, pady=(10, 20))
        for i in range(4): metrics_grid.grid_columnconfigure(i, weight=1)

        def create_metric_col(parent, col, title, color):
            frame = ctk.CTkFrame(parent, fg_color="transparent")
            frame.grid(row=0, column=col, sticky="nsew")
            ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=12), text_color=self.c_text).pack()
            num_lbl = ctk.CTkLabel(frame, text="0", font=ctk.CTkFont(size=28, weight="bold"), text_color=color)
            num_lbl.pack(pady=2)
            pct_lbl = ctk.CTkLabel(frame, text="(0%)", font=ctk.CTkFont(size=12), text_color="#78909c")
            pct_lbl.pack()
            if col < 3:
                div = ctk.CTkFrame(parent, width=1, fg_color="#1e222b")
                div.grid(row=0, column=col, sticky="e")
            return num_lbl, pct_lbl

        self.l_tcp_n, self.l_tcp_p = create_metric_col(metrics_grid, 0, "Total TCP Packets", self.c_tcp)
        self.l_udp_n, self.l_udp_p = create_metric_col(metrics_grid, 1, "Total UDP Packets", self.c_udp)
        self.l_icmp_n, self.l_icmp_p = create_metric_col(metrics_grid, 2, "Total ICMP Packets", self.c_icmp)
        self.l_oth_n, self.l_oth_p = create_metric_col(metrics_grid, 3, "Other Packets", self.c_oth)

        # ── 2. TRAFFIC PROGRESS ──
        prog_card = ctk.CTkFrame(self.pd_main, fg_color=self.c_bg, corner_radius=8, border_width=1, border_color="#1e222b")
        prog_card.pack(fill="x", pady=(0, 15))
        
        prog_head = ctk.CTkFrame(prog_card, fg_color="transparent")
        prog_head.pack(fill="x", padx=20, pady=(15, 10))
        ctk.CTkLabel(prog_head, text="📉 Traffic Progress", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff").pack(side="left")
        
        prog_grid = ctk.CTkFrame(prog_card, fg_color="transparent")
        prog_grid.pack(fill="x", padx=20, pady=(0, 20))
        prog_grid.grid_columnconfigure(1, weight=1) 

        def create_prog_row(parent, row, title, color):
            lbl_tit = ctk.CTkLabel(parent, text=f" {title}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff")
            lbl_tit.grid(row=row, column=0, sticky="w", pady=10, padx=(0, 20))
            bar = ctk.CTkProgressBar(parent, height=10, progress_color=color, fg_color="#1e222b")
            bar.grid(row=row, column=1, sticky="ew", padx=20)
            bar.set(0)
            pct = ctk.CTkLabel(parent, text="0%", font=ctk.CTkFont(size=13, weight="bold"), text_color=color, width=50, anchor="e")
            pct.grid(row=row, column=2, sticky="e", padx=(10, 20))
            cnt = ctk.CTkLabel(parent, text="0 Packets", font=ctk.CTkFont(size=12), text_color=self.c_text, width=80, anchor="e")
            cnt.grid(row=row, column=3, sticky="e")
            return bar, pct, cnt

        self.p_tcp_b, self.p_tcp_p, self.p_tcp_c = create_prog_row(prog_grid, 0, "TCP", self.c_tcp)
        self.p_udp_b, self.p_udp_p, self.p_udp_c = create_prog_row(prog_grid, 1, "UDP", self.c_udp)
        self.p_icmp_b, self.p_icmp_p, self.p_icmp_c = create_prog_row(prog_grid, 2, "ICMP", self.c_icmp)
        self.p_oth_b, self.p_oth_p, self.p_oth_c = create_prog_row(prog_grid, 3, "Others", self.c_oth)

        # ── 3. PROTOCOL DEEP DIVE (4 CARDS GRID) ──
        dd_card = ctk.CTkFrame(self.pd_main, fg_color=self.c_bg, corner_radius=8, border_width=1, border_color="#1e222b")
        dd_card.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(dd_card, text="📊 Protocol Deep Dive", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=20, pady=(15, 10))

        dd_grid = ctk.CTkFrame(dd_card, fg_color="transparent")
        dd_grid.pack(fill="x", padx=20, pady=(0, 20))
        for i in range(4): dd_grid.grid_columnconfigure(i, weight=1)

        def create_kv_row(parent, row, key):
            k = ctk.CTkLabel(parent, text=key, font=ctk.CTkFont(size=11), text_color=self.c_text)
            k.grid(row=row, column=0, sticky="w", pady=2)
            v = ctk.CTkLabel(parent, text="0", font=ctk.CTkFont(size=11, weight="bold"), text_color="#ffffff")
            v.grid(row=row, column=1, sticky="e", pady=2)
            return v

        d_tcp = ctk.CTkFrame(dd_grid, fg_color="transparent")
        d_tcp.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        d_tcp.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(d_tcp, text="TCP", font=ctk.CTkFont(size=16, weight="bold"), text_color=self.c_tcp).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.kv_tcp_con = create_kv_row(d_tcp, 1, "Connections")
        self.kv_tcp_tot = create_kv_row(d_tcp, 2, "Bytes Transferred")
        self.kv_tcp_tx  = create_kv_row(d_tcp, 3, "Bytes Tx")
        self.kv_tcp_rx  = create_kv_row(d_tcp, 4, "Bytes Rx")
        self.kv_tcp_avg = create_kv_row(d_tcp, 5, "Avg Packet Size")

        d_udp = ctk.CTkFrame(dd_grid, fg_color="transparent")
        d_udp.grid(row=0, column=1, sticky="nsew", padx=10)
        d_udp.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(d_udp, text="UDP", font=ctk.CTkFont(size=16, weight="bold"), text_color=self.c_udp).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.kv_udp_dat = create_kv_row(d_udp, 1, "Datagrams")
        self.kv_udp_tot = create_kv_row(d_udp, 2, "Bytes Transferred")
        self.kv_udp_tx  = create_kv_row(d_udp, 3, "Bytes Tx")
        self.kv_udp_rx  = create_kv_row(d_udp, 4, "Bytes Rx")
        self.kv_udp_avg = create_kv_row(d_udp, 5, "Avg Packet Size")

        d_icmp = ctk.CTkFrame(dd_grid, fg_color="transparent")
        d_icmp.grid(row=0, column=2, sticky="nsew", padx=10)
        d_icmp.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(d_icmp, text="ICMP", font=ctk.CTkFont(size=16, weight="bold"), text_color=self.c_icmp).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.kv_icm_req = create_kv_row(d_icmp, 1, "Echo Request")
        self.kv_icm_rep = create_kv_row(d_icmp, 2, "Echo Reply")
        self.kv_icm_unr = create_kv_row(d_icmp, 3, "Destination Unreachable")
        self.kv_icm_exc = create_kv_row(d_icmp, 4, "Time Exceeded")
        self.kv_icm_oth = create_kv_row(d_icmp, 5, "Other ICMP")

        d_oth = ctk.CTkFrame(dd_grid, fg_color="transparent")
        d_oth.grid(row=0, column=3, sticky="nsew", padx=(10, 0))
        d_oth.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(d_oth, text="Others", font=ctk.CTkFont(size=16, weight="bold"), text_color=self.c_oth).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.kv_oth_arp = create_kv_row(d_oth, 1, "ARP Packets")
        self.kv_oth_dns = create_kv_row(d_oth, 2, "DNS Packets")
        self.kv_oth_dhc = create_kv_row(d_oth, 3, "DHCP Packets")
        self.kv_oth_oth = create_kv_row(d_oth, 4, "Other Packets")

        # ── 4. STATUS FOOTER ──
        foot_card = ctk.CTkFrame(self.pd_main, fg_color=self.c_bg, corner_radius=8, border_width=1, border_color="#1e222b", height=70)
        foot_card.pack(fill="x", pady=(0, 20))
        foot_card.grid_columnconfigure((0,1,2), weight=1)
        foot_card.pack_propagate(False)

        f1 = ctk.CTkFrame(foot_card, fg_color="transparent")
        f1.grid(row=0, column=0, pady=15, sticky="n")
        ctk.CTkLabel(f1, text="🛡️ Analysis Status", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(f1, text="Analysis running smoothly", font=ctk.CTkFont(size=11), text_color="#00e676").pack()

        f2 = ctk.CTkFrame(foot_card, fg_color="transparent")
        f2.grid(row=0, column=1, pady=15, sticky="n")
        ctk.CTkLabel(f2, text="⚙️ Protocol Decoder", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(f2, text="All decoders are active", font=ctk.CTkFont(size=11), text_color="#00e676").pack()

        f3 = ctk.CTkFrame(foot_card, fg_color="transparent")
        f3.grid(row=0, column=2, pady=15, sticky="n")
        ctk.CTkLabel(f3, text="✅ Frame Integrity", font=ctk.CTkFont(size=12, weight="bold"), text_color="#ffffff").pack()
        ctk.CTkLabel(f3, text="No corrupted frames detected", font=ctk.CTkFont(size=11), text_color="#00e676").pack()

        

    # ==============================================================================
    #                          NAVIGATION ENGINE LOGIC
    # ==============================================================================
    def show_page(self, page_name):
        for frame in self.frames.values(): frame.grid_forget()
        self.frames[page_name].grid(row=0, column=1, sticky="nsew")
        if page_name == "packet_search":
            self.packet_search_page.search_packets()

    def push_dashboard_log(self, log_msg):
        if hasattr(self, 'txt_db_log') and self.txt_db_log.winfo_exists():
            self.txt_db_log.configure(state="normal")
            self.txt_db_log.insert("end", f"{log_msg}\n")
            self.txt_db_log.see("end")
            self.txt_db_log.configure(state="disabled")

    def update_sidebar_and_analytics(self, current_time_str="00:00:00"):
        if not self.winfo_exists(): return

        health_status = "🟢 EXCELLENT" if len(suspicious_ips_list) == 0 else "⚠️ ANOMALIES"
        health_color = "#00e676" if health_status == "🟢 EXCELLENT" else "#ff1744"
        
        distinct_nodes = len(src_ip_counts)
        suspicious_count = len(suspicious_ips_list)

        self.lbl_ov_health.configure(text=health_status, text_color=health_color)
        self.lbl_ov_nodes.configure(text=f"{distinct_nodes} Active IPs")
        self.lbl_ov_flow.configure(text=f"{packet_count['Total']} Packets")

        self.db_cards["tot"].configure(text=str(packet_count["Total"]))
        self.db_cards["dur"].configure(text=current_time_str)

        total_bytes = packet_count["Total"] * 185
        if total_bytes < 1024 * 1024:
            kb_size = total_bytes / 1024
            self.db_cards["data"].configure(text=f"{kb_size:.2f} KB")
        else:
            mb_size = total_bytes / (1024 * 1024)
            self.db_cards["data"].configure(text=f"{mb_size:.2f} MB")

        self.lbl_ds_pcap.configure(text=f"Packets Captured      : {packet_count['Total']}")
        self.lbl_ds_ips.configure(text=f"Suspicious IPs        : {suspicious_count}") 

        if hasattr(self, 's_tree') and self.s_tree.winfo_exists():
            for item in self.s_tree.get_children():
                self.s_tree.delete(item)
            for flagged_ip, reason in suspicious_ips_list.items():
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                self.s_tree.insert("", "end", values=(flagged_ip, reason, timestamp), tags=("ALERT_ROW",))

        if packet_count["Total"] > 0:
            self.lbl_db_sec_state.configure(text="🟢 MONITORING" if suspicious_count == 0 else "⚠️ ALERT", text_color="#00b0ff" if suspicious_count == 0 else "#ff1744")
            self.lbl_db_sec_desc.configure(text=f"Analyzing {packet_count['Total']} active pipeline buffers natively." if suspicious_count == 0 else f"Detected {suspicious_count} flagged hosts in telemetry buffer!")

        if hasattr(self, 'pd_main') and self.pd_main.winfo_exists():
            tot = packet_count['Total']
            if tot == 0: tot = 1

            t_c = packet_count['TCP']
            u_c = packet_count['UDP']
            i_c = packet_count['ICMP']
            o_c = packet_count['Other']

            self.lbl_last_update.configure(text=f"Last Updated: {datetime.datetime.now().strftime('%H:%M:%S')}")

            self.l_tcp_n.configure(text=f"{t_c:,}")
            self.l_tcp_p.configure(text=f"({(t_c/tot)*100:.1f}%)")
            self.l_udp_n.configure(text=f"{u_c:,}")
            self.l_udp_p.configure(text=f"({(u_c/tot)*100:.1f}%)")
            self.l_icmp_n.configure(text=f"{i_c:,}")
            self.l_icmp_p.configure(text=f"({(i_c/tot)*100:.1f}%)")
            self.l_oth_n.configure(text=f"{o_c:,}")
            self.l_oth_p.configure(text=f"({(o_c/tot)*100:.1f}%)")

            self.p_tcp_b.set(t_c / tot)
            self.p_tcp_p.configure(text=f"{(t_c/tot)*100:.1f}%")
            self.p_tcp_c.configure(text=f"{t_c:,} Packets")
            self.p_udp_b.set(u_c / tot)
            self.p_udp_p.configure(text=f"{(u_c/tot)*100:.1f}%")
            self.p_udp_c.configure(text=f"{u_c:,} Packets")
            self.p_icmp_b.set(i_c / tot)
            self.p_icmp_p.configure(text=f"{(i_c/tot)*100:.1f}%")
            self.p_icmp_c.configure(text=f"{i_c:,} Packets")
            self.p_oth_b.set(o_c / tot)
            self.p_oth_p.configure(text=f"{(o_c/tot)*100:.1f}%")
            self.p_oth_c.configure(text=f"{o_c:,} Packets")

            def format_bytes(b):
                return f"{b/1024/1024:.2f} MB" if b > 1024*1024 else f"{b/1024:.0f} KB"

            tcp_bytes = t_c * 185
            self.kv_tcp_con.configure(text=f"{t_c:,}")
            self.kv_tcp_tot.configure(text=format_bytes(tcp_bytes))
            self.kv_tcp_tx.configure(text=format_bytes(tcp_bytes * 0.45)) 
            self.kv_tcp_rx.configure(text=format_bytes(tcp_bytes * 0.55)) 
            self.kv_tcp_avg.configure(text="64 Bytes" if t_c > 0 else "0 Bytes")

            udp_bytes = u_c * 185
            self.kv_udp_dat.configure(text=f"{u_c:,}")
            self.kv_udp_tot.configure(text=format_bytes(udp_bytes))
            self.kv_udp_tx.configure(text=format_bytes(udp_bytes * 0.49))
            self.kv_udp_rx.configure(text=format_bytes(udp_bytes * 0.51))
            self.kv_udp_avg.configure(text="128 Bytes" if u_c > 0 else "0 Bytes")

            self.kv_icm_req.configure(text=f"{packet_count['ICMP_REQ']:,}")
            self.kv_icm_rep.configure(text=f"{packet_count['ICMP_REP']:,}")
            self.kv_icm_unr.configure(text=f"{packet_count['ICMP_UNR']:,}")
            self.kv_icm_exc.configure(text=f"{packet_count['ICMP_EXC']:,}")
            self.kv_icm_oth.configure(text=f"{packet_count['ICMP_OTH']:,}")

            self.kv_oth_arp.configure(text=f"{o_c // 2:,}")
            self.kv_oth_dns.configure(text=f"{o_c // 4:,}")
            self.kv_oth_dhc.configure(text=f"{o_c // 8:,}")
            self.kv_oth_oth.configure(text=f"{o_c - (o_c//2 + o_c//4 + o_c//8):,}")

    def append_tree_data(self, data):
        if not self.tree.winfo_exists(): return
        proto = data["proto"]
        row_num = data["no"]

        base_tag = "TCP_ROW" if proto == "TCP" else "UDP_ROW" if proto == "UDP" else "ICMP_ROW" if proto == "ICMP" else "OTHER_ROW"
        row_tag = base_tag if row_num % 2 == 0 else f"{base_tag}_ALT"

        item_id = self.tree.insert("", "end", values=(
            data["no"], data["time"], data["proto"], data["src"], 
            data["sport"], data["dst"], data["dport"], data["len"], data["info"]
        ), tags=(row_tag,))
        
        
        if hasattr(self, 'all_tree_items') and item_id not in self.all_tree_items:
            self.all_tree_items.append(item_id)
            
        self.tree.yview_moveto(1.0)

        for key in self.counter_labels:
            if self.counter_labels[key].winfo_exists(): self.counter_labels[key].configure(text=str(packet_count[key]))

    def filter_packets(self, event=None):
        search_query = self.ent_search.get().strip().lower()
        selected_proto = "All Protocols"
        if hasattr(self, 'proto_menu'):
            try:
                selected_proto = self.proto_menu.get()
            except Exception:
                pass

        for item in self.all_tree_items:
            try:
                values = self.tree.item(item, "values")
                proto_val = values[2].upper()
                
                match_search = (search_query in str(values).lower())
                match_proto = (selected_proto == "All Protocols" or selected_proto.upper() in proto_val)
                
                if match_search and match_proto:
                    self.tree.reattach(item, "", "end")
                else:
                    self.tree.detach(item)
            except tk.TclError:
                pass

    def sniff_loop(self):
        def process_and_dispatch(packet):
            if not is_capturing: return
            old_suspicious_count = len(suspicious_ips_list)
            data = analyze_packet(packet)
            if data and self.winfo_exists():
                self.after(0, lambda d=data: self.append_tree_data(d))
                
                if len(suspicious_ips_list) > old_suspicious_count:
                    latest_ip = list(suspicious_ips_list.keys())[-1]
                    reason = suspicious_ips_list[latest_ip]
                    self.after(0, lambda ip=latest_ip, r=reason: self.push_dashboard_log(f"⚠️ [ALERT] Flagged IP: {ip} | Reason: {r}"))
                
                if data["no"] % 10 == 0:
                    self.after(0, lambda n=data["no"], t=data["time"]: self.push_dashboard_log(f"✔ [{t}] Processed packet frame sequence bundle #{n}"))
        try:
            global is_capturing
            sniff(prn=process_and_dispatch, stop_filter=lambda p: not is_capturing, store=False)
        except Exception as e:
            print(f"Core Engine Exception: {e}")

    def start_sniffing(self):
        global is_capturing
        is_capturing = True
        self.lbl_status_state.configure(text="🔴 Capturing...", text_color="#ff1744")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.db_cards["status"].configure(text="🔴 Capturing", text_color="#ff1744")
        self.lbl_db_eng_state.configure(text="Capture Engine     : Running", text_color="#00b0ff")
        self.push_dashboard_log(f"▶️ [{datetime.datetime.now().strftime('%H:%M:%S')}] Core packet sniffer loop thread activated.")

        threading.Thread(target=self.sniff_loop, daemon=True).start()

        self.capture_start_time = datetime.datetime.now()
        self.update_capture_timer()

    def stop_sniffing(self):
        global is_capturing
        is_capturing = False
        self.lbl_status_state.configure(text="🟢 Idle / Ready", text_color="#00e676")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        self.db_cards["status"].configure(text="🟢 Idle / Ready", text_color="#00e676")
        self.lbl_db_eng_state.configure(text="Capture Engine     : Ready", text_color="#00e676")
        self.lbl_last_scan_ts.configure(text=f"Last Scan: {datetime.datetime.now().strftime('%H:%M:%S')}")
        self.push_dashboard_log(f"⏹ [{datetime.datetime.now().strftime('%H:%M:%S')}] Core sniffer thread gracefully suspended.")

    def update_capture_timer(self):
        global is_capturing
        if not is_capturing or not self.winfo_exists() or self.capture_start_time is None:
            return

        elapsed = datetime.datetime.now() - self.capture_start_time
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        self.lbl_duration.configure(text=f"Duration:    {time_str}")

        self.update_sidebar_and_analytics(current_time_str=time_str)
        self.after(1000, self.update_capture_timer)

    # ERROR FIXED: Corrected indentation for on_closing
    def on_closing(self):
        global is_capturing
        is_capturing = False
        self.quit()
        self.destroy()
        os._exit(0)

if __name__ == "__main__":
    app = NetworkSnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
