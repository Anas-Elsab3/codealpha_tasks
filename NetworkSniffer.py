import threading                                          #to run sniffing in the background 
import time                                               #generate time stamps
from tkinter import *                                     #GUI components
from tkinter import ttk, scrolledtext, messagebox         #GUI components
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap    #tools for sniffing

import os                                                 #to check admin permission

def is_admin():
    if os.name == 'nt':  # check if we are on Windows
        import ctypes    #to interact with system-level APIs in Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() # check if currnet is admin
        except:
            return False
    else:
        return os.geteuid() == 0 # non-Windows system

admin_mode = is_admin()

# GLobal variables
captured_packets = []                           #stores packets
sniffing = False                                #control stop sniffing 
sniffer_thread = None                           #a reference to the background that runs the sniffer

protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}    #labeling protocol numbers with their names

def packet_callback(packet):
    global captured_packets
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        proto = protocols.get(ip_layer.proto, str(ip_layer.proto)) # extract protocol
        src = ip_layer.src
        dst = ip_layer.dst
        info = f"[{proto}] {src} → {dst}"

        if packet.haslayer(TCP):
            info += f" | TCP Ports: {packet[TCP].sport} → {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            info += f" | UDP Ports: {packet[UDP].sport} → {packet[UDP].dport}"

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            info += f" | Payload: {repr(payload[:30])}" #take only 30 chars as payloads may be huge or messy

        captured_packets.append(packet)         #save the packet to the list
        output_text.insert(END, info + "\n")    #show the text
        output_text.yview(END)                  #auto-scrolling to the next line

def start_sniff():
    global sniffing, sniffer_thread
    if sniffing:                                #to prevent starting if it's already running
        return
    sniffing = True
    output_text.insert(END, "[+] Started sniffing...\n")
    sniffer_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, stop_filter=lambda _: not sniffing)) #prn to call the function for every packet and stop if sniffing is false
    sniffer_thread.daemon = True
    sniffer_thread.start()

def stop_sniff():
    global sniffing
    if sniffing:
        sniffing = False
        output_text.insert(END, "[!] Stopped sniffing.\n")

def save_capture():
    if not captured_packets:
        messagebox.showinfo("Save Capture", "No packets to save!")
        return

    if not admin_mode:
        messagebox.showwarning("Permission Denied",
            "⚠️ Unable to save .pcap.\n\nThis program needs to be run as administrator/root to save captured packets.")
        return

    filename = f"capture_{time.strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
    path = os.path.abspath(filename)
    try:
        wrpcap(path, captured_packets)
        messagebox.showinfo("Save Capture", f"Packets saved successfully:\n{path}")
    except Exception as e:
        messagebox.showerror("Save Error", f"Something went wrong:\n{e}")


# GUI setup
root = Tk()
root.title("Packet Sniffer GUI")
root.configure(bg="#1e1e1e")
root.resizable(True, True)

style = ttk.Style()
style.theme_use("clam")

# Button style
style.configure("TButton",
    font=("Segoe UI", 10, "bold"),
    foreground="#ffffff",
    background="#2e3f4f",
    borderwidth=0,
    padding=6)
style.map("TButton",
    background=[("active", "#3e5f7f")])

mainframe = ttk.Frame(root, padding="10", style="TFrame")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))

# Allow main window and frame to resize properly
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)



output_text = scrolledtext.ScrolledText(mainframe, width=100, height=25,
    font=("Consolas", 10), bg="#121212", fg="#f0f0f0", insertbackground="white")
output_text.grid(column=0, row=0, columnspan=3, padx=5, pady=10, sticky="nsew")

start_button = ttk.Button(mainframe, text="▶ Start", command=start_sniff)
start_button.grid(column=0, row=1, padx=55)

stop_button = ttk.Button(mainframe, text="■ Stop", command=stop_sniff)
stop_button.grid(column=1, row=1, padx=55)

save_button = ttk.Button(mainframe, text="💾 Save .pcap", command=save_capture)
save_button.grid(column=2, row=1, padx=5)

warning_label = Label(mainframe, text="⚠️ Run as Administrator to save .pcap files",
                      fg="#ffcc00", bg="#1e1e1e", font=("Segoe UI", 9, "italic"))
warning_label.grid(column=2, row=2, columnspan=3, pady=(10,0))

root.mainloop()







