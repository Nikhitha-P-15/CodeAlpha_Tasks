import tkinter as tk
from tkinter import scrolledtext, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from threading import Thread
import queue

# === Global Variables ===
packet_log = []
protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
log_queue = queue.Queue()

# === GUI Window ===
root = tk.Tk()
root.title("Network Sniffer with Live Chart")
root.geometry("1000x700")

# === Log Display ===
log_box = scrolledtext.ScrolledText(root, width=120, height=20)
log_box.pack(pady=10)

# === Filter Entry ===
filter_var = tk.StringVar()
tk.Label(root, text="Filter Protocol (TCP/UDP/ICMP):").pack()
filter_entry = tk.Entry(root, textvariable=filter_var)
filter_entry.pack()

# === Save Log Button ===
tk.Button(root, text="Save Log", command=lambda: save_log()).pack(pady=5)

# === Save Log Function ===
def save_log():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        try:
            with open(file_path, 'w') as f:
                for entry in packet_log:
                    f.write(entry + "\n")
        except Exception as e:
            print(f"Error saving file: {e}")

# === Analyze Packets Safely ===
def analyze_packet(packet):
    if IP in packet:
        proto_num = packet[IP].proto
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, "OTHER")

        if filter_var.get() and proto != filter_var.get().upper():
            return

        src = packet[IP].src
        dst = packet[IP].dst
        info = f"[{proto}] {src} -> {dst}"

        if proto == "TCP" and TCP in packet:
            info += f" | Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif proto == "UDP" and UDP in packet:
            info += f" | Ports: {packet[UDP].sport} -> {packet[UDP].dport}"

        payload = bytes(packet[IP].payload)
        if payload:
            info += f" | Payload: {payload[:30]}..."

        packet_log.append(info)
        protocol_count[proto] = protocol_count.get(proto, 0) + 1
        log_queue.put(info)  # Send to GUI thread

# === Update GUI Log Safely ===
def update_log_display():
    while not log_queue.empty():
        msg = log_queue.get()
        log_box.insert(tk.END, msg + "\n")
        log_box.see(tk.END)
    root.after(500, update_log_display)

# === Start Sniffing in Background Thread ===
def start_sniffing():
    sniff(prn=analyze_packet, store=False)

sniff_thread = Thread(target=start_sniffing, daemon=True)
sniff_thread.start()
update_log_display()  # Start the periodic log display update

# === Matplotlib Chart ===
fig, ax = plt.subplots(figsize=(6, 3))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

protocols = ["TCP", "UDP", "ICMP", "OTHER"]
bars = ax.bar(protocols, [0, 0, 0, 0])
ax.set_ylim(0, 50)
ax.set_ylabel("Packet Count")
ax.set_title("Live Protocol Traffic")

def update_chart(i):
    counts = [protocol_count[p] for p in protocols]
    for bar, val in zip(bars, counts):
        bar.set_height(val)
    canvas.draw()

ani = FuncAnimation(fig, update_chart, interval=1000, cache_frame_data=False)

# === Run the GUI Event Loop ===
root.mainloop()
