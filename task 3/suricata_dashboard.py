import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import time
import threading
import os
from datetime import datetime

LOG_FILE = "logs/fast.log"
RESPONSE_LOG = "logs/alert_responses.log"
RULE_FILE = "/etc/suricata/rules/local.rules"  # Change path if using test system

ALERT_KEYWORDS = {
    "SQL": "red",
    "XSS": "orange",
    "ICMP": "blue",
    "HTTP": "green",
    "SCAN": "magenta",
    "Malware": "purple",
}

def log_response(alert_text):
    with open(RESPONSE_LOG, "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] RESPONSE LOGGED: {alert_text}")

def highlight_alert(text_widget, line):
    for keyword, color in ALERT_KEYWORDS.items():
        if keyword in line:
            start_idx = text_widget.index(tk.END + f"-1line")
            end_idx = text_widget.index(tk.END)
            text_widget.tag_add(keyword, start_idx, end_idx)
            text_widget.tag_config(keyword, foreground=color)
            log_response(line)
            break

def tail_log(text_widget):
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                text_widget.insert(tk.END, line)
                highlight_alert(text_widget, line)
                text_widget.see(tk.END)
            else:
                time.sleep(1)

def rule_guidance():
    popup = tk.Toplevel()
    popup.title("🛠️ Suricata Rule Setup Guide")
    popup.geometry("700x450")

    guidance = tk.Text(popup, wrap=tk.WORD)
    guidance.insert(tk.END, """""")
    guidance.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

def show_rules():
    popup = tk.Toplevel()
    popup.title("📄 View Existing Suricata Rules")
    popup.geometry("700x400")

    text = ScrolledText(popup, wrap=tk.WORD, font=("Courier", 10))
    try:
        with open(RULE_FILE, "r") as f:
            text.insert(tk.END, f.read())
    except Exception as e:
        text.insert(tk.END, f"Error: {e}")
    text.pack(fill=tk.BOTH, expand=True)

def create_rule_form():
    def save_rule():
        proto = proto_entry.get().strip()
        port = port_entry.get().strip()
        keyword = keyword_entry.get().strip()
        sid = sid_entry.get().strip()
        msg = msg_entry.get().strip()

        rule = f'alert {proto} any any -> any {port} (msg:"{msg}"; content:"{keyword}"; sid:{sid}; rev:1;)'

        try:
            with open(RULE_FILE, "a") as f:
                f.write(rule + "\n")
            confirm_label.config(text="✅ Rule saved successfully!")
        except Exception as e:
            confirm_label.config(text=f"❌ Failed to save rule: {e}")

    form = tk.Toplevel()
    form.title("📝 Create New Suricata Rule")
    form.geometry("500x300")

    tk.Label(form, text="Protocol (tcp/udp):").pack()
    proto_entry = tk.Entry(form)
    proto_entry.pack()

    tk.Label(form, text="Destination Port:").pack()
    port_entry = tk.Entry(form)
    port_entry.pack()

    tk.Label(form, text="Content Match (e.g., SELECT):").pack()
    keyword_entry = tk.Entry(form)
    keyword_entry.pack()

    tk.Label(form, text="SID (unique rule ID):").pack()
    sid_entry = tk.Entry(form)
    sid_entry.pack()

    tk.Label(form, text="Message (description):").pack()
    msg_entry = tk.Entry(form)
    msg_entry.pack()

    tk.Button(form, text="💾 Save Rule", command=save_rule, bg="green", fg="white").pack(pady=10)
    confirm_label = tk.Label(form, text="")
    confirm_label.pack()

def run_gui():
    root = tk.Tk()
    root.title("🚨 Suricata Real-Time Intrusion Detection")
    root.geometry("950x550")
    root.configure(bg="#f0f0f0")
    
    title = tk.Label(root, text="📡 Suricata Real-Time Alert Monitor", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
    title.pack(pady=10)

    text_area = ScrolledText(root, font=("Courier", 10), bg="#1e1e1e", fg="white")
    text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    btn_frame = tk.Frame(root, bg="#f0f0f0")
    btn_frame.pack(pady=5)

    tk.Button(btn_frame, text="📖 Rule Setup Guide", command=rule_guidance, bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="📄 View Rules", command=show_rules, bg="#673AB7", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="📝 Create Rule", command=create_rule_form, bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=5)

    t = threading.Thread(target=tail_log, args=(text_area,), daemon=True)
    t.start()

    root.mainloop()

if __name__ == "__main__":
    run_gui()
