import nmap
import re
import signal
import sys
import time
import threading
from datetime import datetime 
import subprocess
from tkinter import *
from tkinter import ttk, messagebox, filedialog

class PortScannerGUI:
    # Initializes the main GUI, sets window title, theme, and starts widget creation
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.configure(bg="black")
        Label(self.root, text="Port Scanner", font=("Arial", 28, "bold"), fg="cyan", bg="black").pack(pady=10)
        self.root.geometry("900x800")

        self.protocol_choice = StringVar(value="tcp")  
        self.filter_choice = StringVar(value="all")     

        self.nm = nmap.PortScanner()
        self.scanned_ports = []
        self.interrupted = False
        self.last_port = None

        self.create_widgets()
    # Creates and configures all the widgets in the GUI
    def create_widgets(self):
        font_large = ("Arial", 18)
        font_medium = ("Arial", 16)

        Label(self.root, text="Target IP:", font=font_medium, bg="black", fg="white").pack()
        self.ip_entry = Entry(self.root, font=font_medium, bg="gray30", fg="white", insertbackground="white", width=40)
        self.ip_entry.pack(pady=2)

        Label(self.root, text="Port Range (e.g., 20-80 or 80):", font=font_medium, bg="black", fg="white").pack()
        self.port_entry = Entry(self.root, font=font_medium, bg="gray30", fg="white", insertbackground="white", width=40)
        self.port_entry.pack(pady=2)

        proto_filter_frame = Frame(self.root, bg="black")
        proto_filter_frame.pack(pady=5)

        # Unified dropdown style matching buttons
        option_style = {
            "font": font_medium,
            "bg": "gray30",
            "fg": "white",
            "activebackground": "gray40",
            "activeforeground": "white",
            "width": 15,
            "relief": RAISED
        }

        # Protocol Dropdown (tcp, udp, both)
        protocol_menu = Menubutton(proto_filter_frame, textvariable=self.protocol_choice, **option_style)
        protocol_menu.menu = Menu(protocol_menu, tearoff=0, bg="gray30", fg="white", font=font_medium)
        for option in ["tcp", "udp", "both"]:
            protocol_menu.menu.add_radiobutton(label=option, variable=self.protocol_choice, value=option)
        protocol_menu["menu"] = protocol_menu.menu
        protocol_menu.grid(row=1, column=0, padx=10)

        # Filter Dropdown (all, open, closed, etc.)
        filter_menu = Menubutton(proto_filter_frame, textvariable=self.filter_choice, **option_style)
        filter_menu.menu = Menu(filter_menu, tearoff=0, bg="gray30", fg="white", font=font_medium)
        for option in ["all", "open", "closed", "filtered", "open|filtered"]:
            filter_menu.menu.add_radiobutton(label=option, variable=self.filter_choice, value=option)
        filter_menu["menu"] = filter_menu.menu
        filter_menu.grid(row=1, column=1, padx=10)

        self.save_var = BooleanVar()
        Checkbutton(self.root, text="Save results to file", variable=self.save_var, font=font_medium,
                    bg="black", fg="white", selectcolor="black").pack(pady=5)

        self.ping_label = Label(self.root, text="Pinging host...", font=font_medium, fg="blue", bg="black")
        self.ping_circle = Canvas(self.root, width=20, height=20, bg="black", highlightthickness=0)
        self.circle = self.ping_circle.create_oval(2, 2, 18, 18, fill="blue")
        self.ping_circle.pack()
        self.ping_label.pack()
        self.ping_label.pack_forget()
        self.ping_circle.pack_forget()

        self.progress_frame = Frame(self.root, bg="black")
        self.progress_frame.pack(pady=10)

        self.progress = ttk.Progressbar(self.progress_frame, length=500, mode='determinate')
        self.progress.pack(side=LEFT)

        self.percent_label = Label(self.progress_frame, text="0%", font=font_medium, bg="black", fg="white")
        self.percent_label.pack(side=LEFT, padx=10)

        self.estimate_label = Label(self.root, text="Estimated time: N/A", font=font_medium, bg="black", fg="white")
        self.estimate_label.pack(pady=(0, 10))

        button_frame = Frame(self.root, bg="black")
        button_frame.pack(pady=10)

        btn_style = {"font": font_medium, "bg": "gray30", "fg": "white", "width": 15}

        self.start_btn = Button(button_frame, text="Start Scan", command=self.start_scan_thread, **btn_style)
        self.start_btn.pack(side=LEFT, padx=20)

        self.cancel_btn = Button(button_frame, text="Cancel Scan", command=self.cancel_scan, **btn_style)
        self.cancel_btn.pack(side=LEFT, padx=20)

        self.output = Text(self.root, height=25, width=90, font=("Courier", 14), bg="black", fg="white")
        self.output.pack(pady=10)
    # Extracts a numeric port number from a text label
    def extract_port_number(self, label):
        match = re.search(r"(\d+)", label)
        return int(match.group()) if match else 0
    # Starts the scan in a new thread to avoid freezing the GUI
    def start_scan_thread(self):
        threading.Thread(target=self.start_scan).start()
    # Checks if the host (IP) is reachable by sending a ping
    def is_host_alive(self, ip):
        try:
            self.ping_label.pack()
            self.ping_circle.pack()
            self.root.update_idletasks()
            result = subprocess.run(["ping", "-n" if sys.platform.startswith("win") else "-c", "1", ip],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.ping_label.pack_forget()
            self.ping_circle.pack_forget()
            return result.returncode == 0
        except Exception:
            self.ping_label.pack_forget()
            self.ping_circle.pack_forget()
            return False
    # Validates input, performs the port scan using nmap, and displays results
    def start_scan(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output.delete("1.0", END)
        self.interrupted = False
        self.scanned_ports = []
        ip = self.ip_entry.get().strip()
        ports_input = self.port_entry.get().strip()
        #used regex to validate ip address is correct
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not ip_pattern.match(ip):
            messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
            return

        if not self.is_host_alive(ip):
            messagebox.showerror("Host Unreachable", f"The target {ip} is offline or unreachable.")
            return

        try:
            if '-' in ports_input:
                start_port, end_port = map(int, ports_input.split('-'))
            else:
                start_port = end_port = int(ports_input)

            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535) or start_port > end_port:
                raise ValueError
        except:
            messagebox.showerror("Invalid Port Range", "Please enter a valid port or port range like 80 or 20-80.")
            return

        protocol = self.protocol_choice.get()
        filter_choice = self.filter_choice.get()
        save_to_file = self.save_var.get()

        total_ports = end_port - start_port + 1
        self.progress["maximum"] = total_ports

        delay_per_port = 0.05
        estimated_total = delay_per_port * total_ports
        self.estimate_label.config(text=f"Estimated time: ~{estimated_total:.2f} sec")

        start_time = time.time()
        results = []
        open_count = 0

        for i, port in enumerate(range(start_port, end_port + 1)):
            if self.interrupted:
                break
            self.last_port = port

            try:
                if protocol in ["tcp", "both"]:
                    tcp_scan = self.nm.scan(ip, str(port), arguments="-sS")
                    state = self.nm[ip]['tcp'][port]['state'] if 'tcp' in self.nm[ip] and port in self.nm[ip]['tcp'] else 'filtered'
                    label = f"TCP Port {port}"
                    if filter_choice == 'all' or filter_choice == state or \
                       (filter_choice == 'open|filtered' and state in ['open', 'filtered']):
                        results.append(f"{label}: {state}")
                        self.scanned_ports.append((label, state))
                        if state == 'open':
                            open_count += 1

                if protocol in ["udp", "both"]:
                    udp_scan = self.nm.scan(ip, str(port), arguments="-sU")
                    state = self.nm[ip]['udp'][port]['state'] if 'udp' in self.nm[ip] and port in self.nm[ip]['udp'] else 'filtered'
                    label = f"UDP Port {port}"
                    if filter_choice == 'all' or filter_choice == state or \
                       (filter_choice == 'open|filtered' and state in ['open', 'filtered']):
                        results.append(f"{label}: {state}")
                        self.scanned_ports.append((label, state))
                        if state == 'open':
                            open_count += 1

            except Exception as e:
                results.append(f"Port {port}: Error - {e}")

            self.progress["value"] = i + 1
            self.percent_label.config(text=f"{int(((i + 1) / total_ports) * 100)}%")
            self.root.update_idletasks()
            time.sleep(delay_per_port)

        end_time = time.time()
        scan_time = end_time - start_time

        self.output.insert(END, f"\nScan Results ({ip}:{ports_input})\n")
        self.output.insert(END, f"Timestamp: {timestamp}\n")
        self.output.insert(END, "\n".join(results))
        self.output.insert(END, f"\n\nOpen Ports: {open_count}")
        self.output.insert(END, f"\nTotal Scan Time: ~{scan_time:.2f} seconds\n")
        #saving the results in a file
        if save_to_file:
            filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if filename:
                try:
                    with open(filename, "w") as f:
                        f.write(f"Timestamp: {timestamp}\n")
                        f.write(f"Scan Results for {ip} ({protocol.upper()})\n")
                        f.write(f"Port Range: {start_port}-{end_port}\n")
                        f.write(f"Filter Mode: {filter_choice}\n")
                        f.write(f"Scan Duration: {round(scan_time, 2)} seconds\n")
                        f.write(f"Total Open Ports: {open_count}\n\n")
                        for label, state in sorted(self.scanned_ports, key=lambda x: self.extract_port_number(x[0])):
                            if filter_choice == "open" and state != "open":
                                continue
                            elif filter_choice == "closed" and state != "closed":
                                continue
                            elif filter_choice == "filtered" and state != "filtered":
                                continue
                            elif filter_choice == "open|filtered" and state not in ["open", "filtered"]:
                                continue
                            f.write(f"{label}: {state}\n")
                    messagebox.showinfo("Saved", f"Results saved to {filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file: {e}")
    # Stops the scan and notifies the user that scanning was canceled
    def cancel_scan(self):
        self.interrupted = True
        self.output.insert(END, f"\n\nScan canceled. Last scanned port: {self.last_port}\n")

if __name__ == "__main__":
    root = Tk()
    app = PortScannerGUI(root)
    root.mainloop()
