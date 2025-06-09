import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import subprocess
import shlex

class ZenmapLikeGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Zenmap-like Python Nmap GUI")
        self.geometry("1000x700")
        self.configure(bg="#222222")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.set_style()

        self.create_widgets()
        self.update_command_preview()

    def set_style(self):
        # Dark theme styles
        self.style.configure("TLabel", background="#222222", foreground="#ffffff", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#444444", foreground="#eee", font=("Segoe UI", 10))
        self.style.map("TButton",
                       background=[('active', '#666666')],
                       foreground=[('active', '#ffffff')])
        self.style.configure("TCheckbutton", background="#222222", foreground="#eee")
        self.style.configure("TCombobox",
                             fieldbackground="#444444",
                             background="#444444",
                             foreground="#eee")

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self, text="Scan Configuration")
        input_frame.configure(style="TLabelframe")
        input_frame.pack(fill='x', padx=10, pady=5)

        # Target IP/Hostname
        ttk.Label(input_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=0, column=1, sticky='w', padx=5, pady=2)
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        # Port Range
        ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.port_entry = ttk.Entry(input_frame, width=30)
        self.port_entry.grid(row=1, column=1, sticky='w', padx=5, pady=2)
        self.port_entry.insert(0, "1-1024")
        self.port_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        # Scan Type
        ttk.Label(input_frame, text="Scan Type:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.scan_type_combo = ttk.Combobox(input_frame, values=[
            "-sS (SYN Scan)",
            "-sT (Connect Scan)",
            "-sU (UDP Scan)",
            "-sN (Null Scan)",
            "-sF (FIN Scan)",
            "-sX (XMAS Scan)",
            "-sn (Ping Scan)"
        ], state="readonly", width=28)
        self.scan_type_combo.grid(row=2, column=1, sticky='w', padx=5, pady=2)
        self.scan_type_combo.current(0)
        self.scan_type_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())

        # Version Detection Checkbox
        self.version_detect = tk.BooleanVar()
        ttk.Checkbutton(input_frame, text="Version Detection (-sV)", variable=self.version_detect,
                        command=self.update_command_preview).grid(row=3, column=1, sticky='w', padx=5, pady=2)

        # OS Detection Checkbox
        self.os_detect = tk.BooleanVar()
        ttk.Checkbutton(input_frame, text="OS Detection (-O)", variable=self.os_detect,
                        command=self.update_command_preview).grid(row=4, column=1, sticky='w', padx=5, pady=2)

        # Timing Template
        ttk.Label(input_frame, text="Timing Template:").grid(row=5, column=0, sticky='w', padx=5, pady=2)
        self.timing_combo = ttk.Combobox(input_frame, values=["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"],
                                         state="readonly", width=28)
        self.timing_combo.grid(row=5, column=1, sticky='w', padx=5, pady=2)
        self.timing_combo.current(3)  # Default -T3
        self.timing_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())

        # NSE Script Name/Pattern
        ttk.Label(input_frame, text="NSE Script Name/Pattern:").grid(row=6, column=0, sticky='w', padx=5, pady=2)
        self.nse_script_entry = ttk.Entry(input_frame, width=30)
        self.nse_script_entry.grid(row=6, column=1, sticky='w', padx=5, pady=2)
        self.nse_script_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        # Optional External NSE Script Path
        ttk.Label(input_frame, text="Optional: External NSE Script Path:").grid(row=7, column=0, sticky='w', padx=5, pady=2)
        self.nse_path_entry = ttk.Entry(input_frame, width=30)
        self.nse_path_entry.grid(row=7, column=1, sticky='w', padx=5, pady=2)
        self.nse_path_entry.bind("<KeyRelease>", lambda e: self.update_command_preview())

        browse_btn = ttk.Button(input_frame, text="Browse", command=self.browse_nse_path)
        browse_btn.grid(row=7, column=2, padx=5, pady=2)

        # Nmap Command Preview Label
        ttk.Label(input_frame, text="Nmap Command Preview:").grid(row=8, column=0, sticky='nw', padx=5, pady=2)
        self.command_preview = tk.Text(input_frame, height=2, width=70, bg="#111111", fg="#00FF00",
                                       font=("Consolas", 10), insertbackground="#00FF00")
        self.command_preview.grid(row=8, column=1, columnspan=2, sticky='w', padx=5, pady=2)
        self.command_preview.configure(state='disabled')

        # Buttons Frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill='x', padx=10, pady=5)

        self.run_button = ttk.Button(btn_frame, text="Run Scan", command=self.run_scan)
        self.run_button.pack(side='left', padx=5)
        self.add_hover_effect(self.run_button)

        self.clear_button = ttk.Button(btn_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side='left', padx=5)
        self.add_hover_effect(self.clear_button)

        # Output Frame
        output_frame = ttk.LabelFrame(self, text="Scan Output")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text = ScrolledText(output_frame, bg="#111111", fg="#00FF00", font=("Consolas", 10), insertbackground="#00FF00")
        self.output_text.pack(fill='both', expand=True)
        self.output_text.configure(state='disabled')

    def add_hover_effect(self, button):
        def on_enter(e):
            button.configure(style="Hover.TButton")

        def on_leave(e):
            button.configure(style="TButton")

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

        # Define Hover style
        self.style.configure("Hover.TButton", background="#555555", foreground="#fff")

    def browse_nse_path(self):
        path = filedialog.askopenfilename(title="Select NSE Script", filetypes=[("Lua Files", "*.lua"), ("All Files", "*.*")])
        if path:
            self.nse_path_entry.delete(0, tk.END)
            self.nse_path_entry.insert(0, path)
            self.update_command_preview()

    def update_command_preview(self):
        target = self.target_entry.get().strip()
        ports = self.port_entry.get().strip()
        scan_type = self.scan_type_combo.get().split()[0]  # extract just flag like -sS
        timing = self.timing_combo.get()
        nse_script = self.nse_script_entry.get().strip()
        nse_path = self.nse_path_entry.get().strip()

        command_parts = ["nmap"]

        if scan_type:
            command_parts.append(scan_type)

        if self.version_detect.get():
            command_parts.append("-sV")

        if self.os_detect.get():
            command_parts.append("-O")

        if ports:
            command_parts.append("-p")
            command_parts.append(ports)

        if timing:
            command_parts.append(timing)

        if nse_script:
            command_parts.append(f"--script={nse_script}")

        if nse_path:
            command_parts.append(f"--script={nse_path}")

        if target:
            command_parts.append(target)

        command_str = " ".join(command_parts)
        self.command_preview.configure(state='normal')
        self.command_preview.delete(1.0, tk.END)
        self.command_preview.insert(tk.END, command_str)
        self.command_preview.configure(state='disabled')

    def run_scan(self):
        self.clear_output()
        cmd = self.command_preview.get(1.0, tk.END).strip()

        if not cmd or cmd == "nmap":
            messagebox.showerror("Error", "Please configure a valid Nmap scan command.")
            return

        # Disable Run button during scan
        self.run_button.config(state=tk.DISABLED)
        threading.Thread(target=self.execute_scan, args=(cmd,), daemon=True).start()

    def execute_scan(self, cmd):
        try:
            process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            self.append_output(f"Running command: {cmd}\n\n")

            for line in process.stdout:
                self.append_output(line)

            process.wait()
            self.append_output(f"\nScan finished with exit code {process.returncode}\n")

        except Exception as e:
            self.append_output(f"\nError running scan: {e}\n")

        self.run_button.config(state=tk.NORMAL)

    def append_output(self, text):
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')

    def clear_output(self):
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')


if __name__ == "__main__":
    app = ZenmapLikeGui()
    app.mainloop()
