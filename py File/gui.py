"""
gui.py - desktop UI for the cipher demo. Run the same file on both machines.

  python gui.py        (Windows / macOS)
  python3 gui.py       (Kali; if tkinter is missing: sudo apt install python3-tk)

Needs cipher.py in the same folder.
"""
import queue
import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from cipher import decrypt, encrypt


class App:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()      # network threads -> UI thread
        self.server = None
        root.title("Cipher Demo")
        root.minsize(640, 520)

        pad = {"padx": 6, "pady": 4}

        # --- settings ---
        top = ttk.LabelFrame(root, text="Settings")
        top.pack(fill="x", **pad)
        ttk.Label(top, text="Secret key:").grid(row=0, column=0, sticky="w", **pad)
        self.key = tk.StringVar(value="Mozard8")
        ttk.Entry(top, textvariable=self.key, width=28).grid(row=0, column=1, sticky="w", **pad)
        self.use_cipher = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Encrypt / decrypt messages",
                        variable=self.use_cipher).grid(row=0, column=2, columnspan=2, sticky="w", **pad)

        # --- receive ---
        rx = ttk.LabelFrame(root, text="Receive")
        rx.pack(fill="x", **pad)
        ttk.Label(rx, text="Listen on port:").grid(row=0, column=0, sticky="w", **pad)
        self.listen_port = tk.StringVar(value="5000")
        ttk.Entry(rx, textvariable=self.listen_port, width=8).grid(row=0, column=1, sticky="w", **pad)
        self.listen_btn = ttk.Button(rx, text="Start listening", command=self.toggle_listen)
        self.listen_btn.grid(row=0, column=2, **pad)
        self.status = ttk.Label(rx, text="Not listening")
        self.status.grid(row=0, column=3, sticky="w", **pad)

        # --- send ---
        tx = ttk.LabelFrame(root, text="Send")
        tx.pack(fill="x", **pad)
        tx.columnconfigure(1, weight=1)
        ttk.Label(tx, text="Send to IP:").grid(row=0, column=0, sticky="w", **pad)
        self.host = tk.StringVar(value="192.168.56.101")
        ttk.Entry(tx, textvariable=self.host, width=18).grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(tx, text="Port:").grid(row=0, column=2, sticky="e", **pad)
        self.send_port = tk.StringVar(value="5000")
        ttk.Entry(tx, textvariable=self.send_port, width=8).grid(row=0, column=3, sticky="w", **pad)
        ttk.Label(tx, text="Message:").grid(row=1, column=0, sticky="w", **pad)
        self.message = tk.StringVar()
        entry = ttk.Entry(tx, textvariable=self.message)
        entry.grid(row=1, column=1, columnspan=2, sticky="ew", **pad)
        entry.bind("<Return>", lambda e: self.send())
        ttk.Button(tx, text="Send", command=self.send).grid(row=1, column=3, **pad)

        # --- log ---
        logf = ttk.LabelFrame(root, text="Activity")
        logf.pack(fill="both", expand=True, **pad)
        self.log = scrolledtext.ScrolledText(logf, height=14, state="disabled",
                                             font=("Courier", 10), wrap="word")
        self.log.pack(fill="both", expand=True, padx=4, pady=4)
        self.log.tag_config("sent", foreground="#1a5fb4")
        self.log.tag_config("recv", foreground="#26a269")
        self.log.tag_config("err", foreground="#c01c28")
        ttk.Button(logf, text="Clear", command=self.clear_log).pack(anchor="e", padx=4, pady=(0, 4))

        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)

    # ---------- helpers ----------
    def write(self, text, tag=None):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def port_of(self, var):
        try:
            p = int(var.get())
            if 1 <= p <= 65535:
                return p
        except ValueError:
            pass
        messagebox.showerror("Cipher Demo", "Port must be a number from 1 to 65535.")
        return None

    def poll(self):
        """Runs on the UI thread; shows anything the network threads queued."""
        while not self.events.empty():
            kind, data = self.events.get()
            if kind == "recv":
                addr, payload = data
                self.write(f"<-- RECEIVED from {addr} ({len(payload)} bytes)", "recv")
                if self.use_cipher.get():
                    self.write(f"    On the wire (hex): {payload.hex()}")
                    try:
                        self.write(f"    Decrypted        : {decrypt(payload, self.key.get())}", "recv")
                    except ValueError as e:
                        self.write(f"    Could not decrypt: {e}", "err")
                else:
                    self.write(f"    Plaintext        : {payload.decode('utf-8', errors='replace')}", "recv")
            elif kind == "sent":
                self.write(f"    Delivered to {data}", "sent")
            elif kind == "err":
                self.write(f"    ERROR: {data}", "err")
        self.root.after(100, self.poll)

    # ---------- receive ----------
    def toggle_listen(self):
        if self.server:
            self.server.close()
            self.server = None
            self.listen_btn.config(text="Start listening")
            self.status.config(text="Not listening")
            return
        port = self.port_of(self.listen_port)
        if port is None:
            return
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
        except OSError as e:
            messagebox.showerror("Cipher Demo", f"Could not listen on port {port}:\n{e}")
            return
        self.server = srv
        self.listen_btn.config(text="Stop listening")
        self.status.config(text=f"Listening on port {port}")
        threading.Thread(target=self.accept_loop, args=(srv,), daemon=True).start()

    def accept_loop(self, srv):
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                return                      # socket was closed
            with conn:
                conn.settimeout(5)
                data = b""
                try:
                    while chunk := conn.recv(4096):
                        data += chunk
                except OSError:
                    pass
            if data:
                self.events.put(("recv", (addr[0], data)))

    # ---------- send ----------
    def send(self):
        text = self.message.get()
        host = self.host.get().strip()
        port = self.port_of(self.send_port)
        if port is None or not text or not host:
            return
        if self.use_cipher.get():
            try:
                payload = encrypt(text, self.key.get())
            except ValueError as e:
                messagebox.showerror("Cipher Demo", str(e))
                return
            self.write(f"--> SENDING to {host}:{port} (encrypted)", "sent")
            self.write(f"    Plaintext        : {text}")
            self.write(f"    On the wire (hex): {payload.hex()}")
        else:
            payload = text.encode("utf-8")
            self.write(f"--> SENDING to {host}:{port} (PLAINTEXT, no encryption)", "sent")
            self.write(f"    On the wire      : {text}")
        self.message.set("")
        threading.Thread(target=self.send_worker, args=(host, port, payload), daemon=True).start()

    def send_worker(self, host, port, payload):
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(payload)
            self.events.put(("sent", f"{host}:{port}"))
        except OSError as e:
            self.events.put(("err", f"could not send to {host}:{port} - {e}"))

    def close(self):
        if self.server:
            self.server.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()