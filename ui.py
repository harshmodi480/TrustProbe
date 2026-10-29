import os
import sys
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
SERVERS_FILE = os.path.join(ROOT, "ui_servers.json")
OUT_DIR = os.path.join(ROOT, "out")

DOCKER_PATH = r"C:\Users\modiha1\AppData\Local\Programs\DockerDesktop\resources\bin"


def get_env():
    env = os.environ.copy()
    if DOCKER_PATH not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + ";" + DOCKER_PATH
    return env


def load_servers():
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE) as f:
            return json.load(f)
    return []


def save_servers(servers):
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)


def generate_config(server, config_path):
    source_type = server.get("source_type", "path")
    source_val = server.get("source", "")
    runtime = server.get("runtime", "python")
    command = server.get("command", "python server.py").split()
    mode = server.get("mode", "full")
    allow_network = server.get("allow_network", False)
    out_dir = server.get("out_dir", os.path.join(OUT_DIR, server["name"].replace(" ", "_")))

    source_block = {"type": source_type}
    if source_type == "path":
        source_block["path"] = source_val
    elif source_type == "npm":
        source_block["package"] = source_val
    elif source_type == "pypi":
        source_block["package"] = source_val

    config = {
        "name": server["name"],
        "server": {
            "source": source_block,
            "runtime": runtime,
            "command": command,
            "startup_timeout_s": int(server.get("startup_timeout", 30)),
            "declared_capabilities": [],
        },
        "scan": {
            "mode": mode,
            "total_timeout_s": int(server.get("total_timeout", 180)),
            "static": {"llm_review": False},
            "dynamic": {
                "enabled": mode == "full",
                "call_timeout_s": 20,
                "max_calls_per_tool": 12,
                "max_total_calls": 200,
                "rugpull_delay_s": 10,
            },
        },
        "policy": {
            "do_not_use_on": ["critical"],
            "allow_network": allow_network,
        },
        "llm": {"enabled": False, "provider_env": "TRUSTPROBE_LLM_API_KEY"},
        "out_dir": out_dir,
    }

    if runtime == "python":
        install_file = server.get("install_file", "requirements.txt")
        if install_file:
            config["server"]["install"] = {"requirements": install_file}
    elif runtime == "node":
        config["server"]["install"] = {"npm": True}

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


class MCPScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TrustProbe — MCP Security Scanner")
        self.root.geometry("1100x720")
        self.root.configure(bg="#0f1117")
        self.root.resizable(True, True)

        self.servers = load_servers()
        self.scan_process = None
        self._build_styles()
        self._build_layout()
        self._refresh_server_list()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = "#0f1117"
        panel = "#1a1d27"
        accent = "#5865f2"
        fg = "#e2e8f0"
        muted = "#64748b"
        border = "#2d3148"

        style.configure("TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=panel, foreground=fg, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=bg, foreground=fg, font=("Segoe UI", 13, "bold"))
        style.configure("Muted.TLabel", background=panel, foreground=muted, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=bg, foreground=fg, font=("Segoe UI", 16, "bold"))

        style.configure("Accent.TButton", background=accent, foreground="white",
                        font=("Segoe UI", 10, "bold"), borderwidth=0, focusthickness=0, padding=(12, 6))
        style.map("Accent.TButton", background=[("active", "#4752c4")])

        style.configure("Danger.TButton", background="#dc2626", foreground="white",
                        font=("Segoe UI", 10), borderwidth=0, focusthickness=0, padding=(10, 6))
        style.map("Danger.TButton", background=[("active", "#b91c1c")])

        style.configure("Ghost.TButton", background=panel, foreground=fg,
                        font=("Segoe UI", 10), borderwidth=1, focusthickness=0, padding=(10, 6))
        style.map("Ghost.TButton", background=[("active", border)])

        style.configure("TEntry", fieldbackground="#252836", foreground=fg,
                        bordercolor=border, insertcolor=fg, font=("Segoe UI", 10))
        style.configure("TCombobox", fieldbackground="#252836", foreground=fg,
                        bordercolor=border, font=("Segoe UI", 10))
        style.map("TCombobox", fieldbackground=[("readonly", "#252836")])

        style.configure("Treeview", background="#1a1d27", foreground=fg,
                        fieldbackground="#1a1d27", borderwidth=0, font=("Segoe UI", 10), rowheight=34)
        style.configure("Treeview.Heading", background="#252836", foreground=muted,
                        font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", accent)], foreground=[("selected", "white")])

        style.configure("TSeparator", background=border)
        style.configure("TCheckbutton", background=panel, foreground=fg, font=("Segoe UI", 10))

        self.colors = {"bg": bg, "panel": panel, "accent": accent, "fg": fg,
                       "muted": muted, "border": border,
                       "success": "#22c55e", "warn": "#f59e0b", "danger": "#ef4444"}

    def _build_layout(self):
        c = self.colors

        # Top bar
        topbar = tk.Frame(self.root, bg=c["panel"], height=52)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="  TrustProbe", bg=c["panel"], fg=c["fg"],
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=12, pady=10)
        tk.Label(topbar, text="MCP Security Scanner", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 10)).pack(side="left", pady=10)

        # Status indicator
        self.docker_dot = tk.Label(topbar, text="●", bg=c["panel"], fg=c["warn"],
                                   font=("Segoe UI", 12))
        self.docker_dot.pack(side="right", padx=4)
        tk.Label(topbar, text="Docker", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(side="right", padx=(8, 0))

        # Main split
        main = tk.Frame(self.root, bg=c["bg"])
        main.pack(fill="both", expand=True)

        # Left sidebar
        sidebar = tk.Frame(main, bg=c["panel"], width=280)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="MCP Servers", bg=c["panel"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(16, 8))

        self.server_list = tk.Listbox(sidebar, bg=c["panel"], fg=c["fg"],
                                      selectbackground=c["accent"], selectforeground="white",
                                      borderwidth=0, highlightthickness=0,
                                      font=("Segoe UI", 10), activestyle="none",
                                      cursor="hand2")
        self.server_list.pack(fill="both", expand=True, padx=8)
        self.server_list.bind("<<ListboxSelect>>", self._on_server_select)

        btn_row = tk.Frame(sidebar, bg=c["panel"])
        btn_row.pack(fill="x", padx=8, pady=12)
        ttk.Button(btn_row, text="+ Add Server", style="Accent.TButton",
                   command=self._open_add_dialog).pack(side="left", fill="x", expand=True)
        ttk.Button(btn_row, text="Delete", style="Danger.TButton",
                   command=self._delete_server).pack(side="left", padx=(6, 0))

        # Right panel — notebook tabs
        right = tk.Frame(main, bg=c["bg"])
        right.pack(side="left", fill="both", expand=True)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self._build_scan_tab()
        self._build_log_tab()
        self._build_results_tab()

        # Check docker async
        threading.Thread(target=self._check_docker, daemon=True).start()

    def _build_scan_tab(self):
        c = self.colors
        tab = tk.Frame(self.notebook, bg=c["bg"])
        self.notebook.add(tab, text="  Scan  ")

        # Server info card
        card = tk.Frame(tab, bg=c["panel"], bd=0)
        card.pack(fill="x", padx=4, pady=(8, 0))

        tk.Label(card, text="Selected Server", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(12, 2))
        self.sel_name = tk.Label(card, text="No server selected", bg=c["panel"], fg=c["fg"],
                                  font=("Segoe UI", 13, "bold"))
        self.sel_name.pack(anchor="w", padx=16)

        info_row = tk.Frame(card, bg=c["panel"])
        info_row.pack(fill="x", padx=16, pady=(4, 12))
        self.sel_runtime = tk.Label(info_row, text="", bg=c["panel"], fg=c["muted"],
                                     font=("Segoe UI", 9))
        self.sel_runtime.pack(side="left")
        self.sel_source = tk.Label(info_row, text="", bg=c["panel"], fg=c["muted"],
                                    font=("Segoe UI", 9))
        self.sel_source.pack(side="left", padx=(16, 0))

        sep = tk.Frame(tab, bg=c["border"], height=1)
        sep.pack(fill="x", padx=4, pady=8)

        # Scan options
        opts = tk.Frame(tab, bg=c["panel"])
        opts.pack(fill="x", padx=4)

        tk.Label(opts, text="Scan Options", bg=c["panel"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 8))

        row1 = tk.Frame(opts, bg=c["panel"])
        row1.pack(fill="x", padx=16, pady=4)

        tk.Label(row1, text="Mode", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w")
        tk.Label(row1, text="Startup Timeout (s)", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).grid(row=0, column=1, sticky="w", padx=(32, 0))
        tk.Label(row1, text="Total Timeout (s)", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).grid(row=0, column=2, sticky="w", padx=(32, 0))

        self.opt_mode = ttk.Combobox(row1, values=["full", "static"], width=12, state="readonly")
        self.opt_mode.set("full")
        self.opt_mode.grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.opt_startup = ttk.Entry(row1, width=10)
        self.opt_startup.insert(0, "30")
        self.opt_startup.grid(row=1, column=1, sticky="w", padx=(32, 0), pady=(2, 0))

        self.opt_timeout = ttk.Entry(row1, width=10)
        self.opt_timeout.insert(0, "180")
        self.opt_timeout.grid(row=1, column=2, sticky="w", padx=(32, 0), pady=(2, 0))

        row2 = tk.Frame(opts, bg=c["panel"])
        row2.pack(fill="x", padx=16, pady=(10, 12))

        self.opt_network = tk.BooleanVar(value=False)
        self.opt_llm = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Allow Network", variable=self.opt_network,
                       bg=c["panel"], fg=c["fg"], selectcolor=c["bg"],
                       activebackground=c["panel"], activeforeground=c["fg"],
                       font=("Segoe UI", 10)).pack(side="left")
        tk.Checkbutton(row2, text="Enable LLM Review", variable=self.opt_llm,
                       bg=c["panel"], fg=c["fg"], selectcolor=c["bg"],
                       activebackground=c["panel"], activeforeground=c["fg"],
                       font=("Segoe UI", 10)).pack(side="left", padx=(20, 0))

        sep2 = tk.Frame(tab, bg=c["border"], height=1)
        sep2.pack(fill="x", padx=4, pady=8)

        # Scan buttons
        btn_area = tk.Frame(tab, bg=c["bg"])
        btn_area.pack(fill="x", padx=4, pady=4)

        ttk.Button(btn_area, text="Run Scan", style="Accent.TButton",
                   command=self._run_scan).pack(side="left", padx=(0, 8))
        ttk.Button(btn_area, text="Quick Scan", style="Ghost.TButton",
                   command=self._run_quick).pack(side="left", padx=(0, 8))
        ttk.Button(btn_area, text="Validate Only", style="Ghost.TButton",
                   command=self._run_validate).pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(btn_area, text="Stop", style="Danger.TButton",
                                    command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="left")

        # Progress
        prog_frame = tk.Frame(tab, bg=c["bg"])
        prog_frame.pack(fill="x", padx=4, pady=(12, 4))
        self.progress_label = tk.Label(prog_frame, text="", bg=c["bg"], fg=c["muted"],
                                        font=("Segoe UI", 9))
        self.progress_label.pack(anchor="w")
        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate", length=400)
        self.progress.pack(fill="x", pady=(4, 0))

    def _build_log_tab(self):
        c = self.colors
        tab = tk.Frame(self.notebook, bg=c["bg"])
        self.notebook.add(tab, text="  Output  ")

        toolbar = tk.Frame(tab, bg=c["bg"])
        toolbar.pack(fill="x", padx=4, pady=(8, 4))
        tk.Label(toolbar, text="Live Output", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(toolbar, text="Clear", style="Ghost.TButton",
                   command=lambda: self.log_box.delete("1.0", "end")).pack(side="right")

        self.log_box = scrolledtext.ScrolledText(
            tab, bg="#0d0f18", fg="#a8b4c8", font=("Consolas", 10),
            borderwidth=0, insertbackground="white", state="disabled",
            wrap="word", padx=12, pady=12)
        self.log_box.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        self.log_box.tag_config("ok", foreground=c["success"])
        self.log_box.tag_config("warn", foreground=c["warn"])
        self.log_box.tag_config("err", foreground=c["danger"])
        self.log_box.tag_config("info", foreground="#60a5fa")

    def _build_results_tab(self):
        c = self.colors
        tab = tk.Frame(self.notebook, bg=c["bg"])
        self.notebook.add(tab, text="  Results  ")

        toolbar = tk.Frame(tab, bg=c["bg"])
        toolbar.pack(fill="x", padx=4, pady=(8, 4))
        tk.Label(toolbar, text="Scan Results", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(toolbar, text="Open Report", style="Accent.TButton",
                   command=self._open_report).pack(side="right")
        ttk.Button(toolbar, text="Refresh", style="Ghost.TButton",
                   command=self._load_results).pack(side="right", padx=(0, 8))

        # Verdict banner
        self.verdict_frame = tk.Frame(tab, bg=c["panel"])
        self.verdict_frame.pack(fill="x", padx=4, pady=(0, 8))
        self.verdict_label = tk.Label(self.verdict_frame, text="No results yet",
                                       bg=c["panel"], fg=c["muted"],
                                       font=("Segoe UI", 12, "bold"), pady=12)
        self.verdict_label.pack()

        # Findings table
        cols = ("id", "severity", "category", "title")
        self.results_tree = ttk.Treeview(tab, columns=cols, show="headings", selectmode="browse")
        self.results_tree.heading("id", text="Rule ID")
        self.results_tree.heading("severity", text="Severity")
        self.results_tree.heading("category", text="Category")
        self.results_tree.heading("title", text="Finding")
        self.results_tree.column("id", width=110, anchor="w")
        self.results_tree.column("severity", width=90, anchor="center")
        self.results_tree.column("category", width=130, anchor="w")
        self.results_tree.column("title", width=500, anchor="w")

        scroll = ttk.Scrollbar(tab, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scroll.set)
        self.results_tree.pack(fill="both", expand=True, padx=4, side="left")
        scroll.pack(side="right", fill="y", pady=4)

        self.results_tree.tag_configure("critical", foreground=c["danger"])
        self.results_tree.tag_configure("high", foreground=c["warn"])
        self.results_tree.tag_configure("medium", foreground="#fb923c")
        self.results_tree.tag_configure("low", foreground=c["success"])
        self.results_tree.tag_configure("info", foreground="#60a5fa")

    # ── Server list ──────────────────────────────────────────────────────────

    def _refresh_server_list(self):
        self.server_list.delete(0, "end")
        for s in self.servers:
            self.server_list.insert("end", f"  {s['name']}")

    def _on_server_select(self, _=None):
        sel = self.server_list.curselection()
        if not sel:
            return
        s = self.servers[sel[0]]
        self.sel_name.config(text=s["name"])
        self.sel_runtime.config(text=f"Runtime: {s.get('runtime','?')}")
        self.sel_source.config(text=f"Source: {s.get('source_type','?')}  •  {s.get('source','')}")
        self.opt_mode.set(s.get("mode", "full"))
        self.opt_startup.delete(0, "end")
        self.opt_startup.insert(0, str(s.get("startup_timeout", 30)))
        self.opt_timeout.delete(0, "end")
        self.opt_timeout.insert(0, str(s.get("total_timeout", 180)))
        self.opt_network.set(s.get("allow_network", False))

    def _delete_server(self):
        sel = self.server_list.curselection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a server to delete.")
            return
        name = self.servers[sel[0]]["name"]
        if messagebox.askyesno("Delete", f"Delete '{name}'?"):
            self.servers.pop(sel[0])
            save_servers(self.servers)
            self._refresh_server_list()
            self.sel_name.config(text="No server selected")
            self.sel_runtime.config(text="")
            self.sel_source.config(text="")

    # ── Add server dialog ────────────────────────────────────────────────────

    def _open_add_dialog(self):
        c = self.colors
        dlg = tk.Toplevel(self.root)
        dlg.title("Add MCP Server")
        dlg.geometry("520x560")
        dlg.configure(bg=c["bg"])
        dlg.resizable(False, False)
        dlg.grab_set()

        def lbl(parent, text):
            tk.Label(parent, text=text, bg=c["bg"], fg=c["muted"],
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 2))

        def entry(parent, default=""):
            e = ttk.Entry(parent, width=54)
            e.insert(0, default)
            e.pack(anchor="w")
            return e

        wrap = tk.Frame(dlg, bg=c["bg"], padx=24)
        wrap.pack(fill="both", expand=True)

        tk.Label(wrap, text="Add MCP Server", bg=c["bg"], fg=c["fg"],
                 font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(20, 4))

        lbl(wrap, "Server Name *")
        e_name = entry(wrap, "My MCP Server")

        lbl(wrap, "Source Type")
        src_var = tk.StringVar(value="path")
        src_row = tk.Frame(wrap, bg=c["bg"])
        src_row.pack(anchor="w")
        for val, label in [("path", "Local Path"), ("npm", "NPM Package"), ("pypi", "PyPI Package")]:
            tk.Radiobutton(src_row, text=label, variable=src_var, value=val,
                           bg=c["bg"], fg=c["fg"], selectcolor=c["panel"],
                           activebackground=c["bg"], activeforeground=c["fg"],
                           font=("Segoe UI", 10)).pack(side="left", padx=(0, 12))

        lbl(wrap, "Source Path / Package Name *")
        src_frame = tk.Frame(wrap, bg=c["bg"])
        src_frame.pack(anchor="w", fill="x")
        e_source = ttk.Entry(src_frame, width=44)
        e_source.pack(side="left")

        def browse():
            path = filedialog.askdirectory()
            if path:
                e_source.delete(0, "end")
                e_source.insert(0, path)

        ttk.Button(src_frame, text="Browse", style="Ghost.TButton",
                   command=browse).pack(side="left", padx=(6, 0))

        lbl(wrap, "Runtime")
        rt_var = tk.StringVar(value="python")
        rt_row = tk.Frame(wrap, bg=c["bg"])
        rt_row.pack(anchor="w")
        for val in ["python", "node"]:
            tk.Radiobutton(rt_row, text=val.capitalize(), variable=rt_var, value=val,
                           bg=c["bg"], fg=c["fg"], selectcolor=c["panel"],
                           activebackground=c["bg"], activeforeground=c["fg"],
                           font=("Segoe UI", 10)).pack(side="left", padx=(0, 12))

        lbl(wrap, "Start Command")
        e_cmd = entry(wrap, "python server.py")

        lbl(wrap, "Install File (requirements.txt / leave blank for npm auto)")
        e_install = entry(wrap, "requirements.txt")

        lbl(wrap, "Scan Mode")
        mode_var = tk.StringVar(value="full")
        mode_row = tk.Frame(wrap, bg=c["bg"])
        mode_row.pack(anchor="w")
        for val in ["full", "static"]:
            tk.Radiobutton(mode_row, text=val.capitalize(), variable=mode_var, value=val,
                           bg=c["bg"], fg=c["fg"], selectcolor=c["panel"],
                           activebackground=c["bg"], activeforeground=c["fg"],
                           font=("Segoe UI", 10)).pack(side="left", padx=(0, 12))

        net_var = tk.BooleanVar(value=False)
        tk.Checkbutton(wrap, text="Allow Network Access", variable=net_var,
                       bg=c["bg"], fg=c["fg"], selectcolor=c["panel"],
                       activebackground=c["bg"], activeforeground=c["fg"],
                       font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))

        def save():
            name = e_name.get().strip()
            source = e_source.get().strip()
            if not name or not source:
                messagebox.showerror("Required", "Name and Source are required.", parent=dlg)
                return
            self.servers.append({
                "name": name,
                "source_type": src_var.get(),
                "source": source,
                "runtime": rt_var.get(),
                "command": e_cmd.get().strip(),
                "install_file": e_install.get().strip(),
                "mode": mode_var.get(),
                "allow_network": net_var.get(),
                "startup_timeout": 30,
                "total_timeout": 180,
            })
            save_servers(self.servers)
            self._refresh_server_list()
            self.server_list.selection_set(len(self.servers) - 1)
            self._on_server_select()
            dlg.destroy()

        btn_row = tk.Frame(wrap, bg=c["bg"])
        btn_row.pack(anchor="w", pady=(16, 0))
        ttk.Button(btn_row, text="Add Server", style="Accent.TButton",
                   command=save).pack(side="left")
        ttk.Button(btn_row, text="Cancel", style="Ghost.TButton",
                   command=dlg.destroy).pack(side="left", padx=(8, 0))

    # ── Scanning ─────────────────────────────────────────────────────────────

    def _get_selected_server(self):
        sel = self.server_list.curselection()
        if not sel:
            messagebox.showwarning("No Selection", "Select an MCP server first.")
            return None
        return self.servers[sel[0]]

    def _apply_opts_to_server(self, server):
        server = dict(server)
        server["mode"] = self.opt_mode.get()
        server["startup_timeout"] = int(self.opt_startup.get() or 30)
        server["total_timeout"] = int(self.opt_timeout.get() or 180)
        server["allow_network"] = self.opt_network.get()
        return server

    def _run_validate(self):
        server = self._get_selected_server()
        if not server:
            return
        server = self._apply_opts_to_server(server)
        config_path = os.path.join(ROOT, "ui_configs", f"{server['name'].replace(' ', '_')}.yaml")
        generate_config(server, config_path)
        self._execute([VENV_PYTHON, "-m", "trustprobe", "validate", "-c", config_path],
                      label="Validating...")

    def _run_scan(self):
        server = self._get_selected_server()
        if not server:
            return
        server = self._apply_opts_to_server(server)
        config_path = os.path.join(ROOT, "ui_configs", f"{server['name'].replace(' ', '_')}.yaml")
        generate_config(server, config_path)
        self._execute([VENV_PYTHON, "-m", "trustprobe", "scan", "-c", config_path],
                      label="Scanning...")

    def _run_quick(self):
        server = self._get_selected_server()
        if not server:
            return
        source = server.get("source", "")
        if not source:
            messagebox.showerror("Error", "Server source path/package is required.")
            return
        self._execute([VENV_PYTHON, "-m", "trustprobe", "quick", source],
                      label="Quick scanning...")

    def _execute(self, cmd, label="Running..."):
        self.notebook.select(1)
        self._log_clear()
        self._log(f"$ {' '.join(cmd)}\n", "info")
        self.progress_label.config(text=label)
        self.progress.start(12)
        self.stop_btn.config(state="normal")

        def run():
            env = get_env()
            self.scan_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            for line in self.scan_process.stdout:
                self._log_line(line)
            self.scan_process.wait()
            rc = self.scan_process.returncode
            self.root.after(0, self._scan_done, rc)

        threading.Thread(target=run, daemon=True).start()

    def _scan_done(self, returncode):
        self.progress.stop()
        self.stop_btn.config(state="disabled")
        if returncode == 0:
            self.progress_label.config(text="Completed successfully")
            self._log("\nScan complete.\n", "ok")
            self._load_results()
            self.notebook.select(2)
        elif returncode == -1:
            self.progress_label.config(text="Stopped")
        else:
            self.progress_label.config(text=f"Finished with exit code {returncode}")
            self._log(f"\nExited with code {returncode}\n", "warn")

    def _stop_scan(self):
        if self.scan_process:
            self.scan_process.terminate()
            self.scan_process = None
        self.progress.stop()
        self.stop_btn.config(state="disabled")
        self.progress_label.config(text="Stopped")

    # ── Logging ──────────────────────────────────────────────────────────────

    def _log_clear(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

    def _log(self, text, tag=None):
        self.log_box.config(state="normal")
        if tag:
            self.log_box.insert("end", text, tag)
        else:
            self.log_box.insert("end", text)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _log_line(self, line):
        tag = None
        l = line.lower()
        if any(x in l for x in ["error", "failed", "traceback", "critical"]):
            tag = "err"
        elif any(x in l for x in ["warning", "warn"]):
            tag = "warn"
        elif any(x in l for x in ["ok", "pass", "complete", "success"]):
            tag = "ok"
        elif any(x in l for x in ["step", "scanning", "running", "probe"]):
            tag = "info"
        self.root.after(0, self._log, line, tag)

    # ── Results ──────────────────────────────────────────────────────────────

    def _load_results(self):
        server = self._get_selected_server()
        results_path = None

        if server:
            out = server.get("out_dir") or os.path.join(OUT_DIR, server["name"].replace(" ", "_"))
            candidate = os.path.join(out, "results.json")
            if os.path.exists(candidate):
                results_path = candidate

        if not results_path:
            for dirpath, _, files in os.walk(OUT_DIR):
                if "results.json" in files:
                    results_path = os.path.join(dirpath, "results.json")
                    break

        if not results_path:
            self.verdict_label.config(text="No results found — run a scan first.", fg=self.colors["muted"])
            return

        with open(results_path) as f:
            data = json.load(f)

        verdict = data.get("verdict", {})
        trust = verdict.get("trust_score", "?")
        decision = verdict.get("decision", "unknown").upper()
        color = {"DO_NOT_USE": self.colors["danger"], "USE_WITH_CAUTION": self.colors["warn"],
                 "APPROVE": self.colors["success"]}.get(decision, self.colors["muted"])
        self.verdict_label.config(
            text=f"Verdict: {decision}   |   Trust Score: {trust}/100",
            fg=color)

        for row in self.results_tree.get_children():
            self.results_tree.delete(row)

        findings = data.get("findings", [])
        for f in findings:
            sev = f.get("severity", "info").lower()
            self.results_tree.insert("", "end", values=(
                f.get("rule_id", ""),
                f.get("severity", "").upper(),
                f.get("category", ""),
                f.get("title", f.get("description", "")),
            ), tags=(sev,))

        if not findings:
            self.results_tree.insert("", "end", values=("", "", "", "No findings — server looks clean."))

    def _open_report(self):
        server = self._get_selected_server()
        out = None
        if server:
            out = server.get("out_dir") or os.path.join(OUT_DIR, server["name"].replace(" ", "_"))
        if not out:
            out = OUT_DIR
        report = os.path.join(out, "report.html")
        if os.path.exists(report):
            os.startfile(report)
        else:
            for dirpath, _, files in os.walk(OUT_DIR):
                if "report.html" in files:
                    os.startfile(os.path.join(dirpath, "report.html"))
                    return
            messagebox.showinfo("No Report", "No report.html found. Run a scan first.")

    # ── Docker check ─────────────────────────────────────────────────────────

    def _check_docker(self):
        env = get_env()
        result = subprocess.run(["docker", "info"], capture_output=True, env=env)
        color = self.colors["success"] if result.returncode == 0 else self.colors["danger"]
        self.root.after(0, lambda: self.docker_dot.config(fg=color))


if __name__ == "__main__":
    root = tk.Tk()
    app = MCPScannerUI(root)
    root.mainloop()
