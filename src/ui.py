import csv
import queue
import re
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .ai_assistant import AIAssistant, OUT_OF_CONTEXT_MESSAGE, ScanContext
from .scanner import PortScanner


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AI Network Port Scanner")
        self.geometry("980x680")
        self.minsize(900, 620)

        self.scanner = None
        self.scanner_thread = None
        self.start_time = None
        self.poll_after_ms = 50

        self.ai_assistant = AIAssistant()
        self.ai_queue = queue.Queue()

        self.last_target = ""
        self.last_start_port = 1
        self.last_end_port = 1024

        self._auto_configure_ai()
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_scan = ttk.Frame(self.tabs)
        self.tab_results = ttk.Frame(self.tabs)
        self.tab_ai = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_scan, text="Scan")
        self.tabs.add(self.tab_results, text="Results")
        self.tabs.add(self.tab_ai, text="AI Assistant")

        self._build_scan_tab()
        self._build_results_tab()
        self._build_ai_tab()

    def _build_scan_tab(self):
        frm_settings = ttk.LabelFrame(self.tab_scan, text="Scan Settings")
        frm_settings.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm_settings, text="Target (IP / Hostname):").grid(
            row=0, column=0, padx=8, pady=8, sticky="e"
        )
        self.ent_target = ttk.Entry(frm_settings, width=40)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="Start Port:").grid(
            row=0, column=2, padx=8, pady=8, sticky="e"
        )
        self.ent_start = ttk.Entry(frm_settings, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_settings, text="End Port:").grid(
            row=0, column=4, padx=8, pady=8, sticky="e"
        )
        self.ent_end = ttk.Entry(frm_settings, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        self.btn_start = ttk.Button(frm_settings, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=8, pady=8, sticky="e")
        self.btn_stop = ttk.Button(
            frm_settings, text="Stop Scan", command=self.stop_scan, state="disabled"
        )
        self.btn_stop.grid(row=1, column=5, padx=8, pady=8, sticky="w")

        for idx in range(6):
            frm_settings.grid_columnconfigure(idx, weight=1)

        frm_status = ttk.LabelFrame(self.tab_scan, text="Live Status")
        frm_status.pack(fill="x", padx=10, pady=(0, 10))

        self.var_status = tk.StringVar(value="Idle")
        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        self.var_progress = tk.StringVar(value="Progress: 0.0%")

        ttk.Label(frm_status, textvariable=self.var_status, style="Header.TLabel").pack(
            side="left", padx=10, pady=8
        )
        ttk.Label(frm_status, textvariable=self.var_elapsed).pack(side="left", padx=12, pady=8)
        ttk.Label(frm_status, textvariable=self.var_progress).pack(side="left", padx=12, pady=8)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

        frm_summary = ttk.LabelFrame(self.tab_scan, text="Scan Summary")
        frm_summary.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt_summary = tk.Text(frm_summary, height=14, wrap="word")
        self.txt_summary.pack(fill="both", expand=True, padx=10, pady=10)
        self.txt_summary.insert(
            tk.END,
            "Run a scan to see live updates and high-level results here.\n",
        )
        self.txt_summary.configure(state="disabled")

    def _build_results_tab(self):
        frm_results = ttk.LabelFrame(self.tab_results, text="Open Ports")
        frm_results.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree_results = ttk.Treeview(
            frm_results,
            columns=("port", "service", "status"),
            show="headings",
            height=18,
        )
        self.tree_results.heading("port", text="Port")
        self.tree_results.heading("service", text="Service")
        self.tree_results.heading("status", text="Status")
        self.tree_results.column("port", width=120, anchor="center")
        self.tree_results.column("service", width=200, anchor="center")
        self.tree_results.column("status", width=160, anchor="center")
        self.tree_results.pack(fill="both", expand=True, side="left", padx=(10, 0), pady=10)

        yscroll = ttk.Scrollbar(frm_results, orient="vertical", command=self.tree_results.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.tree_results.configure(yscrollcommand=yscroll.set)

        frm_actions = ttk.Frame(self.tab_results)
        frm_actions.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(frm_actions, text="Copy Selected", command=self.copy_selected).pack(side="left")
        ttk.Button(frm_actions, text="Export TXT", command=self.export_txt).pack(side="left", padx=8)
        ttk.Button(frm_actions, text="Export CSV", command=self.export_csv).pack(side="left", padx=8)
        ttk.Button(frm_actions, text="Clear Results", command=self.clear_results).pack(side="right")

    def _build_ai_tab(self):
        frm_key = ttk.LabelFrame(self.tab_ai, text="Ask AI for Deeper Insights!")
        frm_key.pack(fill="x", padx=10, pady=10)

        ttk.Label(
            frm_key,
            text="This app is powered by Google Gemini AI!",
        ).grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.var_ai_status = tk.StringVar(value="AI status: Checking configuration...")
        ttk.Label(frm_key, textvariable=self.var_ai_status).grid(
            row=1, column=0, padx=8, pady=(0, 8), sticky="w"
        )
        frm_key.grid_columnconfigure(0, weight=1)
        self._refresh_ai_status()

        frm_chat = ttk.LabelFrame(self.tab_ai, text="Assistant")
        frm_chat.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.txt_chat = tk.Text(frm_chat, wrap="word", height=20)
        self.txt_chat.pack(fill="both", expand=True, padx=10, pady=10)
        self.txt_chat.configure(font=("Segoe UI", 10), spacing1=2, spacing3=3)
        self.txt_chat.tag_configure("chat_user_header", font=("Segoe UI", 10, "bold"))
        self.txt_chat.tag_configure("chat_user_body", lmargin1=16, lmargin2=16)
        self.txt_chat.tag_configure("chat_assistant_header", font=("Segoe UI", 10, "bold"))
        self.txt_chat.tag_configure("chat_assistant_body", lmargin1=16, lmargin2=16, spacing3=4)
        self.txt_chat.tag_configure("chat_bullet", lmargin1=32, lmargin2=50)
        self.txt_chat.tag_configure("chat_subheading", font=("Segoe UI", 10, "bold"), lmargin1=16, lmargin2=16)
        self.txt_chat.tag_configure("chat_error", foreground="#b00020", lmargin1=16, lmargin2=16)
        self.txt_chat.tag_configure("chat_separator", foreground="#7a7a7a")
        self.txt_chat.insert(
            tk.END,
            "Ask about your scan results, open ports, risk hints, and hardening tips.\n\n",
        )
        self.txt_chat.configure(state="disabled")

        frm_chat_actions = ttk.Frame(self.tab_ai)
        frm_chat_actions.pack(fill="x", padx=10, pady=(0, 10))
        self.ent_question = ttk.Entry(frm_chat_actions)
        self.ent_question.pack(side="left", fill="x", expand=True)
        ttk.Button(frm_chat_actions, text="Ask", command=self.ask_ai).pack(side="left", padx=8)
        ttk.Button(
            frm_chat_actions, text="Explain Results with AI", command=self.explain_results
        ).pack(side="left")
        ttk.Button(frm_chat_actions, text="Clear Chat", command=self.clear_chat).pack(
            side="right"
        )

    def _auto_configure_ai(self):
        try:
            self.ai_assistant.configure_from_env("GEMINI_API_KEY")
        except Exception:
            # Keep UI usable even if AI config fails; status label will show disconnected.
            pass

    def _refresh_ai_status(self):
        if self.ai_assistant.is_ready():
            self.var_ai_status.set("AI status: Connected")
        else:
            self.var_ai_status.set("AI status: Not connected (GEMINI_API_KEY Missing)")

    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return
        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0-65535 and start <= end.")
            return

        self.last_target = target
        self.last_start_port = start_port
        self.last_end_port = end_port
        self.scanner = PortScanner(target, start_port, end_port, timeout=0.5, max_workers=500)

        try:
            resolved_ip = self.scanner.resolve_target()
        except Exception as exc:
            self.scanner = None
            messagebox.showerror("Resolution Error", f"Could not resolve target.\n{exc}")
            return

        self._append_summary(
            f"Target: {target} ({resolved_ip})\n"
            f"Range: {start_port}-{end_port}\n"
            "Scan started.\n\n"
        )
        for row in self.tree_results.get_children():
            self.tree_results.delete(row)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.var_status.set("Scanning...")
        self.progress.configure(value=0, maximum=max(1, self.scanner.total_ports))
        self.var_progress.set("Progress: 0.0%")
        self.start_time = time.time()
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping...")

    def poll_results(self):
        if not self.scanner:
            return
        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()
                if msg_type == "open":
                    port, service = a, b
                    self.tree_results.insert("", tk.END, values=(port, service, "Open"))
                    self._append_summary(f"[+] Port {port} ({service}) is open\n")
                elif msg_type == "error":
                    port, err = a, b
                    self._append_summary(f"[!] Error scanning port {port}: {err}\n")
                elif msg_type == "progress":
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    percentage = (scanned / max(total, 1)) * 100
                    self.var_progress.set(f"Progress: {percentage:.1f}%")
                    self.var_status.set(f"Scanning... {scanned}/{total}")
                elif msg_type == "done":
                    self._finish_scan()
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        elif self.var_status.get() in ("Scanning...", "Stopping..."):
            self._finish_scan()

    def _finish_scan(self):
        total_open = len(self.scanner.open_ports) if self.scanner else 0
        self.var_status.set("Completed")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.start_time = None
        self._append_summary(f"\nScan complete. Open ports found: {total_open}\n")

    def update_elapsed(self):
        if self.start_time and self.var_status.get() in ("Scanning...", "Stopping..."):
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self.update_elapsed)

    def clear_results(self):
        for row in self.tree_results.get_children():
            self.tree_results.delete(row)
        self._set_summary_text("Results cleared.\n")
        self.var_status.set("Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.var_progress.set("Progress: 0.0%")
        self.progress.configure(value=0, maximum=1)

    def copy_selected(self):
        selected = self.tree_results.selection()
        if not selected:
            messagebox.showinfo("Copy Selected", "Please select a row first.")
            return
        values = self.tree_results.item(selected[0], "values")
        text = f"Port {values[0]} ({values[1]}) is {values[2]}"
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Selected row copied to clipboard.")

    def export_txt(self):
        rows = self._collect_rows()
        if not rows:
            messagebox.showinfo("Export TXT", "No results to export.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Export results as TXT",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"open_ports_{int(time.time())}.txt",
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", encoding="utf-8") as file_obj:
                file_obj.write("Open Ports:\n")
                for port, service, status in rows:
                    file_obj.write(f"Port {port} ({service}) - {status}\n")
            messagebox.showinfo("Export TXT", "TXT export completed.")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def export_csv(self):
        rows = self._collect_rows()
        if not rows:
            messagebox.showinfo("Export CSV", "No results to export.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Export results as CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"open_ports_{int(time.time())}.csv",
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Port", "Service", "Status"])
                writer.writerows(rows)
            messagebox.showinfo("Export CSV", "CSV export completed.")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def _collect_rows(self):
        rows = []
        for item_id in self.tree_results.get_children():
            rows.append(self.tree_results.item(item_id, "values"))
        return rows

    def explain_results(self):
        self.ent_question.delete(0, tk.END)
        self.ent_question.insert(
            0,
            "Please summarize this scan result, provide risk hints, and basic hardening steps.",
        )
        self.ask_ai()

    def clear_chat(self):
        self.ai_assistant.clear_history()
        self.txt_chat.configure(state="normal")
        self.txt_chat.delete("1.0", tk.END)
        self.txt_chat.insert(tk.END, "Chat cleared.\n\n")
        self.txt_chat.configure(state="disabled")

    def ask_ai(self):
        question = self.ent_question.get().strip()
        if not question:
            messagebox.showinfo("AI Assistant", "Please enter a question.")
            return

        context = self._current_context()
        self._append_user_message(question)
        if not self.ai_assistant.is_in_scope(question, context):
            self._append_assistant_message(OUT_OF_CONTEXT_MESSAGE)
            self.ent_question.delete(0, tk.END)
            return

        if not self.ai_assistant.is_ready():
            messagebox.showerror(
                "AI Assistant",
                "AI key is not configured. Add GEMINI_API_KEY in your .env file.",
            )
            return

        self._append_chat("Assistant: Thinking...\n", "chat_assistant_header")
        self.ent_question.delete(0, tk.END)
        worker = threading.Thread(
            target=self._ask_ai_worker, args=(question, context), daemon=True
        )
        worker.start()
        self.after(120, self._poll_ai_queue)

    def _ask_ai_worker(self, question, context):
        try:
            answer = self.ai_assistant.ask(question, context)
            self.ai_queue.put(("ok", answer))
        except Exception as exc:
            self.ai_queue.put(("error", str(exc)))

    def _poll_ai_queue(self):
        try:
            msg_type, payload = self.ai_queue.get_nowait()
            self._replace_last_thinking_message()
            if msg_type == "ok":
                self._append_assistant_message(payload)
            else:
                self._append_chat("Assistant Error:\n", "chat_assistant_header")
                self._append_chat(f"{payload}\n\n", "chat_error")
        except queue.Empty:
            self.after(120, self._poll_ai_queue)

    def _replace_last_thinking_message(self):
        self.txt_chat.configure(state="normal")
        content = self.txt_chat.get("1.0", tk.END)
        marker = "Assistant: Thinking...\n"
        idx = content.rfind(marker)
        if idx >= 0:
            replacement = content[:idx] + content[idx + len(marker) :]
        else:
            replacement = content
        self.txt_chat.delete("1.0", tk.END)
        self.txt_chat.insert(tk.END, replacement)
        self.txt_chat.configure(state="disabled")

    def _current_context(self):
        open_ports = self.scanner.open_ports if self.scanner else []
        return ScanContext(
            target=self.last_target or self.ent_target.get().strip(),
            start_port=self.last_start_port,
            end_port=self.last_end_port,
            open_ports=open_ports,
        )

    def _append_summary(self, text):
        self.txt_summary.configure(state="normal")
        self.txt_summary.insert(tk.END, text)
        self.txt_summary.see(tk.END)
        self.txt_summary.configure(state="disabled")

    def _set_summary_text(self, text):
        self.txt_summary.configure(state="normal")
        self.txt_summary.delete("1.0", tk.END)
        self.txt_summary.insert(tk.END, text)
        self.txt_summary.configure(state="disabled")

    def _append_chat(self, text, tag=None):
        self.txt_chat.configure(state="normal")
        if tag:
            self.txt_chat.insert(tk.END, text, tag)
        else:
            self.txt_chat.insert(tk.END, text)
        self.txt_chat.see(tk.END)
        self.txt_chat.configure(state="disabled")

    def _append_user_message(self, message):
        self._append_chat("You:\n", "chat_user_header")
        self._append_chat(f"{message.strip()}\n\n", "chat_user_body")
        self._append_chat("-" * 54 + "\n", "chat_separator")

    def _append_assistant_message(self, message):
        self._append_chat("Assistant:\n", "chat_assistant_header")
        formatted_lines = self._prettify_ai_response(message)
        if not formatted_lines:
            self._append_chat("No response generated.\n", "chat_assistant_body")
        else:
            for line, tag in formatted_lines:
                self._append_chat(f"{line}\n", tag)
        self._append_chat("\n" + "-" * 54 + "\n", "chat_separator")

    def _prettify_ai_response(self, raw_text):
        text = (raw_text or "").replace("\r\n", "\n").strip()
        if not text:
            return []

        # Normalize markdown-like bullets and numbering to readable lines.
        lines = [ln.rstrip() for ln in text.split("\n")]
        pretty = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                pretty.append(("", "chat_assistant_body"))
                continue

            clean = re.sub(r"^\s{0,3}(#{1,6}\s*)", "", line).strip()
            clean = self._clean_inline_markdown(clean)
            if re.match(r"^(\*\*|__)?[A-Za-z0-9 /-]{2,40}:(\*\*|__)?$", clean):
                pretty.append((clean.replace("**", "").replace("__", ""), "chat_subheading"))
                continue

            bullet_match = re.match(r"^[-*]\s+(.+)$", line)
            if bullet_match:
                bullet_text = self._clean_inline_markdown(bullet_match.group(1).strip())
                pretty.append((f"• {bullet_text}", "chat_bullet"))
                continue

            numbered_match = re.match(r"^\d+[\).]\s+(.+)$", line)
            if numbered_match:
                numbered_text = self._clean_inline_markdown(numbered_match.group(1).strip())
                pretty.append((f"- {numbered_text}", "chat_bullet"))
                continue

            pretty.append((clean, "chat_assistant_body"))
        return pretty

    def _clean_inline_markdown(self, text):
        cleaned = text.replace("**", "").replace("__", "")
        cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
        cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
        return cleaned
