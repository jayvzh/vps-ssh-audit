import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime, timedelta
from collections import defaultdict

from main import (
    load_cache, save_cache, get_ip_geo, format_geo_info, 
    open_log, parse_line, detect_risks, generate_html_report,
    get_representative_ips, get_ip_segment
)


def get_app_dir():
    """获取应用程序所在目录（兼容PyInstaller打包）"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class SSHAuditGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH 审计工具")
        self.root.geometry("800x650")
        self.root.minsize(700, 550)
        
        self.is_running = False
        self.log_dir = tk.StringVar()
        self.days = tk.IntVar(value=7)
        self.threshold = tk.IntVar(value=10)
        self.enable_geo = tk.BooleanVar(value=True)
        self.report_path = tk.StringVar()
        
        script_dir = get_app_dir()
        self.log_dir.set(script_dir)
        
        default_report_path = self._get_default_report_path()
        self.report_path.set(default_report_path)
        
        self._create_widgets()
        
    def _get_default_report_path(self):
        script_dir = get_app_dir()
        index = 1
        while True:
            report_name = f"ssh_audit_report-{index}.html"
            report_path = os.path.join(script_dir, report_name)
            if not os.path.exists(report_path):
                return report_path
            index += 1
        
    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        config_frame = ttk.LabelFrame(main_frame, text="配置参数", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=5)
        
        ttk.Label(row1, text="日志目录:").pack(side=tk.LEFT)
        log_entry = ttk.Entry(row1, textvariable=self.log_dir, width=50)
        log_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        ttk.Button(row1, text="浏览...", command=self._browse_dir).pack(side=tk.LEFT)
        
        row_report = ttk.Frame(config_frame)
        row_report.pack(fill=tk.X, pady=5)
        
        ttk.Label(row_report, text="报告路径:").pack(side=tk.LEFT)
        report_entry = ttk.Entry(row_report, textvariable=self.report_path, width=50)
        report_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        ttk.Button(row_report, text="浏览...", command=self._browse_report).pack(side=tk.LEFT)
        
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, pady=5)
        
        ttk.Label(row2, text="分析天数:").pack(side=tk.LEFT)
        days_spin = ttk.Spinbox(row2, from_=1, to=365, textvariable=self.days, width=10)
        days_spin.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(row2, text="高频IP阈值:").pack(side=tk.LEFT)
        threshold_spin = ttk.Spinbox(row2, from_=1, to=1000, textvariable=self.threshold, width=10)
        threshold_spin.pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Checkbutton(row2, text="查询IP归属地", variable=self.enable_geo).pack(side=tk.LEFT)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(button_frame, text="开始分析", command=self._start_analysis)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.open_report_btn = ttk.Button(button_frame, text="打开报告", command=self._open_report, state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(button_frame, text="退出", command=self.root.quit).pack(side=tk.RIGHT)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))
        
        self.status_label = ttk.Label(progress_frame, text="就绪")
        self.status_label.pack(side=tk.LEFT)
        
        log_frame = ttk.LabelFrame(main_frame, text="运行日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def _browse_dir(self):
        directory = filedialog.askdirectory(initialdir=self.log_dir.get())
        if directory:
            self.log_dir.set(directory)
            
    def _browse_report(self):
        initial_file = os.path.basename(self.report_path.get())
        initial_dir = os.path.dirname(self.report_path.get())
        if not os.path.isdir(initial_dir):
            initial_dir = get_app_dir()
        file_path = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            initialfile=initial_file,
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")]
        )
        if file_path:
            self.report_path.set(file_path)
            
    def _log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def _update_status(self, message):
        self.status_label.config(text=message)
        
    def _update_progress(self, value):
        self.progress_var.set(value)
        
    def _start_analysis(self):
        if self.is_running:
            return
            
        log_dir = self.log_dir.get()
        if not os.path.isdir(log_dir):
            messagebox.showerror("错误", f"目录不存在: {log_dir}")
            return
            
        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.open_report_btn.config(state=tk.DISABLED)
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self._run_analysis, daemon=True)
        thread.start()
        
    def _run_analysis(self):
        try:
            start_time = datetime.now()
            
            self.root.after(0, self._log, "=" * 50)
            self.root.after(0, self._log, "       SSH 审计工具（图形界面版）")
            self.root.after(0, self._log, "=" * 50)
            
            log_dir = self.log_dir.get()
            days = self.days.get()
            threshold = self.threshold.get()
            enable_geo = self.enable_geo.get()
            
            cutoff = datetime.now() - timedelta(days=days)
            
            cache = load_cache()
            
            recent_logs = []
            stats = defaultdict(lambda: {"count": 0, "first": None, "last": None})
            
            files = sorted([f for f in os.listdir(log_dir)
                          if f.startswith("auth.log") or f.endswith(".log")])
            total_files = len(files)
            
            if total_files == 0:
                self.root.after(0, self._log, f"错误: 目录 {log_dir} 中没有找到日志文件")
                self.root.after(0, messagebox.showerror, "错误", "没有找到日志文件")
                return
                
            self.root.after(0, self._log, "")
            self.root.after(0, self._log, "─" * 50)
            self.root.after(0, self._log, f"发现 {total_files} 个日志文件")
            self.root.after(0, self._log, "─" * 50)
            self.root.after(0, self._log, "")
            
            total_lines = 0
            parsed_lines = 0
            
            for idx, fname in enumerate(files, 1):
                path = os.path.join(log_dir, fname)
                self.root.after(0, self._log, f"[{idx}/{total_files}] 处理: {fname}")
                
                progress = (idx / total_files) * 50
                self.root.after(0, self._update_progress, progress)
                self.root.after(0, self._update_status, f"处理文件 {idx}/{total_files}: {fname}")
                
                file_lines = 0
                with open_log(path) as f:
                    for line in f:
                        total_lines += 1
                        file_lines += 1
                        
                        parsed = parse_line(line)
                        if not parsed:
                            continue
                            
                        parsed_lines += 1
                        
                        dt = parsed["dt"]
                        ip = parsed["ip"]
                        
                        s = stats[ip]
                        s["count"] += 1
                        s["first"] = s["first"] or dt
                        s["last"] = dt
                        
                        if dt >= cutoff:
                            recent_logs.append(parsed)
                            
                self.root.after(0, self._log, f"    完成: {file_lines} 行")
                
            self.root.after(0, self._log, "")
            self.root.after(0, self._log, "─" * 50)
            self.root.after(0, self._log, f"解析统计: 总行数 {total_lines}, 有效解析 {parsed_lines} 行")
            self.root.after(0, self._log, "─" * 50)
            self.root.after(0, self._log, "")
            
            unique_ips = set([x["ip"] for x in recent_logs] + list(stats.keys()))
            total_ips = len(unique_ips)
            
            representative_ips, private_ips = get_representative_ips(unique_ips)
            total_representative = len(representative_ips)
            total_private = len(private_ips)
            
            self.root.after(0, self._log, "IP 分析统计:")
            self.root.after(0, self._log, f"  - 总 IP 数: {total_ips}")
            self.root.after(0, self._log, f"  - 内网 IP: {total_private} (不查询)")
            self.root.after(0, self._log, f"  - 待查询 IP: {total_representative} (聚合后)")
            self.root.after(0, self._log, "")
            
            private_result = {"country": "", "region": "", "city": "", "org": "", "status": "private"}
            for ip in private_ips:
                segment = get_ip_segment(ip)
                cache[segment] = private_result
                if ip in cache:
                    del cache[ip]
                
            if enable_geo and total_representative > 0:
                self.root.after(0, self._log, "开始查询IP归属地...")
                self.root.after(0, self._update_status, "查询IP归属地...")
                
                queried_ips = 0
                for ip in representative_ips:
                    queried_ips += 1
                    progress = 50 + (queried_ips / total_representative) * 45
                    self.root.after(0, self._update_progress, progress)
                    self.root.after(0, self._update_status, f"查询IP归属地: {queried_ips}/{total_representative}")
                    
                    if queried_ips % 5 == 0 or queried_ips == total_representative:
                        self.root.after(0, self._log, f"    查询进度: {queried_ips}/{total_representative}")
                    get_ip_geo(ip, cache, enable_geo)
                    
                self.root.after(0, self._log, f"    完成: {total_representative} 个代表性IP")
            elif not enable_geo:
                for ip in unique_ips:
                    get_ip_geo(ip, cache, False)
                        
            save_cache(cache)
            
            self.root.after(0, self._update_progress, 95)
            self.root.after(0, self._update_status, "生成报告...")
            
            risks = detect_risks(recent_logs, stats, threshold)
            
            report_path = self.report_path.get()
            report_dir = os.path.dirname(report_path)
            if report_dir and not os.path.exists(report_dir):
                os.makedirs(report_dir, exist_ok=True)
            
            generated_path = generate_html_report(recent_logs, stats, risks, cache, days, threshold, 
                               total_files, parsed_lines, total_ips, total_representative, total_private,
                               output_path=report_path)
            
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            self.root.after(0, self._update_progress, 100)
            self.root.after(0, self._update_status, "完成")
            
            self.root.after(0, self._log, "")
            self.root.after(0, self._log, "=" * 50)
            self.root.after(0, self._log, f"✅ HTML报告生成: {os.path.basename(generated_path)}")
            self.root.after(0, self._log, f"⏱️  总耗时: {elapsed_time:.2f} 秒")
            self.root.after(0, self._log, "=" * 50)
            
            self.root.after(0, self._on_analysis_complete)
            
        except Exception as e:
            self.root.after(0, self._log, f"\n错误: {str(e)}")
            self.root.after(0, messagebox.showerror, "错误", f"分析过程中出错: {str(e)}")
        finally:
            self.is_running = False
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            
    def _on_analysis_complete(self):
        self.open_report_btn.config(state=tk.NORMAL)
        report_path = self.report_path.get()
        messagebox.showinfo("完成", f"分析完成！报告已生成: {os.path.basename(report_path)}")
        
    def _open_report(self):
        report_path = self.report_path.get()
        if os.path.exists(report_path):
            os.startfile(report_path)
        else:
            messagebox.showwarning("警告", "报告文件不存在")


def main():
    root = tk.Tk()
    app = SSHAuditGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
