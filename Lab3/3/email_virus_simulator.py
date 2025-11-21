import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import json
import os
from datetime import datetime
import base64
import hashlib

class EmailVirusSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Email & Document Virus Simulation System")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Simulation state
        self.is_running = False
        self.received_emails = []
        self.processed_docs = []
        self.virus_detected = []
        self.error_rate = 0.4  # 40% error rate
        self.virus_rate = 0.25  # 25% virus rate
        
        # Email configuration
        self.email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'check_interval': 30
        }
        
        self.setup_ui()
        self.load_config()
        
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Danger.TLabel', foreground='red', font=('Arial', 10, 'bold'))
        style.configure('Success.TLabel', foreground='green', font=('Arial', 10, 'bold'))
        style.configure('Warning.TLabel', foreground='orange', font=('Arial', 10, 'bold'))
        
        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Email Monitoring Tab
        email_frame = ttk.Frame(notebook)
        notebook.add(email_frame, text="📧 Email Monitor")
        self.setup_email_tab(email_frame)
        
        # Document Analysis Tab
        doc_frame = ttk.Frame(notebook)
        notebook.add(doc_frame, text="📄 Document Analysis")
        self.setup_document_tab(doc_frame)
        
        # Virus Detection Tab
        virus_frame = ttk.Frame(notebook)
        notebook.add(virus_frame, text="🦠 Virus Detection")
        self.setup_virus_tab(virus_frame)
        
        # Settings Tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="⚙️ Settings")
        self.setup_settings_tab(settings_frame)
        
    def setup_email_tab(self, parent):
        # Email configuration frame
        config_frame = ttk.LabelFrame(parent, text="Email Configuration")
        config_frame.pack(fill='x', padx=5, pady=5)
        
        # Email settings grid
        ttk.Label(config_frame, text="Email Address:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.email_address = ttk.Entry(config_frame, width=30)
        self.email_address.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="App Password:").grid(row=0, column=2, sticky='w', padx=5, pady=2)
        self.email_password = ttk.Entry(config_frame, width=20, show='*')
        self.email_password.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Check Interval (sec):").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.check_interval = ttk.Entry(config_frame, width=10)
        self.check_interval.insert(0, "30")
        self.check_interval.grid(row=1, column=1, padx=5, pady=2)
        
        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="🚀 Start Monitoring", command=self.start_simulation)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹️ Stop Monitoring", command=self.stop_simulation, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="📧 Send Test Email", command=self.send_test_email).pack(side='left', padx=5)
        ttk.Button(control_frame, text="🔄 Manual Check", command=self.manual_email_check).pack(side='left', padx=5)
        
        # Status display
        status_frame = ttk.LabelFrame(parent, text="Email Monitoring Status")
        status_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.email_status = scrolledtext.ScrolledText(status_frame, height=20, bg='#1e1e1e', fg='#00ff00', font=('Consolas', 10))
        self.email_status.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(parent, text="Statistics")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        self.stats_labels = {}
        stats_items = [('Emails Processed', 'emails'), ('Viruses Detected', 'viruses'), ('Errors Encountered', 'errors'), ('Clean Documents', 'clean')]
        
        for i, (label, key) in enumerate(stats_items):
            ttk.Label(stats_frame, text=f"{label}:").grid(row=0, column=i*2, sticky='w', padx=5, pady=2)
            self.stats_labels[key] = ttk.Label(stats_frame, text="0", style='Success.TLabel')
            self.stats_labels[key].grid(row=0, column=i*2+1, padx=5, pady=2)
        
    def setup_document_tab(self, parent):
        # Document list with enhanced columns
        list_frame = ttk.LabelFrame(parent, text="Document Processing History")
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('Timestamp', 'Filename', 'Size', 'Type', 'Status', 'Threat Level', 'Error Details')
        self.doc_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        column_widths = {'Timestamp': 120, 'Filename': 200, 'Size': 80, 'Type': 80, 'Status': 100, 'Threat Level': 100, 'Error Details': 200}
        for col in columns:
            self.doc_tree.heading(col, text=col)
            self.doc_tree.column(col, width=column_widths.get(col, 150))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.doc_tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.doc_tree.xview)
        self.doc_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.doc_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Document details
        details_frame = ttk.LabelFrame(parent, text="Document Analysis Details")
        details_frame.pack(fill='x', padx=5, pady=5)
        
        self.doc_details = scrolledtext.ScrolledText(details_frame, height=8, bg='#1e1e1e', fg='#ffffff', font=('Consolas', 10))
        self.doc_details.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.doc_tree.bind('<<TreeviewSelect>>', self.on_doc_select)
        
    def setup_virus_tab(self, parent):
        # Virus detection results
        virus_list_frame = ttk.LabelFrame(parent, text="Virus Detection Results")
        virus_list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        virus_columns = ('Timestamp', 'Filename', 'Virus Type', 'Severity', 'Action Taken', 'Hash')
        self.virus_tree = ttk.Treeview(virus_list_frame, columns=virus_columns, show='headings', height=12)
        
        for col in virus_columns:
            self.virus_tree.heading(col, text=col)
            self.virus_tree.column(col, width=150)
        
        virus_scrollbar = ttk.Scrollbar(virus_list_frame, orient='vertical', command=self.virus_tree.yview)
        self.virus_tree.configure(yscrollcommand=virus_scrollbar.set)
        
        self.virus_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        virus_scrollbar.pack(side='right', fill='y')
        
        # Virus analysis details
        virus_details_frame = ttk.LabelFrame(parent, text="Virus Analysis Report")
        virus_details_frame.pack(fill='x', padx=5, pady=5)
        
        self.virus_details = scrolledtext.ScrolledText(virus_details_frame, height=10, bg='#2d1b1b', fg='#ff6b6b', font=('Consolas', 10))
        self.virus_details.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.virus_tree.bind('<<TreeviewSelect>>', self.on_virus_select)
        
    def setup_settings_tab(self, parent):
        # Simulation parameters
        sim_frame = ttk.LabelFrame(parent, text="Simulation Parameters")
        sim_frame.pack(fill='x', padx=5, pady=5)
        
        # Error rate
        ttk.Label(sim_frame, text="Document Error Rate (%):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.error_rate_var = tk.StringVar(value=str(int(self.error_rate * 100)))
        error_scale = ttk.Scale(sim_frame, from_=0, to=100, orient='horizontal', 
                               variable=self.error_rate_var, command=self.update_error_rate)
        error_scale.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        self.error_label = ttk.Label(sim_frame, text=f"{int(self.error_rate * 100)}%")
        self.error_label.grid(row=0, column=2, padx=5, pady=5)
        
        # Virus rate
        ttk.Label(sim_frame, text="Virus Detection Rate (%):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.virus_rate_var = tk.StringVar(value=str(int(self.virus_rate * 100)))
        virus_scale = ttk.Scale(sim_frame, from_=0, to=80, orient='horizontal', 
                               variable=self.virus_rate_var, command=self.update_virus_rate)
        virus_scale.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        self.virus_label = ttk.Label(sim_frame, text=f"{int(self.virus_rate * 100)}%")
        self.virus_label.grid(row=1, column=2, padx=5, pady=5)
        
        # Error types
        error_frame = ttk.LabelFrame(parent, text="Error Types to Simulate")
        error_frame.pack(fill='x', padx=5, pady=5)
        
        self.error_types = {
            'file_corruption': tk.BooleanVar(value=True),
            'network_timeout': tk.BooleanVar(value=True),
            'invalid_format': tk.BooleanVar(value=True),
            'encoding_error': tk.BooleanVar(value=True),
            'permission_denied': tk.BooleanVar(value=True),
            'disk_full': tk.BooleanVar(value=False)
        }
        
        for i, (error_type, var) in enumerate(self.error_types.items()):
            ttk.Checkbutton(error_frame, text=error_type.replace('_', ' ').title(), 
                           variable=var).grid(row=i//3, column=i%3, sticky='w', padx=10, pady=2)
        
        # Virus types
        virus_frame = ttk.LabelFrame(parent, text="Virus Types to Simulate")
        virus_frame.pack(fill='x', padx=5, pady=5)
        
        self.virus_types = {
            'trojan': tk.BooleanVar(value=True),
            'worm': tk.BooleanVar(value=True),
            'ransomware': tk.BooleanVar(value=True),
            'spyware': tk.BooleanVar(value=True),
            'adware': tk.BooleanVar(value=False),
            'rootkit': tk.BooleanVar(value=True)
        }
        
        for i, (virus_type, var) in enumerate(self.virus_types.items()):
            ttk.Checkbutton(virus_frame, text=virus_type.replace('_', ' ').title(), 
                           variable=var).grid(row=i//3, column=i%3, sticky='w', padx=10, pady=2)
        
    def update_error_rate(self, value):
        self.error_rate = float(value) / 100
        self.error_label.config(text=f"{int(float(value))}%")
        
    def update_virus_rate(self, value):
        self.virus_rate = float(value) / 100
        self.virus_label.config(text=f"{int(float(value))}%")
        
    def log_email_status(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "#00ff00", "WARN": "#ffff00", "ERROR": "#ff0000", "VIRUS": "#ff6b6b"}
        
        self.email_status.config(state='normal')
        self.email_status.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
        
        # Color coding for the last line
        line_start = self.email_status.index("end-2c linestart")
        line_end = self.email_status.index("end-2c lineend")
        self.email_status.tag_add(level, line_start, line_end)
        self.email_status.tag_config(level, foreground=colors.get(level, "#ffffff"))
        
        self.email_status.see(tk.END)
        self.email_status.config(state='disabled')
        self.root.update_idletasks()
        
    def start_simulation(self):
        if not self.email_address.get():
            messagebox.showerror("Error", "Please enter email address!")
            return
            
        self.is_running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        self.log_email_status("Starting email monitoring simulation...")
        
        # Start simulation thread
        self.sim_thread = threading.Thread(target=self.simulation_loop)
        self.sim_thread.daemon = True
        self.sim_thread.start()
        
    def stop_simulation(self):
        self.is_running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.log_email_status("Email monitoring stopped.", "WARN")
        
    def simulation_loop(self):
        while self.is_running:
            try:
                # Simulate checking emails
                self.simulate_email_check()
                
                # Wait for next check
                interval = int(self.check_interval.get())
                for _ in range(interval):
                    if not self.is_running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.log_email_status(f"Simulation error: {str(e)}", "ERROR")
                break
                
    def simulate_email_check(self):
        self.log_email_status("Checking for new emails...")
        
        # Randomly decide if new email is received (70% chance)
        if random.random() > 0.3:
            # Generate simulated email with attachment
            self.simulate_new_email()
        else:
            self.log_email_status("No new emails found.")
            
    def simulate_new_email(self):
        # Generate random email data
        senders = ["client@company.com", "support@service.org", "admin@system.net", "user@domain.com", "suspicious@unknown.xyz"]
        subjects = ["Document Review Required", "Invoice Attached", "System Report", "Important Update", "Urgent: Action Required"]
        
        sender = random.choice(senders)
        subject = random.choice(subjects)
        
        # Generate attachment
        doc_types = ['pdf', 'docx', 'xlsx', 'txt', 'zip', 'exe']
        doc_type = random.choice(doc_types)
        filename = f"attachment_{random.randint(1000, 9999)}.{doc_type}"
        
        self.log_email_status(f"📧 New email from {sender}: '{subject}' with attachment: {filename}")
        
        # Process the document
        self.process_document(filename, sender, subject)
        
    def process_document(self, filename, sender, subject):
        self.log_email_status(f"🔄 Processing document: {filename}")
        
        # Simulate processing delay
        time.sleep(random.uniform(2, 5))
        
        # Determine status
        has_virus = random.random() < self.virus_rate
        has_error = random.random() < self.error_rate and not has_virus
        
        status = "Clean"
        threat_level = "Low"
        error_details = "None"
        
        if has_virus:
            status = "INFECTED"
            threat_level = self.simulate_virus_detection(filename)
        elif has_error:
            status = "Error"
            error_details = self.simulate_processing_error(filename)
        else:
            self.log_email_status(f"✅ Document {filename} processed successfully - CLEAN")
            
        # Create document record
        doc_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'size': f"{random.randint(10, 5000)} KB",
            'type': filename.split('.')[-1].upper(),
            'status': status,
            'threat_level': threat_level,
            'error_details': error_details,
            'sender': sender,
            'subject': subject,
            'hash': hashlib.md5(filename.encode()).hexdigest()[:16],
            'details': self.generate_analysis_report(filename, status, threat_level, error_details)
        }
        
        self.processed_docs.append(doc_data)
        self.update_statistics()
        
        # Update UI
        self.root.after(0, self.update_doc_tree, doc_data)
        
    def simulate_virus_detection(self, filename):
        enabled_viruses = [k for k, v in self.virus_types.items() if v.get()]
        if not enabled_viruses:
            return "Low"
            
        virus_type = random.choice(enabled_viruses)
        severity_levels = ["Low", "Medium", "High", "Critical"]
        severity = random.choice(severity_levels)
        
        action_taken = {
            "Low": "Quarantined",
            "Medium": "Deleted",
            "High": "Blocked & Reported",
            "Critical": "System Alert & Isolation"
        }[severity]
        
        self.log_email_status(f"🦠 VIRUS DETECTED in {filename}: {virus_type.upper()} - Severity: {severity}", "VIRUS")
        
        # Create virus record
        virus_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'filename': filename,
            'virus_type': virus_type.title(),
            'severity': severity,
            'action_taken': action_taken,
            'hash': hashlib.md5(filename.encode()).hexdigest()[:16],
            'details': self.generate_virus_report(filename, virus_type, severity, action_taken)
        }
        
        self.virus_detected.append(virus_data)
        self.root.after(0, self.update_virus_tree, virus_data)
        
        return severity
        
    def simulate_processing_error(self, filename):
        enabled_errors = [k for k, v in self.error_types.items() if v.get()]
        if not enabled_errors:
            return "Unknown error"
            
        error_type = random.choice(enabled_errors)
        
        error_messages = {
            'file_corruption': f"File header corruption detected in {filename}. Unable to parse document structure.",
            'network_timeout': f"Network timeout while downloading {filename}. Connection unstable.",
            'invalid_format': f"Invalid file format for {filename}. Expected format validation failed.",
            'encoding_error': f"Character encoding error in {filename}. Unable to decode text content.",
            'permission_denied': f"Access denied while processing {filename}. Insufficient privileges.",
            'disk_full': f"Insufficient disk space to process {filename}. Available space exceeded."
        }
        
        error_message = error_messages.get(error_type, "Unknown processing error occurred.")
        self.log_email_status(f"❌ Error processing {filename}: {error_type}", "ERROR")
        
        return error_message
        
    def generate_analysis_report(self, filename, status, threat_level, error_details):
        report = f"=== DOCUMENT ANALYSIS REPORT ===\n\n"
        report += f"Filename: {filename}\n"
        report += f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"File Size: {random.randint(10, 5000)} KB\n"
        report += f"File Type: {filename.split('.')[-1].upper()}\n"
        report += f"Status: {status}\n"
        report += f"Threat Level: {threat_level}\n\n"
        
        if status == "INFECTED":
            report += "⚠️ THREAT DETECTED ⚠️\n"
            report += "This file contains malicious content and has been quarantined.\n"
            report += "DO NOT OPEN OR EXECUTE THIS FILE.\n\n"
        elif status == "Error":
            report += "❌ PROCESSING ERROR\n"
            report += f"Error Details: {error_details}\n\n"
        else:
            report += "✅ CLEAN FILE\n"
            report += "No threats detected. File appears to be safe.\n\n"
            
        report += f"File Hash: {hashlib.md5(filename.encode()).hexdigest()}\n"
        report += f"Scan Engine Version: v{random.uniform(1.0, 3.0):.1f}\n"
        
        return report
        
    def generate_virus_report(self, filename, virus_type, severity, action_taken):
        report = f"=== VIRUS DETECTION REPORT ===\n\n"
        report += f"⚠️ MALWARE DETECTED ⚠️\n\n"
        report += f"File: {filename}\n"
        report += f"Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Virus Type: {virus_type.title()}\n"
        report += f"Severity Level: {severity}\n"
        report += f"Action Taken: {action_taken}\n\n"
        
        virus_descriptions = {
            'trojan': "Malicious software disguised as legitimate program. May steal sensitive data.",
            'worm': "Self-replicating malware that spreads across network connections.",
            'ransomware': "Encrypts files and demands payment for decryption key. HIGHLY DANGEROUS.",
            'spyware': "Secretly monitors user activity and collects personal information.",
            'adware': "Displays unwanted advertisements and may track browsing habits.",
            'rootkit': "Provides unauthorized access to system while hiding its presence."
        }
        
        report += f"Description: {virus_descriptions.get(virus_type, 'Unknown malware type')}\n\n"
        report += f"Recommended Actions:\n"
        report += f"- File has been {action_taken.lower()}\n"
        report += f"- Run full system scan\n"
        report += f"- Change all passwords\n"
        report += f"- Monitor system for unusual activity\n"
        
        return report
        
    def update_doc_tree(self, doc_data):
        # Color coding based on status
        item_id = self.doc_tree.insert('', 0, values=(
            doc_data['timestamp'],
            doc_data['filename'],
            doc_data['size'],
            doc_data['type'],
            doc_data['status'],
            doc_data['threat_level'],
            doc_data['error_details'][:50] + "..." if len(doc_data['error_details']) > 50 else doc_data['error_details']
        ))
        
        # Apply color tags
        if doc_data['status'] == "INFECTED":
            self.doc_tree.set(item_id, 'Status', '🦠 INFECTED')
        elif doc_data['status'] == "Error":
            self.doc_tree.set(item_id, 'Status', '❌ Error')
        else:
            self.doc_tree.set(item_id, 'Status', '✅ Clean')
            
    def update_virus_tree(self, virus_data):
        self.virus_tree.insert('', 0, values=(
            virus_data['timestamp'],
            virus_data['filename'],
            virus_data['virus_type'],
            virus_data['severity'],
            virus_data['action_taken'],
            virus_data['hash']
        ))
        
    def update_statistics(self):
        total_emails = len(self.processed_docs)
        total_viruses = len(self.virus_detected)
        total_errors = len([doc for doc in self.processed_docs if doc['status'] == 'Error'])
        total_clean = total_emails - total_viruses - total_errors
        
        self.stats_labels['emails'].config(text=str(total_emails))
        self.stats_labels['viruses'].config(text=str(total_viruses), style='Danger.TLabel' if total_viruses > 0 else 'Success.TLabel')
        self.stats_labels['errors'].config(text=str(total_errors), style='Warning.TLabel' if total_errors > 0 else 'Success.TLabel')
        self.stats_labels['clean'].config(text=str(total_clean))
        
    def on_doc_select(self, event):
        selection = self.doc_tree.selection()
        if selection:
            item = self.doc_tree.item(selection[0])
            filename = item['values'][1]
            
            doc_data = next((doc for doc in self.processed_docs if doc['filename'] == filename), None)
            if doc_data:
                self.doc_details.delete(1.0, tk.END)
                self.doc_details.insert(1.0, doc_data['details'])
                
    def on_virus_select(self, event):
        selection = self.virus_tree.selection()
        if selection:
            item = self.virus_tree.item(selection[0])
            filename = item['values'][1]
            
            virus_data = next((virus for virus in self.virus_detected if virus['filename'] == filename), None)
            if virus_data:
                self.virus_details.delete(1.0, tk.END)
                self.virus_details.insert(1.0, virus_data['details'])
                
    def send_test_email(self):
        self.log_email_status("Simulating test email reception...")
        
        # Generate test email
        test_filename = f"test_document_{datetime.now().strftime('%H%M%S')}.pdf"
        self.process_document(test_filename, "test@simulator.local", "Test Email Simulation")
        
    def manual_email_check(self):
        if self.is_running:
            self.log_email_status("Manual email check requested...")
            threading.Thread(target=self.simulate_email_check, daemon=True).start()
        else:
            messagebox.showwarning("Warning", "Please start monitoring first!")
            
    def load_config(self):
        try:
            if os.path.exists('virus_sim_config.json'):
                with open('virus_sim_config.json', 'r') as f:
                    config = json.load(f)
                    self.error_rate = config.get('error_rate', 0.4)
                    self.virus_rate = config.get('virus_rate', 0.25)
        except:
            pass
            
    def save_config(self):
        config = {
            'error_rate': self.error_rate,
            'virus_rate': self.virus_rate,
            'check_interval': self.check_interval.get()
        }
        
        try:
            with open('virus_sim_config.json', 'w') as f:
                json.dump(config, f, indent=2)
        except:
            pass

def main():
    root = tk.Tk()
    app = EmailVirusSimulator(root)
    
    def on_closing():
        app.stop_simulation()
        app.save_config()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Center window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (1200 // 2)
    y = (root.winfo_screenheight() // 2) - (800 // 2)
    root.geometry(f'1200x800+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()
