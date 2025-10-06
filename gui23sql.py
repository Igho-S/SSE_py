#this is the old gui

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from sse23c_mysql import RemoteDatabaseManager, ForwardPrivacySearchableEncryption  # Adjusted import

class ScrolledFrame(ttk.Frame):
    def __init__(self, parent, *args, **kw):
        ttk.Frame.__init__(self, parent, *args, **kw)
        vscrollbar = ttk.Scrollbar(self, orient="vertical")
        vscrollbar.pack(fill='y', side='right', expand=False)
        canvas = tk.Canvas(self, bd=0, highlightthickness=0,
                           yscrollcommand=vscrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        vscrollbar.config(command=canvas.yview)
        canvas.xview_moveto(0)
        canvas.yview_moveto(0)
        self.interior = interior = ttk.Frame(canvas)
        interior_id = canvas.create_window(0, 0, window=interior,
                                           anchor="nw")
        def _configure_interior(event):
            size = (interior.winfo_reqwidth(), interior.winfo_reqheight())
            canvas.config(scrollregion="0 0 %s %s" % size)
            if interior.winfo_reqwidth() != canvas.winfo_width():
                canvas.config(width=interior.winfo_reqwidth())
        interior.bind('<Configure>', _configure_interior)
        def _configure_canvas(event):
            if interior.winfo_reqwidth() != canvas.winfo_width():
                canvas.itemconfigure(interior_id, width=canvas.winfo_width())
        canvas.bind('<Configure>', _configure_canvas)

class EncryptionClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Forward Privacy Searchable Encryption Client")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Style configuration for better look
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use 'clam' theme for modern look
        self.style.configure('TButton', padding=10, relief="flat", background="#4CAF50", foreground="white")
        self.style.map('TButton', background=[('active', '#45a049')])
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('TRadiobutton', padding=5)
        self.style.configure('TCheckbutton', padding=5)
        self.style.configure('Treeview.Heading', font=('Helvetica', 10, 'bold'))
        self.style.configure('Treeview', rowheight=25)
        
        # Initialize variables
        self.db_manager = None
        self.sse = None
        self.server_url = tk.StringVar()
        self.user_id = tk.StringVar()
        self.passphrase = tk.StringVar()
        self.archive_passcode = tk.StringVar()
        self.is_connected = False
        
        # Timers for auto-lock
        self.idle_timeout = 15 * 60 * 1000  # 15 minutes in ms
        self.minimize_timeout = 3 * 60 * 1000  # 3 minutes in ms
        self.idle_timer = None
        self.minimize_timer = None
        self.is_minimized = False
        
        self.setup_ui()
        
        # Bind events for idle detection
        self.root.bind('<Any-KeyPress>', self.reset_timers)
        self.root.bind('<Any-ButtonPress>', self.reset_timers)
        self.root.bind('<Motion>', self.reset_timers)
        
        # Bind for minimize/restore
        self.root.bind('<Map>', self.on_restore)
        self.root.bind('<Unmap>', self.on_minimize)
        
        self.reset_timers()
        
    def setup_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create scrolled frames for each tab
        self.connection_frame = ScrolledFrame(self.notebook)
        self.document_frame = ScrolledFrame(self.notebook)
        self.search_frame = ScrolledFrame(self.notebook)
        self.session_frame = ScrolledFrame(self.notebook)
        self.archive_frame = ScrolledFrame(self.notebook)
        
        self.notebook.add(self.connection_frame, text="Connection")
        self.notebook.add(self.document_frame, text="Documents")
        self.notebook.add(self.search_frame, text="Search")
        self.notebook.add(self.session_frame, text="Sessions")
        self.notebook.add(self.archive_frame, text="Archive")
        
        # Setup each frame using interior
        self.setup_connection_frame(self.connection_frame.interior)
        self.setup_document_frame(self.document_frame.interior)
        self.setup_search_frame(self.search_frame.interior)
        self.setup_session_frame(self.session_frame.interior)
        self.setup_archive_frame(self.archive_frame.interior)
        
        # Status bar with connection indicator
        status_frame = ttk.Frame(self.root, relief=tk.SUNKEN, padding=5)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to connect")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.connection_dot = ttk.Label(status_frame, text="●", foreground="red")
        self.connection_dot.pack(side=tk.RIGHT, padx=10)
        
    def update_connection_status(self):
        if self.is_connected:
            self.connection_dot.config(foreground="green")
        else:
            self.connection_dot.config(foreground="red")
        
    def setup_connection_frame(self, parent):
        # Use Labelframe for grouping
        conn_group = ttk.LabelFrame(parent, text="Server Connection", padding=10)
        conn_group.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(conn_group, text="Server URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_group, textvariable=self.server_url, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(conn_group, text="User ID:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_group, textvariable=self.user_id, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(conn_group, text="Passphrase:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_group, textvariable=self.passphrase, show="*", width=30).grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(conn_group, text="User Type:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.user_type = tk.StringVar(value="existing")
        ttk.Radiobutton(conn_group, text="Existing User", variable=self.user_type, value="existing").grid(row=3, column=1, sticky=tk.W)
        ttk.Radiobutton(conn_group, text="New User", variable=self.user_type, value="new").grid(row=3, column=1, padx=100, sticky=tk.W)
        
        buttons_frame = ttk.Frame(conn_group)
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(buttons_frame, text="Connect", command=self.connect).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Disconnect", command=self.disconnect).pack(side=tk.LEFT, padx=5)
        
        # Connection status
        self.connection_status = ttk.Label(conn_group, text="Not connected")
        self.connection_status.grid(row=5, column=0, columnspan=2, pady=5)
        
        # Configure grid weights
        conn_group.grid_columnconfigure(1, weight=1)
        
    def setup_document_frame(self, parent):
        # Add document group
        add_group = ttk.LabelFrame(parent, text="Add Document", padding=10)
        add_group.pack(fill=tk.X, pady=10)
        
        add_group.rowconfigure(1, weight=1)
        add_group.columnconfigure(1, weight=1)
        
        ttk.Label(add_group, text="Document ID:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.doc_id = ttk.Entry(add_group, width=30)
        self.doc_id.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(add_group, text="Content:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.NW)
        self.content = scrolledtext.ScrolledText(add_group, width=50, height=10)
        self.content.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(add_group, text="Keywords (comma separated):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.keywords = ttk.Entry(add_group, width=50)
        self.keywords.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(add_group, text="Add Document", command=self.add_document).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Document list group
        list_group = ttk.LabelFrame(parent, text="Your Documents", padding=10)
        list_group.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview for documents
        columns = ("doc_id", "session_id", "created_at", "status")
        self.doc_tree = ttk.Treeview(list_group, columns=columns, show="headings", height=10)
        self.doc_tree.heading("doc_id", text="Document ID")
        self.doc_tree.heading("session_id", text="Session ID")
        self.doc_tree.heading("created_at", text="Created At")
        self.doc_tree.heading("status", text="Status")
        
        self.doc_tree.column("doc_id", width=150)
        self.doc_tree.column("session_id", width=100)
        self.doc_tree.column("created_at", width=150)
        self.doc_tree.column("status", width=100)
        
        self.doc_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(list_group)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="View Selected", command=self.view_document).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete Selected", command=self.delete_document).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Refresh List", command=self.refresh_documents).pack(side=tk.LEFT, padx=5)
        
    def setup_search_frame(self, parent):
        # Search group
        search_group = ttk.LabelFrame(parent, text="Keyword Search", padding=10)
        search_group.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_group, text="Keyword:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.search_keyword = ttk.Entry(search_group, width=30)
        self.search_keyword.grid(row=0, column=1, padx=5, pady=5)
        
        self.include_archived_search = tk.BooleanVar()
        ttk.Checkbutton(search_group, text="Include Archived Sessions", variable=self.include_archived_search).grid(row=1, column=1, sticky=tk.W)
        
        ttk.Button(search_group, text="Search", command=self.search).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Partial search group
        partial_group = ttk.LabelFrame(parent, text="Partial Keyword Search", padding=10)
        partial_group.pack(fill=tk.X, pady=10)
        
        ttk.Label(partial_group, text="Partial Keyword:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.partial_keyword = ttk.Entry(partial_group, width=30)
        self.partial_keyword.grid(row=0, column=1, padx=5, pady=5)
        
        self.include_archived_partial = tk.BooleanVar()
        ttk.Checkbutton(partial_group, text="Include Archived Sessions", variable=self.include_archived_partial).grid(row=1, column=1, sticky=tk.W)
        
        ttk.Button(partial_group, text="Partial Search", command=self.partial_search).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Results group
        results_group = ttk.LabelFrame(parent, text="Search Results", padding=10)
        results_group.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.results_list = tk.Listbox(results_group, width=80, height=15)
        self.results_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        buttons_frame = ttk.Frame(results_group)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="View Selected Result", command=self.view_searched_document).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
    def clear_results(self):
        self.results_list.delete(0, tk.END)
        
    def setup_session_frame(self, parent):
        # Session info
        info_group = ttk.LabelFrame(parent, text="Session Information", padding=10)
        info_group.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_group, text="Current Session:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.current_session = ttk.Label(info_group, text="Not available")
        self.current_session.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Session list
        list_group = ttk.LabelFrame(parent, text="All Sessions", padding=10)
        list_group.pack(fill=tk.BOTH, expand=True, pady=10)
        
        columns = ("session_id", "created_at", "doc_count", "status")
        self.session_tree = ttk.Treeview(list_group, columns=columns, show="headings", height=10)
        self.session_tree.heading("session_id", text="Session ID")
        self.session_tree.heading("created_at", text="Created At")
        self.session_tree.heading("doc_count", text="Document Count")
        self.session_tree.heading("status", text="Status")
        
        self.session_tree.column("session_id", width=250)
        self.session_tree.column("created_at", width=150)
        self.session_tree.column("doc_count", width=100)
        self.session_tree.column("status", width=150)
        
        self.session_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        buttons_frame = ttk.Frame(list_group)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(buttons_frame, text="Refresh Sessions", command=self.refresh_sessions).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="End Current Session", command=self.end_session).pack(side=tk.LEFT, padx=5)
        
    def setup_archive_frame(self, parent):
        # Archive management
        archive_group = ttk.LabelFrame(parent, text="Archive Access Management", padding=10)
        archive_group.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(archive_group, text="Archive Passcode:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(archive_group, textvariable=self.archive_passcode, show="*", width=30).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(archive_group, text="Set/Change Archive Passcode", command=self.set_archive_passcode).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(archive_group, text="Unlock Archive Access", command=self.unlock_archive).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(archive_group, text="Lock Archive Access", command=self.lock_archive).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Archive status
        ttk.Label(archive_group, text="Archive Status:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.archive_status = ttk.Label(archive_group, text="Not unlocked")
        self.archive_status.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        archive_group.grid_columnconfigure(1, weight=1)
        
    def connect(self):
        def connect_thread():
            try:
                self.status_var.set("Connecting to server...")
                self.db_manager = RemoteDatabaseManager(self.server_url.get())
                self.db_manager.connect()
                
                # Temporarily store passphrase before clearing
                temp_user_id = self.user_id.get()
                temp_passphrase = self.passphrase.get()
                
                # Create or authenticate user
                self.sse = ForwardPrivacySearchableEncryption(
                    self.db_manager, 
                    temp_user_id, 
                    temp_passphrase
                )
                
                if self.user_type.get() == "new":
                    messagebox.showinfo("Success", f"New user '{temp_user_id}' created successfully.")
                    
                    # Ask about archive passcode
                    if messagebox.askyesno("Archive Passcode", "Would you like to set an archive passcode for accessing old sessions?"):
                        self.set_archive_passcode_dialog(temp_passphrase)
                else:
                    messagebox.showinfo("Success", f"Welcome back, {temp_user_id}!")
                    
                    # Ask about unlocking archive
                    if messagebox.askyesno("Archive Access", "Do you want to unlock access to archived sessions?"):
                        self.unlock_archive_dialog()
                
                self.connection_status.config(text="Connected")
                self.status_var.set(f"Connected to DB | User ID: {self.sse.user_id}")
                self.is_connected = True
                self.update_connection_status()
                
                # Clear sensitive fields
                self.user_id.set("")
                self.passphrase.set("")
                
                # Enable other tabs
                for i in range(1, self.notebook.index("end")):
                    self.notebook.tab(i, state="normal")
                
                # Refresh data
                self.refresh_sessions()
                self.refresh_documents()
                
            except Exception as e:
                self.status_var.set(f"Connection failed: {str(e)}")
                messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
                self.connection_status.config(text="Connection failed")
        
        # Run connection in a thread to avoid freezing the UI
        threading.Thread(target=connect_thread, daemon=True).start()
        
    def disconnect(self):
        if not self.is_connected:
            return
            
        try:
            if self.sse:
                self.sse.end_current_session()  # End session on disconnect
            if self.db_manager:
                self.db_manager.disconnect()
            self.sse = None
            self.db_manager = None
            self.is_connected = False
            self.update_connection_status()
            self.connection_status.config(text="Disconnected")
            self.status_var.set("Disconnected")
            
            # Disable other tabs
            for i in range(1, self.notebook.index("end")):
                self.notebook.tab(i, state="disabled")
                
            # Clear data
            self.clear_all_data()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to disconnect: {str(e)}")
    
    def clear_all_data(self):
        # Clear treeviews and lists
        for item in self.doc_tree.get_children():
            self.doc_tree.delete(item)
        for item in self.session_tree.get_children():
            self.session_tree.delete(item)
        self.results_list.delete(0, tk.END)
        self.current_session.config(text="Not available")
        self.archive_status.config(text="Not unlocked")
        
    def reset_timers(self, event=None):
        if self.idle_timer:
            self.root.after_cancel(self.idle_timer)
        self.idle_timer = self.root.after(self.idle_timeout, self.auto_lock)
        
        if self.is_minimized and self.minimize_timer:
            self.root.after_cancel(self.minimize_timer)
            self.minimize_timer = None
        
    def on_minimize(self, event=None):
        if self.root.state() == 'iconic':
            self.is_minimized = True
            if self.minimize_timer:
                self.root.after_cancel(self.minimize_timer)
            self.minimize_timer = self.root.after(self.minimize_timeout, self.auto_lock)
        
    def on_restore(self, event=None):
        if self.root.state() != 'iconic':
            self.is_minimized = False
            if self.minimize_timer:
                self.root.after_cancel(self.minimize_timer)
                self.minimize_timer = None
            self.reset_timers()
        
    def auto_lock(self):
        if self.is_connected:
            messagebox.showinfo("Auto Lock", "Session timed out. Please relogin.")
            self.disconnect()
            # Require relogin - but since disconnect already handles, and user can reconnect
        
    def add_document(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        doc_id = self.doc_id.get()
        content = self.content.get("1.0", tk.END).strip()
        keywords = [k.strip() for k in self.keywords.get().split(",") if k.strip()]
        
        if not doc_id or not content or not keywords:
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        try:
            self.sse.add_document_with_partial_search(doc_id, content, keywords)
            messagebox.showinfo("Success", f"Document '{doc_id}' added successfully")
            
            # Clear fields
            self.doc_id.delete(0, tk.END)
            self.content.delete("1.0", tk.END)
            self.keywords.delete(0, tk.END)
            
            # Refresh document list
            self.refresh_documents()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add document: {str(e)}")
    
    def search(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        keyword = self.search_keyword.get().strip()
        if not keyword:
            messagebox.showerror("Error", "Please enter a keyword to search")
            return
            
        try:
            results = self.sse.search_documents(keyword, self.include_archived_search.get())
            self.display_results(results)
            self.search_keyword.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")
    
    def partial_search(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        keyword = self.partial_keyword.get().strip()
        if not keyword:
            messagebox.showerror("Error", "Please enter a partial keyword to search")
            return
            
        try:
            results = self.sse.partial_search(keyword, self.include_archived_partial.get())
            self.display_results(results)
            self.partial_keyword.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Partial search failed: {str(e)}")
    
    def display_results(self, results):
        self.results_list.delete(0, tk.END)
        if results:
            for doc_id in results:
                self.results_list.insert(tk.END, doc_id)
        else:
            self.results_list.insert(tk.END, "No results found")
    
    def view_searched_document(self):
        selection = self.results_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a document to view")
            return
            
        doc_id = self.results_list.get(selection[0])
        self.view_document_by_id(doc_id)
    
    def refresh_documents(self):
        if not self.sse:
            return
            
        try:
            # Clear treeview
            for item in self.doc_tree.get_children():
                self.doc_tree.delete(item)
                
            # Get documents
            include_archived = self.sse.archive_access_key is not None
            documents = self.sse.list_documents(include_archived)
            
            # Add to treeview
            for doc in documents:
                status = "Current" if doc['is_current_session'] else "Archived"
                created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(doc['created_at']))
                self.doc_tree.insert("", tk.END, values=(
                    doc['doc_id'], 
                    doc['session_id'][:8] + "...", 
                    created_at, 
                    status
                ))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh documents: {str(e)}")
    
    def view_document(self):
        selection = self.doc_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a document to view")
            return
            
        item = self.doc_tree.item(selection[0])
        doc_id = item['values'][0]
        self.view_document_by_id(doc_id)
    
    def view_document_by_id(self, doc_id):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        try:
            content = self.sse.get_document(doc_id)
            if content:
                # Create a new window to display the document
                window = tk.Toplevel(self.root)
                window.title(f"Document: {doc_id}")
                window.geometry("600x400")
                window.resizable(True, True)
                
                text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD)
                text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                text_area.insert(tk.INSERT, content)
                text_area.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", "Failed to retrieve document or access denied")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view document: {str(e)}")
    
    def delete_document(self):
        selection = self.doc_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a document to delete")
            return
            
        item = self.doc_tree.item(selection[0])
        doc_id = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete document '{doc_id}'?"):
            try:
                self.sse.delete_document(doc_id)
                messagebox.showinfo("Success", f"Document '{doc_id}' deleted successfully")
                self.refresh_documents()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete document: {str(e)}")
    
    def refresh_sessions(self):
        if not self.sse:
            return
            
        try:
            # Update current session
            self.current_session.config(text=self.sse.current_session_id)
            
            # Clear treeview
            for item in self.session_tree.get_children():
                self.session_tree.delete(item)
                
            # Get session info
            info = self.sse.get_session_info()
            
            # Add to treeview
            archive_status = "Unlocked" if self.sse.archive_access_key is not None else "Locked"
            for session in info['sessions']:
                if session['is_current']:
                    status = "Active"
                else:
                    status = f"Archived - {archive_status}"
                created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['created_at']))
                self.session_tree.insert("", tk.END, values=(
                    session['session_id'], 
                    created_at, 
                    session['document_count'], 
                    status
                ))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh sessions: {str(e)}")
    
    def end_session(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to end the current session? This implements forward privacy."):
            try:
                old_session = self.sse.current_session_id
                self.sse.end_current_session()
                messagebox.showinfo("Success", f"Session ended. New session started.")
                self.refresh_sessions()
                self.refresh_documents()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to end session: {str(e)}")
    
    def set_archive_passcode_dialog(self, main_passphrase):
        # Create a dialog to set archive passcode
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Archive Passcode")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="New Archive Passcode:").pack(pady=5)
        passcode_entry = ttk.Entry(dialog, show="*", width=30)
        passcode_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Confirm Passcode:").pack(pady=5)
        confirm_entry = ttk.Entry(dialog, show="*", width=30)
        confirm_entry.pack(pady=5)
        
        def set_passcode():
            if passcode_entry.get() != confirm_entry.get():
                messagebox.showerror("Error", "Passcodes don't match")
                return
                
            try:
                # For new users, use the main passphrase as the "old" passcode
                self.sse.set_archive_passcode(main_passphrase, passcode_entry.get())
                messagebox.showinfo("Success", "Archive passcode set successfully")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to set archive passcode: {str(e)}")
        
        ttk.Button(dialog, text="Set Passcode", command=set_passcode).pack(pady=10)
    
    def ask_string_dialog(self, title, prompt, show=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=prompt).pack(pady=10)
        entry = ttk.Entry(dialog, show=show, width=30)
        entry.pack(pady=5)
        
        result = [None]
        
        def confirm():
            result[0] = entry.get()
            dialog.destroy()
        
        def cancel():
            result[0] = None
            dialog.destroy()
        
        buttons = ttk.Frame(dialog)
        buttons.pack(pady=10)
        ttk.Button(buttons, text="OK", command=confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=5)
        
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        self.root.wait_window(dialog)
        return result[0]
    
    def set_archive_passcode(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        # Check if we need old passcode
        try:
            result = self.sse.db_manager.execute_query(
                "SELECT archive_key_hash FROM users WHERE user_id = %s",
                (self.sse.user_id,)
            )
            has_existing = result and result[0]['archive_key_hash']
            
            if has_existing:
                # Need old archive passcode
                old_passcode = self.ask_string_dialog("Archive Passcode", "Enter current archive passcode:", show="*")
                if old_passcode is None:
                    return
            else:
                # Need main passphrase for first-time setup
                old_passcode = self.ask_string_dialog("Verification", "Enter your main passphrase:", show="*")
                if old_passcode is None:
                    return
            
            new_passcode = self.ask_string_dialog("New Archive Passcode", "Enter new archive passcode:", show="*")
            if new_passcode is None:
                return
                
            confirm = self.ask_string_dialog("Confirm", "Confirm new archive passcode:", show="*")
            if new_passcode != confirm:
                messagebox.showerror("Error", "Passcodes don't match")
                return
                
            self.sse.set_archive_passcode(old_passcode, new_passcode)
            messagebox.showinfo("Success", "Archive passcode set/updated successfully")
            self.archive_passcode.set("")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set archive passcode: {str(e)}")
    
    def unlock_archive_dialog(self):
        passcode = self.ask_string_dialog("Archive Access", "Enter archive passcode:", show="*")
        if passcode:
            self.unlock_archive_with_passcode(passcode)
    
    def unlock_archive_with_passcode(self, passcode):
        try:
            if self.sse.unlock_archive_access(passcode):
                self.archive_status.config(text="Unlocked")
                messagebox.showinfo("Success", "Archive access unlocked")
            else:
                messagebox.showerror("Error", "Invalid archive passcode")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock archive: {str(e)}")
    
    def unlock_archive(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        passcode = self.archive_passcode.get()
        if not passcode:
            messagebox.showerror("Error", "Please enter an archive passcode")
            return
            
        self.unlock_archive_with_passcode(passcode)
        self.archive_passcode.set("")
    
    def lock_archive(self):
        if not self.sse:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        self.sse.archive_access_key = None
        self.archive_status.config(text="Locked")
        messagebox.showinfo("Success", "Archive access locked")
        self.archive_passcode.set("")

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionClientGUI(root)
    root.mainloop()