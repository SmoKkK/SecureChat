import socketio
import customtkinter as ctk  # Modern GUI library
from tkinter import simpledialog
import threading
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import json
from PIL import Image, ImageTk
import tkinter as tk
from datetime import datetime
import re
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter

# Set appearance mode and color theme
ctk.set_appearance_mode("System")  # Options: "Dark", "Light", "System"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

class ChatClient:
    def __init__(self, server_url):
        self.sio = socketio.Client()
        self.server_url = server_url
        self.username = None
        self.encryption_key = None
        self.current_chat = "Global"  # Track current chat (Global or specific user)
        self.online_users = []  # List of online users
        self.messages_file = "messages.json"  # File to store messages
        self.active_user_buttons = {}  # Track active user buttons
        self.link_urls = {}  # Store URLs for links
        self.spoiler_ranges = []  # Store ranges for spoilers
        
        self.sio.on('connect', self.on_connect)
        self.sio.on('disconnect', self.on_disconnect)
        self.sio.on('message', self.on_message)
        self.sio.on('userList', self.on_user_list)
        
        self.root = ctk.CTk()  # Use customtkinter's main window
        self.root.title("Secure Chat Client")
        self.root.geometry("1200x700")
        self.root.minsize(800, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.setup_gui()
    
    def setup_gui(self):
        # Configure grid layout
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Sidebar for chat selection (left side)
        self.sidebar = ctk.CTkFrame(self.root, corner_radius=0, fg_color="#1a1a1a", width=250)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_columnconfigure(0, weight=1)
        self.sidebar.grid_rowconfigure(2, weight=1)
        
        # Fix sidebar width
        self.sidebar.grid_propagate(False)
        
        # App title in sidebar
        self.app_title_frame = ctk.CTkFrame(self.sidebar, corner_radius=0, fg_color="#1a1a1a", height=60)
        self.app_title_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 5))
        self.app_title_frame.grid_propagate(False)
        
        self.app_title = ctk.CTkLabel(
            self.app_title_frame, text="Secure Chat Client", 
            font=("Helvetica", 22, "bold"), text_color="#ffffff")
        self.app_title.pack(side=ctk.LEFT, padx=20, pady=15)
        
        # Connection status frame
        self.status_frame = ctk.CTkFrame(self.sidebar, corner_radius=0, fg_color="#1a1a1a", height=50)
        self.status_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self.status_frame.grid_propagate(False)
        
        # Status indicator container
        self.status_indicator_frame = ctk.CTkFrame(self.status_frame, fg_color="#252525", corner_radius=10)
        self.status_indicator_frame.pack(fill=ctk.X, padx=0, pady=5)
        
        self.status_indicator = ctk.CTkCanvas(self.status_indicator_frame, width=12, height=12, 
                                             bg="#252525", highlightthickness=0)
        self.status_indicator.pack(side=ctk.LEFT, padx=(15, 10), pady=10)
        self.status_indicator.create_oval(2, 2, 10, 10, fill="#ff3b30", outline="")
        
        self.status_text = ctk.CTkLabel(
            self.status_indicator_frame, text="Disconnected", font=("Helvetica", 12),
            text_color="#cccccc")
        self.status_text.pack(side=ctk.LEFT, fill=ctk.X, padx=5, pady=10)
        
        # Connect button (initially hidden)
        self.connect_button = ctk.CTkButton(
            self.sidebar, text="Reconnect", command=self.reconnect,
            font=("Helvetica", 13), height=32, fg_color="#0a84ff", 
            hover_color="#007aff", corner_radius=8)
        self.connect_button.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self.connect_button.grid_remove()  # Initially hidden
        
        # Chat selection area with scrollable frame
        self.chats_container_frame = ctk.CTkFrame(self.sidebar, corner_radius=0, fg_color="#1a1a1a")
        self.chats_container_frame.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        self.chats_container_frame.grid_columnconfigure(0, weight=1)
        self.chats_container_frame.grid_rowconfigure(1, weight=1)
        
        # Chats label
        self.chats_label = ctk.CTkLabel(
            self.chats_container_frame, text="Chats", 
            font=("Helvetica", 16, "bold"), text_color="#ffffff")
        self.chats_label.grid(row=0, column=0, sticky="w", padx=20, pady=(10, 5))
        
        # Scrollable frame for chats
        self.chats_container = ctk.CTkScrollableFrame(
            self.chats_container_frame, corner_radius=0, fg_color="#1a1a1a",
            scrollbar_button_color="#333333", scrollbar_button_hover_color="#444444")
        self.chats_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        
        # Global Chat button
        self.global_chat_button = ctk.CTkButton(
            self.chats_container, text="Global Chat", height=40,
            command=lambda: self.switch_chat("Global"),
            font=("Helvetica", 14), fg_color="#0a84ff", hover_color="#3a3a3a",
            text_color="#ffffff", corner_radius=8)
        self.global_chat_button.pack(fill=ctk.X, pady=(5, 10), padx=15)
        
        # User profile section at bottom of sidebar
        self.profile_frame = ctk.CTkFrame(self.sidebar, corner_radius=0, fg_color="#252525", height=70)
        self.profile_frame.grid(row=3, column=0, sticky="ew", padx=0, pady=0)
        self.profile_frame.grid_propagate(False)
        
        self.profile_label = ctk.CTkLabel(
            self.profile_frame, text="Not logged in", font=("Helvetica", 14, "bold"),
            text_color="#ffffff")
        self.profile_label.pack(fill=ctk.X, padx=20, pady=(15, 0))
        
        self.logout_button = ctk.CTkButton(
            self.profile_frame, text="Disconnect", height=25, width=200,
            command=self.disconnect, font=("Helvetica", 12),
            fg_color="#3a3a3a", hover_color="#4a4a4a", corner_radius=5)
        self.logout_button.pack(anchor="w", padx=20, pady=(5, 15))
        
        # Main content area (right side)
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="#212121")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Chat header
        self.chat_header = ctk.CTkFrame(self.main_frame, corner_radius=0, fg_color="#252525", height=60)
        self.chat_header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        
        self.chat_title = ctk.CTkLabel(
            self.chat_header, text="Global Chat", font=("Helvetica", 18, "bold"),
            text_color="#ffffff")
        self.chat_title.pack(side=ctk.LEFT, padx=20, pady=15)
        
        self.online_indicator = ctk.CTkLabel(
            self.chat_header, text="0 users online", font=("Helvetica", 12),
            text_color="#aaaaaa")
        self.online_indicator.pack(side=ctk.RIGHT, padx=20, pady=15)
        
        # Chat display area
        self.chat_frame = ctk.CTkFrame(self.main_frame, corner_radius=0, fg_color="#212121")
        self.chat_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.chat_frame.grid_rowconfigure(0, weight=1)
        self.chat_frame.grid_columnconfigure(0, weight=1)
        
        # Use a text widget that supports tags for different message types
        self.chat_display = tk.Text(
            self.chat_frame, wrap=tk.WORD, state=tk.DISABLED, 
            bg="#212121", fg="#ffffff", font=("Helvetica", 13),
            highlightthickness=0, bd=0, padx=20, pady=20)
        self.chat_display.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        
        # Configure message appearance
        self.chat_display.tag_configure("system", foreground="#aaaaaa", font=("Helvetica", 12, "italic"))
        self.chat_display.tag_configure("user", foreground="#3a8eff")
        self.chat_display.tag_configure("dm", foreground="#ffcc00")
        self.chat_display.tag_configure("timestamp", foreground="#666666", font=("Helvetica", 11))
        self.chat_display.tag_configure("bold", font=("Helvetica", 13, "bold"))
        self.chat_display.tag_configure("italic", font=("Helvetica", 13, "italic"))
        self.chat_display.tag_configure("code", font=("Courier", 12), background="#2c2c2c")
        self.chat_display.tag_configure("code_block", font=("Courier", 12), background="#2c2c2c")
        self.chat_display.tag_configure("link", foreground="#4da6ff", underline=True)
        self.chat_display.tag_configure("spoiler", foreground="#2c2c2c", background="#2c2c2c")
        self.chat_display.tag_configure("spoiler_revealed", foreground="#ffffff", background="#2c2c2c")
        self.chat_display.tag_bind("spoiler", "<Button-1>", self.on_spoiler_hover)  
        self.chat_display.tag_bind("spoiler", "<Leave>", self.on_spoiler_leave)
        
        # Scrollbar for chat
        self.chat_scrollbar = ctk.CTkScrollbar(self.chat_frame, command=self.chat_display.yview)
        self.chat_scrollbar.grid(row=0, column=1, sticky="ns")
        self.chat_display.configure(yscrollcommand=self.chat_scrollbar.set)
        
        # Input area at the bottom
        self.input_frame = ctk.CTkFrame(self.main_frame, corner_radius=0, fg_color="#2c2c2c", height=70)
        self.input_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.input_frame.grid_columnconfigure(0, weight=1)
        
        # Replace single-line entry with multiline text widget
        self.message_input = ctk.CTkTextbox(
            self.input_frame, 
            font=("Helvetica", 14), 
            height=40,
            fg_color="#333333",
            text_color="#ffffff",
            border_width=0,
            wrap="word"
        )
        self.message_input.grid(row=0, column=0, sticky="ew", padx=(20, 10), pady=15)
        
        # Bind Shift+Enter for newline and Enter to send message
        self.message_input.bind("<Return>", lambda event: self.handle_enter(event))
        self.message_input.bind("<Shift-Return>", lambda event: self.handle_shift_enter(event))
        
        self.send_button = ctk.CTkButton(
            self.input_frame, text="Send", command=self.send_message, 
            font=("Helvetica", 14), width=80, height=40,
            fg_color="#0a84ff", hover_color="#007aff", corner_radius=8)
        self.send_button.grid(row=0, column=1, padx=(0, 20), pady=15)
    
    def parse_markdown(self, text):
        """
        Parse Markdown syntax and prepare it for rendering.
        This function creates a list of text segments and their associated tags.
        """
        segments = []
        current_position = 0
        
        # Process code blocks first (triple backticks)
        code_block_pattern = re.compile(r'```(.*?)```', re.DOTALL)
        code_block_matches = list(code_block_pattern.finditer(text))
        
        # Process text segments between and around code blocks
        last_end = 0
        for match in code_block_matches:
            start, end = match.span()
            
            # Process text before the code block
            if start > last_end:
                pre_text = text[last_end:start]
                segments.extend(self.process_inline_markdown(pre_text, last_end))
            
            # Extract language and code
            code_content = match.group(1).strip()
            language = "code"
            if "\n" in code_content:
                first_line = code_content.split("\n", 1)[0].strip()
                if first_line and not first_line.startswith("```"):
                    language = first_line
                    code_content = code_content[len(first_line)+1:].strip()
            
            # Add the code block
            segments.append((code_content, start, end, "code_block", language))
            last_end = end
        
        # Process the remaining text after all code blocks
        if last_end < len(text):
            remaining_text = text[last_end:]
            segments.extend(self.process_inline_markdown(remaining_text, last_end))
        
        return segments
    
    def process_inline_markdown(self, text, offset=0):
        """Process inline markdown elements like bold, italic, code, and links."""
        segments = []
        
        # Find all inline markdown elements
        patterns = [
            # Bold
            (r'\*\*(.*?)\*\*', "bold"),
            # Italic
            (r'\*(.*?)\*', "italic"),
            # Inline code with `
            (r'`(.*?)`', "code"),
            # Links with [text](url)
            (r'\[(.*?)\]\((.*?)\)', "link"),
            # Spoiler
            (r'\|\|(.*?)\|\|', "spoiler"),
        ]
        
        # Find all matches for each pattern
        all_matches = []
        for pattern, tag in patterns:
            for match in re.finditer(pattern, text):
                # Store the match span, the content (without markup), and tag
                if tag == "link":
                    # For links, store both text and URL
                    all_matches.append((match.span(), match.group(1), match.group(2), tag))
                else:
                    # For other tags, store content without markers, and the full match span
                    all_matches.append((match.span(), match.group(1), None, tag))
        
        # Sort matches by their start position
        all_matches.sort(key=lambda x: x[0][0])
        
        # Check for overlapping matches and remove them
        filtered_matches = []
        if all_matches:
            filtered_matches.append(all_matches[0])
            for current_match in all_matches[1:]:
                prev_match = filtered_matches[-1]
                # If current match starts before previous match ends, skip it
                if current_match[0][0] < prev_match[0][1]:
                    continue
                filtered_matches.append(current_match)
        
        # Process matches in order
        last_end = 0
        for (start, end), content, url, tag in filtered_matches:
            # If there's plain text before this match, add it
            if start > last_end:
                plain_text = text[last_end:start]
                if plain_text:
                    segments.append((plain_text, offset + last_end, offset + start, None, None))
            
            # Handle the matched content based on tag
            if tag == "link":
                segments.append((content, offset + start, offset + end, tag, url))
            else:
                segments.append((content, offset + start, offset + end, tag, None))
            
            last_end = end
        
        # Add any remaining text after the last match
        if last_end < len(text):
            plain_text = text[last_end:]
            if plain_text:
                segments.append((plain_text, offset + last_end, offset + len(text), None, None))
        
        return segments
    
    def render_markdown(self, text_widget, segments):
        def handle_link_click(event):
            index = text_widget.index(f"@%d,%d" % (event.x, event.y))
            tags = text_widget.tag_names(index)
            if 'link' in tags:
                for (start, end), url in self.link_urls.items():
                    if text_widget.compare(start, '<=', index) and text_widget.compare(index, '<', end):
                        import webbrowser
                        webbrowser.open(url)
                        return

        # Bind click handler
        text_widget.tag_bind("link", "<Button-1>", handle_link_click)
        text_widget.tag_config("link", foreground="#4da6ff", underline=1)
        text_widget.tag_bind("link", "<Enter>", lambda e: text_widget.config(cursor="hand2"))
        text_widget.tag_bind("link", "<Leave>", lambda e: text_widget.config(cursor=""))
        
        for content, _, _, tag, extra_info in segments:
            if tag == "code_block":
                text_widget.insert(tk.END, "\n")
                try:
                    lexer = get_lexer_by_name(extra_info or "text", stripall=True)
                    formatter = HtmlFormatter(style="monokai", noclasses=True)
                    highlighted_html = highlight(content, lexer, formatter)
                    text_widget.insert(tk.END, f"```{extra_info or 'text'}\n", "code_block")
                    text_widget.insert(tk.END, content + "\n", "code_block")
                    text_widget.insert(tk.END, "```\n")
                except Exception:
                    text_widget.insert(tk.END, f"```{extra_info or 'text'}\n", "code_block")
                    text_widget.insert(tk.END, content + "\n", "code_block")
                    text_widget.insert(tk.END, "```\n")

            elif tag == "link":
                start_index = text_widget.index("insert")
                text_widget.insert(tk.END, content, "link")
                end_index = text_widget.index("insert")
                self.link_urls[(start_index, end_index)] = extra_info

            elif tag == "spoiler":
                start_index = text_widget.index("insert")
                text_widget.insert(tk.END, content, "spoiler")
                end_index = text_widget.index("insert")
                self.spoiler_ranges.append((start_index, end_index))
                # Don't configure or bind tags here, it's already done once in setup_gui

            elif tag:
                text_widget.insert(tk.END, content, tag)
            else:
                text_widget.insert(tk.END, content)
    
    def display_formatted_message(self, username, message, timestamp=None, is_dm=False):
        """
        Display a message with proper Markdown formatting.
        """
        self.flash_taskbar()
        self.chat_display.config(state=tk.NORMAL)
        
        # Clear spoiler ranges for new message
        self.spoiler_ranges = []
        
        # Insert timestamp
        if not timestamp:
            timestamp = datetime.now().strftime("%H:%M")
        
        # Insert username
        if username == "System":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            # System messages don't need markdown parsing
            self.chat_display.insert(tk.END, f"{username}: ", "system")
            self.chat_display.insert(tk.END, message + "\n", "system")
        else:
            # Insert username with appropriate tag
            if is_dm:
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"{username}: ", "dm")
            else:
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"{username}: ", "user")
            
            # Parse and render markdown content
            parsed_segments = self.parse_markdown(message)
            self.render_markdown(self.chat_display, parsed_segments)
            self.chat_display.insert(tk.END, "\n")  # End the message with newline
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def switch_chat(self, chat_target):
        """Switch between Global Chat and Private Chat with a user."""
        self.current_chat = chat_target
        
        # Update the current chat label
        self.chat_title.configure(text=f"{chat_target} Chat" if chat_target == "Global" else f"Chat with {chat_target}")
        
        # Highlight the active chat button
        if chat_target == "Global":
            self.global_chat_button.configure(fg_color="#0a84ff")
            for username, button in self.active_user_buttons.items():
                button.configure(fg_color="#2c2c2c")
        else:
            self.global_chat_button.configure(fg_color="#2c2c2c")
            for username, button in self.active_user_buttons.items():
                if username == chat_target:
                    button.configure(fg_color="#0a84ff")
                else:
                    button.configure(fg_color="#2c2c2c")
        
        # Add system message showing chat switch
        self.display_message("System", f"Switched to {chat_target} chat")
    
    def save_username(self, username):
        with open("username.txt", "w") as file:
            file.write(username)
    
    def load_username(self):
        if os.path.exists("username.txt"):
            with open("username.txt", "r") as file:
                return file.read().strip()
        return None
    
    def start(self):
        # Create a custom dialog for encryption key
        key_dialog = ctk.CTkToplevel(self.root)
        key_dialog.title("Encryption Key")
        key_dialog.geometry("400x200")
        key_dialog.resizable(False, False)
        key_dialog.transient(self.root)
        key_dialog.grab_set()
        
        # Center the dialog on screen
        key_dialog.update_idletasks()
        width = key_dialog.winfo_width()
        height = key_dialog.winfo_height()
        x = (key_dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (key_dialog.winfo_screenheight() // 2) - (height // 2)
        key_dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        dialog_frame = ctk.CTkFrame(key_dialog, corner_radius=0)
        dialog_frame.pack(fill=ctk.BOTH, expand=True)
        
        ctk.CTkLabel(
            dialog_frame, text="Enter Encryption Key", 
            font=("Helvetica", 18, "bold")
        ).pack(pady=(25, 15))
        
        key_var = tk.StringVar()
        key_entry = ctk.CTkEntry(
            dialog_frame, textvariable=key_var, show="•", 
            width=300, height=40, font=("Helvetica", 14)
        )
        key_entry.pack(pady=(5, 20))
        key_entry.focus()
        
        def submit_key():
            self.encryption_key = key_var.get()
            if not self.encryption_key:
                return
            self.encryption_key = hashlib.sha256(self.encryption_key.encode()).digest()
            key_dialog.destroy()
            self.continue_login()
            
        ctk.CTkButton(
            dialog_frame, text="Connect", command=submit_key,
            width=150, height=40, font=("Helvetica", 14)
        ).pack(pady=10)
        
        key_entry.bind("<Return>", lambda e: submit_key())
        
        # Wait for the dialog to be closed
        self.root.wait_window(key_dialog)
        
        self.root.mainloop()
    
    def continue_login(self):
        if not self.encryption_key:
            return
            
        saved_username = self.load_username()
        if saved_username:
            self.username = saved_username
        else:
            # Create a custom dialog for username
            username_dialog = ctk.CTkToplevel(self.root)
            username_dialog.title("Username")
            username_dialog.geometry("400x200")
            username_dialog.resizable(False, False)
            username_dialog.transient(self.root)
            username_dialog.grab_set()
            
            # Center the dialog on screen
            username_dialog.update_idletasks()
            width = username_dialog.winfo_width()
            height = username_dialog.winfo_height()
            x = (username_dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (username_dialog.winfo_screenheight() // 2) - (height // 2)
            username_dialog.geometry(f"{width}x{height}+{x}+{y}")
            
            dialog_frame = ctk.CTkFrame(username_dialog, corner_radius=0)
            dialog_frame.pack(fill=ctk.BOTH, expand=True)
            
            ctk.CTkLabel(
                dialog_frame, text="Enter Username", 
                font=("Helvetica", 18, "bold")
            ).pack(pady=(25, 15))
            
            username_var = tk.StringVar()
            username_entry = ctk.CTkEntry(
                dialog_frame, textvariable=username_var, 
                width=300, height=40, font=("Helvetica", 14)
            )
            username_entry.pack(pady=(5, 20))
            username_entry.focus()
            
            def submit_username():
                self.username = username_var.get()
                if not self.username:
                    self.username = f"User_{int(time.time())}"
                self.save_username(self.username)
                username_dialog.destroy()
                self.finalize_startup()
                
            ctk.CTkButton(
                dialog_frame, text="Join Chat", command=submit_username,
                width=150, height=40, font=("Helvetica", 14)
            ).pack(pady=10)
            
            username_entry.bind("<Return>", lambda e: submit_username())
            
            # Wait for the dialog to be closed
            self.root.wait_window(username_dialog)
        
        if saved_username:
            self.finalize_startup()
    
    def finalize_startup(self):
        # Update profile
        self.profile_label.configure(text=self.username)
        
        # Load existing messages
        self.load_messages()
        
        # Connect to server
        self.connection_thread = threading.Thread(target=self.connect_to_server)
        self.connection_thread.daemon = True
        self.connection_thread.start()
    
    def encrypt_message(self, message):
        cipher = AES.new(self.encryption_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted_bytes).decode()
    
    def decrypt_message(self, encrypted_message):
        try:
            data = base64.b64decode(encrypted_message)
            iv = data[:16]
            encrypted_bytes = data[16:]
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()
        except Exception as e:
            # print(f"Decryption error: {str(e)}")
            return None  # Return None if decryption fails
    
    def reconnect(self):
        """Reconnect to the server after disconnection."""
        self.connect_button.grid_remove()  # Hide connect button
        self.connection_thread = threading.Thread(target=self.connect_to_server)
        self.connection_thread.daemon = True
        self.connection_thread.start()
    
    def connect_to_server(self):
        try:
            self.update_status("Connecting...", "#ffcc00")  # Yellow for connecting
            self.sio.connect(self.server_url)
            self.sio.emit('join', self.username)
        except Exception as e:
            self.display_message("System", f"Error connecting to server: {str(e)}")
            self.update_status(f"Connection failed", "#ff3b30")  # Red for failed
            self.connect_button.grid()  # Show connect button when connection fails
    
    def on_connect(self):
        self.update_status("Connected", "#30d158")  # Green for connected
        self.display_message("System", "Connected to the server")
        self.connect_button.grid_remove()  # Hide connect button when connected
    
    def on_disconnect(self):
        self.update_status("Disconnected", "#ff3b30")  # Red for disconnected
        self.display_message("System", "Disconnected from the server")
        self.connect_button.grid()  # Show connect button when disconnected
        self.online_indicator.configure(text="0 users online")  # Reset user count
        self.update_users_list([])  # Clear users list
    
    def on_message(self, data):
        decrypted_text = self.decrypt_message(data['text'])
        if decrypted_text is None:  # Skip messages with decryption errors
            return
        is_dm = data.get('recipient') is not None
        self.display_formatted_message(data['user'], decrypted_text, data.get('time'), is_dm)
        self.save_message(data)  # Save the received message
    
    def on_user_list(self, users):
        self.online_users = users
        self.update_users_list(users)
        # Update the online users count
        user_count = len(users)
        self.online_indicator.configure(text=f"{user_count} users online")
    
    def display_message(self, username, message, timestamp=None, is_dm=False):
        """Simple message display without markdown for system messages"""
        self.flash_taskbar()
        self.chat_display.config(state=tk.NORMAL)
        
        # Insert timestamp
        if not timestamp:
            timestamp = datetime.now().strftime("%H:%M")
        
        # Insert username
        if username == "System":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            # System messages don't need markdown parsing
            self.chat_display.insert(tk.END, f"{username}: ", "system")
            self.chat_display.insert(tk.END, message + "\n", "system")
        elif is_dm:
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{username}: ", "dm")
            self.chat_display.insert(tk.END, message + "\n")
        else:
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{username}: ", "user")
            self.chat_display.insert(tk.END, message + "\n")
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def update_status(self, status_text, color="#cccccc"):
        self.status_text.configure(text=status_text)
        self.status_indicator.delete("all")
        self.status_indicator.create_oval(2, 2, 10, 10, fill=color, outline="")
    
    def update_users_list(self, users):
        # Clear all existing user buttons first
        for button in self.active_user_buttons.values():
            button.destroy()
        self.active_user_buttons = {}
        
        # Add user buttons
        for user in users:
            if user == self.username:  # Skip self
                continue
                
            user_button = ctk.CTkButton(
                self.chats_container, text=user, height=40,
                command=lambda u=user: self.switch_chat(u),
                font=("Helvetica", 14), fg_color="#2c2c2c", hover_color="#3a3a3a",
                text_color="#ffffff", corner_radius=8)
            user_button.pack(fill=ctk.X, pady=5, padx=15)
            
            # Store reference to button
            self.active_user_buttons[user] = user_button
    
    def load_messages(self):
        """Load messages from the JSON file and display them with markdown support."""
        if not os.path.exists(self.messages_file):
            return
        
        try:
            with open(self.messages_file, "r") as file:
                messages = json.load(file)
            
            for message_data in messages:
                decrypted_text = self.decrypt_message(message_data['text'])
                if decrypted_text is None:  # Skip messages with decryption errors
                    continue
                is_dm = message_data.get('recipient') is not None
                
                # Use the formatted display with markdown support
                self.display_formatted_message(
                    message_data['user'], 
                    decrypted_text, 
                    message_data.get('time'), 
                    is_dm
                )
            
            # Re-encrypt messages with the current key
            self.reencrypt_messages(messages)
        except Exception as e:
            self.display_message("System", f"Error loading messages: {str(e)}")
    
    def flash_taskbar(self):
        """Flash the window in the taskbar to notify user of new messages"""
        if self.root.winfo_viewable() and not self.root.focus_get():
            try:
                import ctypes
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                ctypes.windll.user32.FlashWindow(hwnd, True)
            except Exception:
                # Fallback to simple beep if flashing fails
                import winsound
                winsound.Beep(1000, 200)
    
    def handle_enter(self, event):
        """Handle Enter key (send message)"""
        self.send_message()
        return 'break'  # Prevent default behavior (newline)

    def handle_shift_enter(self, event):
        """Handle Shift+Enter key (insert newline)"""
        self.message_input.insert("insert", "\n")
        return 'break'  # Prevent default behavior
    
    def send_message(self, event=None):
        """Updated to support multiline messages"""
        message = self.message_input.get("1.0", "end-1c").strip()
        if message and self.sio.connected:
            if message.startswith("/"):
                self.handle_command(message)
            else:
                encrypted_message = self.encrypt_message(message)
                timestamp = datetime.now().strftime("%H:%M")
                
                if self.current_chat == "Global":
                    # Send global message
                    self.sio.emit('message', {"text": encrypted_message, "time": timestamp})
                else:
                    # Send private message to the selected user
                    self.sio.emit('message', {"text": encrypted_message, "recipient": self.current_chat, "time": timestamp})
            
            self.message_input.delete("1.0", "end")  # Clear the textbox
    
    def handle_command(self, command):
        """Handle client-side commands."""
        if command == "/help":
            self.display_help()
        elif command == "/markdown":
            # Show markdown examples
            examples = """
**Markdown Examples**

1. Bold: `**bold text**` or `__bold text__`
2. Italic: `*italic text*` or `_italic text_`
3. Inline Code: `code`
4. Links: `[text](https://example.com)`
5. Code Blocks:
```python
print('Hello World!')
```
6. Spoilers: `||spoiler text||`
"""
            self.display_message("System", examples)
            return

        elif command == "/clear":
            self.clear_chat()
        elif command.startswith("/echo "):
            self.echo_message(command[6:])
        else:
            self.display_message("System", f"Unknown command: {command}")
    
    def display_help(self):
        """Display a list of client-side commands."""
        help_text = """
        Client-Side Commands:
        /help - Show this help message
        /clear - Clear the chat display
        /echo <message> - Echo a message locally
        """
        self.display_message("System", help_text)
    
    def clear_chat(self):
        """Clear the chat display."""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def echo_message(self, message):
        """Echo a message locally without sending it to the server."""
        self.display_message("You (Echo)", message)
    
    def disconnect(self):
        if self.sio.connected:
            self.sio.disconnect()
    
    def on_closing(self):
        self.disconnect()
        self.root.destroy()
    
    def save_message(self, message_data):
        """Save a message to the JSON file."""
        if not os.path.exists(self.messages_file):
            with open(self.messages_file, "w") as file:
                json.dump([], file)
        
        with open(self.messages_file, "r") as file:
            messages = json.load(file)
        
        messages.append(message_data)
        
        with open(self.messages_file, "w") as file:
            json.dump(messages, file)
    
    def reencrypt_messages(self, messages):
        """Re-encrypt messages with the current encryption key."""
        try:
            reencrypted_messages = []
            for message_data in messages:
                decrypted_text = self.decrypt_message(message_data['text'])
                if decrypted_text is None:  # Skip messages with decryption errors
                    continue
                reencrypted_text = self.encrypt_message(decrypted_text)
                message_data['text'] = reencrypted_text
                reencrypted_messages.append(message_data)
            
            with open(self.messages_file, "w") as file:
                json.dump(reencrypted_messages, file)
        except Exception as e:
            self.display_message("System", f"Error re-encrypting messages: {str(e)}")
    
    def on_spoiler_hover(self, event):
        # Get the index under the cursor
        index = self.chat_display.index(f"@%d,%d" % (event.x, event.y))
        
        # Get tags at this position
        tags = self.chat_display.tag_names(index)
        
        if 'spoiler' in tags:
            # Find which spoiler range contains this index
            for start, end in self.spoiler_ranges:
                if self.chat_display.compare(start, '<=', index) and self.chat_display.compare(index, '<', end):
                    # Reveal this spoiler
                    self.chat_display.tag_add("spoiler_revealed", start, end)
                    self.chat_display.tag_raise("spoiler_revealed", "spoiler")
                    return

    def on_spoiler_leave(self, event):
        # Remove all revealed spoilers
        self.chat_display.tag_remove("spoiler_revealed", "1.0", "end")

if __name__ == "__main__":
    SERVER_URL = "http://31.6.1.223:6969/"
    client = ChatClient(SERVER_URL)
    client.start()