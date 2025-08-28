import discord
import asyncio
import os
import json
from cryptography.fernet import Fernet
import keyring
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, Toplevel, Listbox, Scrollbar, Frame, Label, Entry, Button
import threading
import pystray
from PIL import Image, ImageDraw
import requests
from queue import Queue


APP_NAME = "FakeNitro"
KEYRING_SERVICE = APP_NAME
APPDATA_PATH = os.path.join(os.getenv('APPDATA'), APP_NAME)
TOKEN_FILE_PATH = os.path.join(APPDATA_PATH, 'token.dat')
EMOJI_FILE_PATH = os.path.join(APPDATA_PATH, 'emojis.json')
os.makedirs(APPDATA_PATH, exist_ok=True)

def get_encryption_key():
    key = keyring.get_password(KEYRING_SERVICE, "encryption_key")
    if key is None:
        key = Fernet.generate_key().decode('utf-8')
        keyring.set_password(KEYRING_SERVICE, "encryption_key", key)
    return key.encode('utf-8')

def encrypt_token(token, key):
    f = Fernet(key)
    return f.encrypt(token.encode('utf-8'))

def decrypt_token(encrypted_token, key):
    f = Fernet(key)
    return f.decrypt(encrypted_token).decode('utf-8')

def save_token(token):
    try:
        key = get_encryption_key()
        encrypted_token = encrypt_token(token, key)
        with open(TOKEN_FILE_PATH, 'wb') as f:
            f.write(encrypted_token)
        return True
    except Exception as e:
        print(f"[ERROR] Could not save token: {e}")
        return False

def load_token():
    try:
        if os.path.exists(TOKEN_FILE_PATH):
            with open(TOKEN_FILE_PATH, 'rb') as f:
                encrypted_token = f.read()
            key = get_encryption_key()
            return decrypt_token(encrypted_token, key)
    except Exception as e:
        print(f"[ERROR] Could not load or decrypt token: {e}")
    return None


def load_emoji_database():
    global EMOJI_CONFIG
    try:
        with open(EMOJI_FILE_PATH, 'r') as f:
            data = json.load(f)
            EMOJI_CONFIG = data.pop('__config__', {'prefix': '~'})
            if 'prefix' not in EMOJI_CONFIG:
                EMOJI_CONFIG['prefix'] = '~'
            return data
    except FileNotFoundError:
        print(f"[INFO] emojis.json not found at {EMOJI_FILE_PATH}. Creating a new one.")
        EMOJI_CONFIG = {'prefix': '~'}
        save_emoji_database()
        return {}
    except json.JSONDecodeError:
        print("[ERROR] emojis.json is not formatted correctly! Please check the syntax.")
        exit()

def save_emoji_database():
    try:
        full_data = EMOJI_DATABASE.copy()
        full_data['__config__'] = EMOJI_CONFIG
        with open(EMOJI_FILE_PATH, 'w') as f:
            json.dump(full_data, f, indent=4, sort_keys=True)
        return True
    except Exception as e:
        print(f"[ERROR] Could not save to emojis.json: {e}")
        return False

EMOJI_CONFIG = {}
EMOJI_DATABASE = load_emoji_database()


def get_token_from_credentials(email, password, two_fa_callback):
    """
    Logs into Discord via direct API call to fetch the auth token.
    Handles 2FA by using a callback to prompt the user.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
        "Content-Type": "application/json",
        "Referer": "https://discord.com/login"
    })

    login_payload = {
        "login": email,
        "password": password,
        "undelete": False,
        "captcha_key": None,
        "login_source": None,
        "gift_code_sku_id": None
    }

    try:
        response = session.post("https://discord.com/api/v9/auth/login", json=login_payload)
        response_data = response.json()

        if response.status_code == 200 and 'token' in response_data:
            return response_data['token'], "Login successful."
        
        elif response.status_code == 200 and response_data.get('mfa') is True:
            ticket = response_data['ticket']
            code = two_fa_callback()
            if not code:
                return None, "2FA cancelled by user."

            mfa_payload = {
                "code": code,
                "ticket": ticket,
                "login_source": None,
                "gift_code_sku_id": None
            }
            mfa_response = session.post("https://discord.com/api/v9/auth/mfa/totp", json=mfa_payload)
            mfa_data = mfa_response.json()
            
            if mfa_response.status_code == 200 and 'token' in mfa_data:
                return mfa_data['token'], "Login successful with 2FA."
            else:
                error_message = mfa_data.get('message', 'Unknown 2FA error.')
                return None, f"2FA Failed: {error_message}"

        else:
            errors = response_data.get('errors', {})
            error_message = " | ".join([f"{k}: {' '.join(v['_errors'][0].values())}" for k, v in errors.items()])
            if not error_message:
                error_message = response_data.get('message', 'Invalid credentials or unknown login error.')
            return None, error_message

    except requests.exceptions.RequestException as e:
        return None, f"A network error occurred: {e}"
    except Exception as e:
        return None, f"An unexpected error occurred during login: {e}"


class DiscordBot(discord.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gui = None

    async def on_ready(self):
        self.log(f'Logged in as {self.user.name} ({self.user.id})')
        self.log(f'Loaded {len(EMOJI_DATABASE)} custom emoji URLs.')
        self.log(f'Trigger prefix is: {EMOJI_CONFIG.get("prefix", "~")}')
        self.log('URL embed script is active. Listening for your messages...')
        self.log('----------------------------------------------------')
        self.log('Commands:')
        self.log(f'  - @Yourself add <URL> <{EMOJI_CONFIG.get("prefix", "~")}trigger>')
        self.log('  - @Yourself list [page_number]')
        self.log('----------------------------------------------------')

    def log(self, message):
        if self.gui:
            self.gui.log_message(message)
        print(message)

    async def on_message(self, message):
        if message.author.id != self.user.id:
            return

        content = message.content
        mention_standard = f'<@{self.user.id}>'
        mention_nickname = f'<@!{self.user.id}>'

        if content.startswith(f'{mention_standard} add ') or content.startswith(f'{mention_nickname} add '):
            await self.handle_add_emoji(message)
            return
        elif content.startswith(f'{mention_standard} list') or content.startswith(f'{mention_nickname} list'):
            await self.handle_list_emojis(message)
            return

        if message.content.startswith("**Custom Emojis"):
            return

        content_to_scan = message.content
        replacements = []
        sorted_triggers = sorted(EMOJI_DATABASE.keys(), key=len, reverse=True)

        for trigger in sorted_triggers:
            while trigger in content_to_scan:
                replacements.append((trigger, EMOJI_DATABASE[trigger]))
                content_to_scan = content_to_scan.replace(trigger, "", 1)

        if not replacements:
            return

        text_parts = message.content
        urls_to_post = []
        for trigger, url in replacements:
            text_parts = text_parts.replace(trigger, '', 1)
            urls_to_post.append(url)

        final_content = ' '.join(text_parts.split())

        if final_content:
            final_content += '\n' + '\n'.join(urls_to_post)
        else:
            final_content = '\n'.join(urls_to_post)

        final_content = final_content.strip()

        if final_content == message.content:
            return

        try:
            await asyncio.sleep(0.1)
            await message.edit(content=final_content)
        except (discord.errors.Forbidden, discord.errors.HTTPException):
            try:
                await message.channel.send(content=final_content, reference=message.reference)
                await message.delete()
            except discord.errors.Forbidden:
                self.log(f"Could not delete original or send new message in #{message.channel}. Missing permissions.")
            except Exception as fallback_e:
                self.log(f"An error occurred during fallback delete/resend: {fallback_e}")
        except Exception as e:
            self.log(f"An unexpected error occurred while editing: {e}")

    async def handle_add_emoji(self, message):
        try:
            content = message.content
            prefix = EMOJI_CONFIG.get('prefix', '~')
            prefix_standard = f'<@{self.user.id}> add '
            prefix_nickname = f'<@!{self.user.id}> add '

            if content.startswith(prefix_standard):
                args_string = content[len(prefix_standard):]
            elif content.startswith(prefix_nickname):
                args_string = content[len(prefix_nickname):]
            else:
                return

            args = args_string.split()

            if len(args) != 2:
                await message.channel.send(f"Invalid format. Use: `@me add <url> <trigger>`", delete_after=10)
                return

            url, trigger = args[0], args[1]
            if not trigger.startswith(prefix):
                await message.channel.send(f"Invalid trigger format. Must start with `{prefix}`.", delete_after=10)
                return

            if not url.startswith('http'):
                await message.channel.send("Invalid URL format. Must start with `http` or `https`.", delete_after=10)
                return

            if trigger in EMOJI_DATABASE:
                await message.channel.send(f"⚠️ Overwriting existing trigger `{trigger}`.", delete_after=7)

            EMOJI_DATABASE[trigger] = url
            self.log(f"Added/updated emoji: {trigger} -> {url}")
            if save_emoji_database():
                await message.channel.send(f"✅ Added `{trigger}`.", delete_after=5)
            else:
                await message.channel.send(f"❌ Failed to save `{trigger}`.", delete_after=10)
        except Exception as e:
            self.log(f"Error handling add command: {e}")
        finally:
            await message.delete()

    async def handle_list_emojis(self, message):
        PAGE_SIZE = 20
        try:
            sorted_triggers = sorted(EMOJI_DATABASE.keys())
            total_emojis = len(sorted_triggers)
            if total_emojis == 0:
                await message.channel.send("You have no custom emojis saved.", delete_after=10)
                return

            total_pages = (total_emojis + PAGE_SIZE - 1) // PAGE_SIZE
            parts = message.content.split()
            page_number = 1
            if len(parts) > 2:
                try: page_number = int(parts[2])
                except ValueError: pass
            page_number = max(1, min(page_number, total_pages))
            
            start_index = (page_number - 1) * PAGE_SIZE
            end_index = start_index + PAGE_SIZE
            page_items = sorted_triggers[start_index:end_index]
            header = f"**Custom Emojis ({total_emojis}) — Page {page_number}/{total_pages}**"
            formatted_list = "\n".join(f"`{item}`" for item in page_items)
            final_message = f"{header}\n{formatted_list}"
            await message.channel.send(final_message, delete_after=60)
        except Exception as e:
            self.log(f"Error handling list command: {e}")
        finally:
            await message.delete()

class DatabaseManager:
    def __init__(self, master, app_instance):
        self.master = Toplevel(master)
        self.master.title("Emoji Database Manager")
        self.master.geometry("700x500")
        self.app = app_instance
        
        left_frame = Frame(self.master, padx=5, pady=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        Label(left_frame, text="Triggers").pack()
        list_frame = Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        scrollbar = Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.emoji_listbox = Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.emoji_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.emoji_listbox.bind("<<ListboxSelect>>", self.on_list_select)
        scrollbar.config(command=self.emoji_listbox.yview)

        right_frame = Frame(self.master, padx=10, pady=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        details_frame = tk.LabelFrame(right_frame, text="Emoji Details", padx=5, pady=5)
        details_frame.pack(fill=tk.X, pady=5)
        Label(details_frame, text="Trigger:", anchor='w').pack(fill=tk.X)
        self.trigger_entry = Entry(details_frame)
        self.trigger_entry.pack(fill=tk.X, pady=(0, 5))
        Label(details_frame, text="URL:", anchor='w').pack(fill=tk.X)
        self.url_entry = Entry(details_frame)
        self.url_entry.pack(fill=tk.X)

        actions_frame = tk.LabelFrame(right_frame, text="Actions", padx=5, pady=5)
        actions_frame.pack(fill=tk.X, pady=5)
        Button(actions_frame, text="Save as New", command=self.add_new).pack(fill=tk.X, pady=2)
        Button(actions_frame, text="Update Selected", command=self.update_selected).pack(fill=tk.X, pady=2)
        Button(actions_frame, text="Delete Selected", command=self.delete_selected).pack(fill=tk.X, pady=2)

        config_frame = tk.LabelFrame(right_frame, text="Configuration", padx=5, pady=5)
        config_frame.pack(fill=tk.X, pady=5)
        Label(config_frame, text="Trigger Prefix:", anchor='w').pack(fill=tk.X)
        self.prefix_entry = Entry(config_frame, width=10)
        self.prefix_entry.pack(fill=tk.X, pady=(0, 5))
        self.prefix_entry.insert(0, EMOJI_CONFIG.get('prefix', '~'))
        Button(config_frame, text="Save Prefix", command=self.save_prefix).pack(fill=tk.X, pady=2)

        self.populate_list()

    def populate_list(self):
        self.emoji_listbox.delete(0, tk.END)
        for trigger in sorted(EMOJI_DATABASE.keys()):
            self.emoji_listbox.insert(tk.END, trigger)
        self.clear_entries()

    def on_list_select(self, event=None):
        selection = self.emoji_listbox.curselection()
        if not selection:
            return
        
        trigger = self.emoji_listbox.get(selection[0])
        url = EMOJI_DATABASE.get(trigger, "")

        self.trigger_entry.delete(0, tk.END)
        self.trigger_entry.insert(0, trigger)
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)

    def clear_entries(self):
        self.trigger_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        self.emoji_listbox.selection_clear(0, tk.END)

    def add_new(self):
        trigger = self.trigger_entry.get().strip()
        url = self.url_entry.get().strip()
        prefix = EMOJI_CONFIG.get('prefix', '~')

        if not trigger or not url:
            messagebox.showerror("Error", "Trigger and URL cannot be empty.")
            return
        if not trigger.startswith(prefix):
            messagebox.showerror("Error", f"Trigger must start with the prefix '{prefix}'.")
            return
        if trigger in EMOJI_DATABASE:
            if not messagebox.askyesno("Confirm", f"Trigger '{trigger}' already exists. Overwrite it?"):
                return
        
        EMOJI_DATABASE[trigger] = url
        if save_emoji_database():
            self.app.log_message(f"[DB] Added: {trigger}")
            self.populate_list()
        else:
            messagebox.showerror("Error", "Failed to save the database file.")

    def update_selected(self):
        selection = self.emoji_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No trigger selected to update.")
            return

        original_trigger = self.emoji_listbox.get(selection[0])
        new_trigger = self.trigger_entry.get().strip()
        new_url = self.url_entry.get().strip()
        prefix = EMOJI_CONFIG.get('prefix', '~')

        if not new_trigger or not new_url:
            messagebox.showerror("Error", "Trigger and URL cannot be empty.")
            return
        if not new_trigger.startswith(prefix):
            messagebox.showerror("Error", f"Trigger must start with the prefix '{prefix}'.")
            return

        if original_trigger != new_trigger:
            del EMOJI_DATABASE[original_trigger]
        
        EMOJI_DATABASE[new_trigger] = new_url
        if save_emoji_database():
            self.app.log_message(f"[DB] Updated: {new_trigger}")
            self.populate_list()
        else:
            del EMOJI_DATABASE[new_trigger]
            EMOJI_DATABASE[original_trigger] = self.url_entry.get().strip()
            messagebox.showerror("Error", "Failed to save the database file.")

    def delete_selected(self):
        selection = self.emoji_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No trigger selected to delete.")
            return
        
        trigger = self.emoji_listbox.get(selection[0])
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete '{trigger}'?"):
            del EMOJI_DATABASE[trigger]
            if save_emoji_database():
                self.app.log_message(f"[DB] Deleted: {trigger}")
                self.populate_list()
            else:
                messagebox.showerror("Error", "Failed to save the database file.")
    
    def save_prefix(self):
        new_prefix = self.prefix_entry.get().strip()
        if not new_prefix:
            messagebox.showerror("Error", "Prefix cannot be empty.")
            return
        
        EMOJI_CONFIG['prefix'] = new_prefix
        if save_emoji_database():
            self.app.log_message(f"[CONFIG] Prefix changed to: {new_prefix}")
            messagebox.showinfo("Success", f"Prefix successfully changed to '{new_prefix}'.")
        else:
            messagebox.showerror("Error", "Failed to save the configuration.")



class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Discord Bot Control")
        self.root.geometry("600x450")
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)

        self.bot_thread = None
        self.bot = None
        self.loop = None
        self.tray_icon = None
        self.db_manager_window = None

        login_frame = tk.LabelFrame(root, text="Login Credentials")
        login_frame.pack(pady=10, padx=10, fill='x')
        token_row = tk.Frame(login_frame)
        token_row.pack(fill='x', pady=2, padx=5)
        tk.Label(token_row, text="Discord Token:", width=15, anchor='w').pack(side=tk.LEFT)
        self.token_entry = tk.Entry(token_row, width=50, show="*")
        self.token_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        stored_token = load_token()
        if stored_token:
            self.token_entry.insert(0, stored_token)

        tk.Label(login_frame, text="--- OR (To fetch a new token) ---").pack(pady=(5, 0))
        email_row = tk.Frame(login_frame)
        email_row.pack(fill='x', pady=2, padx=5)
        tk.Label(email_row, text="Email:", width=15, anchor='w').pack(side=tk.LEFT)
        self.email_entry = tk.Entry(email_row, width=50)
        self.email_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        password_row = tk.Frame(login_frame)
        password_row.pack(fill='x', pady=2, padx=5)
        tk.Label(password_row, text="Password:", width=15, anchor='w').pack(side=tk.LEFT)
        self.password_entry = tk.Entry(password_row, width=50, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5, fill='x', expand=True)

        control_frame = tk.Frame(root)
        control_frame.pack(pady=5)
        self.start_button = tk.Button(control_frame, text="Start Bot", command=self.start_bot_thread)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(control_frame, text="Stop Bot", command=self.stop_bot, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.db_button = tk.Button(control_frame, text="Manage Database", command=self.open_database_manager)
        self.db_button.pack(side=tk.LEFT, padx=5)

        log_frame = tk.LabelFrame(root, text="Logs")
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', wrap=tk.WORD, bg='black', fg='lightgrey')
        self.log_text.pack(fill="both", expand=True)

    def open_database_manager(self):
        if self.db_manager_window and self.db_manager_window.winfo_exists():
            self.db_manager_window.lift()
        else:
            self.db_manager_window = DatabaseManager(self.root, self)

    def log_message(self, message):
        self.root.after(0, self._log_message, message)

    def _log_message(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.config(state='disabled')
        self.log_text.see(tk.END)

    def prompt_2fa(self):
        q = Queue()
        self.root.after(0, lambda: q.put(simpledialog.askstring("2FA Required", "Enter your 2-Factor Authentication code:", parent=self.root)))
        return q.get()

    def start_bot_thread(self):
        if self.bot_thread and self.bot_thread.is_alive():
            self.log_message("[INFO] Bot is already running.")
            return
        threading.Thread(target=self.start_bot_logic, daemon=True).start()

    def start_bot_logic(self):
        token = self.token_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        if not token and (email and password):
            self.log_message("[INFO] No token found. Attempting to log in with credentials...")
            new_token, message = get_token_from_credentials(email, password, self.prompt_2fa)
            if new_token:
                self.log_message(f"[SUCCESS] {message}")
                token = new_token
                self.root.after(0, lambda: self.token_entry.delete(0, tk.END))
                self.root.after(0, lambda: self.token_entry.insert(0, token))
            else:
                self.log_message(f"[ERROR] Failed to fetch token: {message}")
                return

        if not token:
            self.log_message("[ERROR] No token available. Please provide a token or credentials.")
            return
        
        if save_token(token): self.log_message("[INFO] Token has been securely saved.")
        else: self.log_message("[ERROR] Could not save the token securely.")

        self.root.after(0, self.set_gui_running)
        self.loop = asyncio.new_event_loop()
        self.bot_thread = threading.Thread(target=self.run_bot, args=(token,), daemon=True)
        self.bot_thread.start()

    def set_gui_running(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.token_entry.config(state=tk.DISABLED)
        self.email_entry.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)

    def run_bot(self, token):
        asyncio.set_event_loop(self.loop)
        intents = discord.Intents.default()
        intents.messages = True
        self.bot = DiscordBot(intents=intents)
        self.bot.gui = self
        try:
            self.bot.run(token, bot=False)
        except discord.errors.LoginFailure:
            self.log_message("[FATAL] Login failed. The provided token is invalid.")
        except Exception as e:
            self.log_message(f"[ERROR] An unexpected error occurred: {e}")
        finally:
            self.log_message("[INFO] Bot has disconnected.")
            self.root.after(0, self.bot_stopped)

    def stop_bot(self):
        if self.bot and self.loop and not self.bot.is_closed():
            self.log_message("[INFO] Stopping the bot...")
            asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop)
        else:
            self.log_message("[INFO] Bot is not running or already stopping.")

    def bot_stopped(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.token_entry.config(state=tk.NORMAL)
        self.email_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
        self.log_message("[INFO] Bot is stopped. Ready to start again.")
        self.bot_thread = None
        self.bot = None
        self.loop = None

    def hide_window(self):
        self.root.withdraw()
        image = create_image()
        menu = (pystray.MenuItem('Show', self.show_window, default=True), pystray.MenuItem('Quit', self.quit_window))
        self.tray_icon = pystray.Icon("DiscordEmojiBot", image, "Discord Emoji Bot", menu)
        self.tray_icon.run()

    def show_window(self, icon, item):
        icon.stop()
        self.root.after(0, self.root.deiconify)

    def quit_window(self, icon, item):
        self.log_message("[INFO] Quit command received. Shutting down.")
        if icon:
            icon.stop()
        
        if self.bot and self.loop and not self.bot.is_closed():
            asyncio.run_coroutine_threadsafe(self.bot.close(), self.loop)
        
        if self.bot_thread:
            self.bot_thread.join(timeout=5.0)
        
        self.root.after(0, self.root.destroy)

def create_image():
    width, height, color1, color2 = 64, 64, "black", "white"
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 2, 0, width, height // 2), fill=color2)
    dc.rectangle((0, height // 2, width // 2, height), fill=color2)
    return image

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
