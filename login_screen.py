from kivy.uix.screenmanager import Screen
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
import hashlib
import os

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.master_file = 'master.txt'
        self.last_password = None  # Store last entered password for encryption
    
    def on_enter(self):
        """Called when screen is entered"""
        # Clear the stored password when returning to login
        self.last_password = None
        # Check if master password exists
        if not os.path.exists(self.master_file):
            self.ids.title_label.text = "Set Master Password"
            self.ids.login_button.text = "Set Password"
            self.ids.password_input.hint_text = "Create your master password"
        else:
            self.ids.title_label.text = "Enter Master Password"
            self.ids.login_button.text = "Login"
            self.ids.password_input.hint_text = "Enter your master password"
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def set_master_password(self, password):
        """Set master password for first time"""
        if len(password) < 6:
            self.show_popup("Error", "Password must be at least 6 characters long")
            return False
        
        hashed_password = self.hash_password(password)
        with open(self.master_file, 'w') as f:
            f.write(hashed_password)
        return True
    
    def verify_master_password(self, password):
        """Verify master password"""
        if not os.path.exists(self.master_file):
            return False
        
        with open(self.master_file, 'r') as f:
            stored_hash = f.read().strip()
        
        return self.hash_password(password) == stored_hash
    
    def on_login_button_press(self):
        """Handle login button press"""
        password = self.ids.password_input.text
        
        if not password:
            self.show_popup("Error", "Please enter a password")
            return
        
        # Store password for encryption purposes
        self.last_password = password
        
        if not os.path.exists(self.master_file):
            # First time setup
            if self.set_master_password(password):
                self.show_popup("Success", "Master password set successfully!", self.go_to_vault)
        else:
            # Login
            if self.verify_master_password(password):
                self.go_to_vault()
            else:
                self.show_popup("Error", "Invalid master password")
                self.last_password = None  # Clear password if login failed
        
        # Clear password field
        self.ids.password_input.text = ""
    
    def go_to_vault(self):
        """Navigate to vault screen"""
        self.manager.current = 'vault'
        # Refresh vault screen
        vault_screen = self.manager.get_screen('vault')
        vault_screen.load_passwords()
    
    def show_popup(self, title, message, callback=None):
        """Show popup message"""
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        content.add_widget(Label(text=message, text_size=(300, None), halign='center'))
        
        button = Button(text='OK', size_hint=(1, 0.3))
        content.add_widget(button)
        
        popup = Popup(title=title, content=content, size_hint=(0.8, 0.4))
        
        def close_popup(instance):
            popup.dismiss()
            if callback:
                callback()
        
        button.bind(on_press=close_popup)
        popup.open()
