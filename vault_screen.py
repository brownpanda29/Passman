from kivy.uix.screenmanager import Screen
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from password_utils import generate_password, encrypt_data, decrypt_data, analyze_password_strength
import csv
import os
import json

class VaultScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vault_file = 'vault.enc'  # Changed to .enc for encrypted file
        self.passwords = []
        self.master_password = None  # Store master password for encryption
    
    def on_enter(self):
        """Called when screen is entered"""
        # Get master password from login screen
        login_screen = self.manager.get_screen('login')
        self.master_password = login_screen.last_password
        self.load_passwords()
    
    def generate_password_action(self):
        """Generate a random password and fill the password field"""
        new_password = generate_password()
        self.ids.password_input.text = new_password
    
    def save_password(self):
        """Save password to encrypted file"""
        site = self.ids.site_input.text.strip()
        username = self.ids.username_input.text.strip()
        password = self.ids.password_input.text.strip()
        
        if not site or not username or not password:
            self.show_popup("Error", "Please fill in all fields")
            return
        
        # Analyze password strength
        strength_info = analyze_password_strength(password)
        
        # Show password analysis popup
        self.show_password_analysis(password, strength_info, site, username)
    
    def show_password_analysis(self, password, strength_info, site, username):
        """Show password strength analysis popup"""
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Title
        title_label = Label(text="Password Security Analysis", font_size=16, bold=True, size_hint_y=None, height=30)
        content.add_widget(title_label)
        
        # Strength indicator
        strength_color = strength_info['color']
        strength_label = Label(
            text=f"Strength: {strength_info['strength']}", 
            color=strength_color + [1],
            font_size=14,
            bold=True,
            size_hint_y=None, 
            height=30
        )
        content.add_widget(strength_label)
        
        # Score
        score_label = Label(
            text=f"Security Score: {strength_info['score']}/100",
            size_hint_y=None,
            height=25
        )
        content.add_widget(score_label)
        
        # Crack time
        crack_label = Label(
            text=f"Estimated crack time: {strength_info['crack_time']}",
            size_hint_y=None,
            height=25,
            text_size=(350, None),
            halign='center'
        )
        content.add_widget(crack_label)
        
        # Issues
        if strength_info['issues']:
            issues_label = Label(
                text="Security Issues:",
                font_size=12,
                bold=True,
                size_hint_y=None,
                height=25
            )
            content.add_widget(issues_label)
            
            for issue in strength_info['issues']:
                issue_label = Label(
                    text=f"• {issue}",
                    font_size=11,
                    size_hint_y=None,
                    height=20,
                    text_size=(350, None),
                    halign='left'
                )
                content.add_widget(issue_label)
        
        # Recommendations
        if strength_info['recommendations']:
            rec_label = Label(
                text="Recommendations:",
                font_size=12,
                bold=True,
                size_hint_y=None,
                height=25
            )
            content.add_widget(rec_label)
            
            for rec in strength_info['recommendations']:
                rec_item = Label(
                    text=f"• {rec}",
                    font_size=11,
                    size_hint_y=None,
                    height=20,
                    text_size=(350, None),
                    halign='left'
                )
                content.add_widget(rec_item)
        
        # Buttons
        button_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint_y=None, height=50)
        
        save_anyway_btn = Button(text='Save Anyway', size_hint_x=0.5)
        save_anyway_btn.bind(on_press=lambda x: self.save_password_confirmed(site, username, password, popup))
        
        cancel_btn = Button(text='Cancel', size_hint_x=0.5)
        cancel_btn.bind(on_press=lambda x: popup.dismiss())
        
        button_layout.add_widget(save_anyway_btn)
        button_layout.add_widget(cancel_btn)
        content.add_widget(button_layout)
        
        popup = Popup(title='Password Analysis', content=content, size_hint=(0.9, 0.8))
        popup.open()
    
    def save_password_confirmed(self, site, username, password, popup):
        """Save password after confirmation"""
        popup.dismiss()
        
        # Add new password to list
        new_entry = {
            'site': site,
            'username': username,
            'password': password
        }
        self.passwords.append(new_entry)
        
        # Save encrypted data
        try:
            self.save_encrypted_passwords()
        except Exception as e:
            self.show_popup("Error", f"Failed to save password: {str(e)}")
            self.passwords.pop()  # Remove the entry if save failed
            return
        
        # Clear input fields
        self.ids.site_input.text = ""
        self.ids.username_input.text = ""
        self.ids.password_input.text = ""
        
        # Update display
        self.update_password_display()
        
        self.show_popup("Success", f"Password saved for {site}")
    
    def check_password_strength(self, password):
        """Check password strength and show analysis"""
        if not password:
            self.show_popup("Error", "Please enter a password to analyze")
            return
        
        strength_info = analyze_password_strength(password)
        self.show_password_strength_popup(strength_info)
    
    def show_password_strength_popup(self, strength_info):
        """Show password strength analysis in popup"""
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Title
        title_label = Label(text="Password Strength Analysis", font_size=16, bold=True, size_hint_y=None, height=30)
        content.add_widget(title_label)
        
        # Strength indicator
        strength_color = strength_info['color']
        strength_label = Label(
            text=f"Strength: {strength_info['strength']}", 
            color=strength_color + [1],
            font_size=14,
            bold=True,
            size_hint_y=None, 
            height=30
        )
        content.add_widget(strength_label)
        
        # Score
        score_label = Label(
            text=f"Security Score: {strength_info['score']}/100",
            size_hint_y=None,
            height=25
        )
        content.add_widget(score_label)
        
        # Crack time
        crack_label = Label(
            text=f"Estimated crack time: {strength_info['crack_time']}",
            size_hint_y=None,
            height=25,
            text_size=(350, None),
            halign='center'
        )
        content.add_widget(crack_label)
        
        # Issues
        if strength_info['issues']:
            issues_label = Label(
                text="Security Issues:",
                font_size=12,
                bold=True,
                size_hint_y=None,
                height=25
            )
            content.add_widget(issues_label)
            
            for issue in strength_info['issues']:
                issue_label = Label(
                    text=f"• {issue}",
                    font_size=11,
                    size_hint_y=None,
                    height=20,
                    text_size=(350, None),
                    halign='left'
                )
                content.add_widget(issue_label)
        
        # Recommendations
        if strength_info['recommendations']:
            rec_label = Label(
                text="Recommendations:",
                font_size=12,
                bold=True,
                size_hint_y=None,
                height=25
            )
            content.add_widget(rec_label)
            
            for rec in strength_info['recommendations']:
                rec_item = Label(
                    text=f"• {rec}",
                    font_size=11,
                    size_hint_y=None,
                    height=20,
                    text_size=(350, None),
                    halign='left'
                )
                content.add_widget(rec_item)
        
        # Close button
        close_btn = Button(text='Close', size_hint_y=None, height=40)
        content.add_widget(close_btn)
        
        popup = Popup(title='Password Analysis', content=content, size_hint=(0.9, 0.8))
        close_btn.bind(on_press=popup.dismiss)
        popup.open()
    
    def load_passwords(self):
        """Load passwords from encrypted file and display them"""
        self.passwords = []
        
        if not os.path.exists(self.vault_file):
            self.update_password_display()
            return
        
        try:
            # Read encrypted data
            with open(self.vault_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decrypted_data = decrypt_data(encrypted_data, self.master_password)
            
            # Parse JSON data
            if decrypted_data:
                self.passwords = json.loads(decrypted_data)
                
        except Exception as e:
            self.show_popup("Error", f"Error loading passwords: {str(e)}")
            self.passwords = []
        
        self.update_password_display()
    
    def save_encrypted_passwords(self):
        """Save passwords to encrypted file"""
        if not self.passwords:
            # If no passwords, remove the file
            if os.path.exists(self.vault_file):
                os.remove(self.vault_file)
            return
        
        # Convert passwords to JSON
        json_data = json.dumps(self.passwords, indent=2)
        
        # Encrypt data
        encrypted_data = encrypt_data(json_data, self.master_password)
        
        # Save encrypted data
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted_data)
    
    def update_password_display(self):
        """Update the password display list"""
        # Clear existing items
        self.ids.password_list.clear_widgets()
        
        if not self.passwords:
            no_data_label = Label(text="No passwords saved yet", size_hint_y=None, height=40)
            self.ids.password_list.add_widget(no_data_label)
            return
        
        # Add headers
        header_layout = GridLayout(cols=4, size_hint_y=None, height=40)
        header_layout.add_widget(Label(text="Site", bold=True))
        header_layout.add_widget(Label(text="Username", bold=True))
        header_layout.add_widget(Label(text="Password/Strength", bold=True))
        header_layout.add_widget(Label(text="Actions", bold=True))
        self.ids.password_list.add_widget(header_layout)
        
        # Add password entries
        for i, password_entry in enumerate(self.passwords):
            entry_layout = GridLayout(cols=4, size_hint_y=None, height=40)
            
            # Site
            entry_layout.add_widget(Label(text=password_entry['site'], text_size=(None, None)))
            
            # Username
            entry_layout.add_widget(Label(text=password_entry['username'], text_size=(None, None)))
            
            # Password (masked) with strength indicator
            password_layout = BoxLayout(orientation='horizontal')
            masked_password = '*' * len(password_entry['password'])
            password_layout.add_widget(Label(text=masked_password, text_size=(None, None), size_hint_x=0.7))
            
            # Add strength indicator
            strength_info = analyze_password_strength(password_entry['password'])
            strength_color = strength_info['color']
            strength_label = Label(
                text=strength_info['strength'][:4],  # Show first 4 chars (Weak, Good, Strong)
                color=strength_color + [1],
                size_hint_x=0.3,
                font_size=10
            )
            password_layout.add_widget(strength_label)
            entry_layout.add_widget(password_layout)
            
            # Actions
            action_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=40)
            
            show_btn = Button(text='Show', size_hint_x=0.33, size_hint_y=None, height=30)
            show_btn.bind(on_press=lambda x, pwd=password_entry['password']: self.show_password(pwd))
            action_layout.add_widget(show_btn)
            
            check_btn = Button(text='Check', size_hint_x=0.33, size_hint_y=None, height=30)
            check_btn.bind(on_press=lambda x, pwd=password_entry['password']: self.show_password_strength_popup(analyze_password_strength(pwd)))
            action_layout.add_widget(check_btn)
            
            delete_btn = Button(text='Delete', size_hint_x=0.34, size_hint_y=None, height=30)
            delete_btn.bind(on_press=lambda x, idx=i: self.delete_password(idx))
            action_layout.add_widget(delete_btn)
            
            entry_layout.add_widget(action_layout)
            self.ids.password_list.add_widget(entry_layout)
    
    def show_password(self, password):
        """Show password in popup"""
        self.show_popup("Password", f"Password: {password}")
    
    def delete_password(self, index):
        """Delete password entry"""
        if 0 <= index < len(self.passwords):
            site = self.passwords[index]['site']
            
            # Remove from list
            self.passwords.pop(index)
            
            # Save encrypted data
            try:
                self.save_encrypted_passwords()
            except Exception as e:
                self.show_popup("Error", f"Failed to delete password: {str(e)}")
                return
            
            # Update display
            self.update_password_display()
            
            self.show_popup("Success", f"Password for {site} deleted")
    
    def rewrite_csv(self):
        """Legacy method - now handled by save_encrypted_passwords"""
        self.save_encrypted_passwords()
    
    def logout(self):
        """Logout and return to login screen"""
        self.manager.current = 'login'
    
    def show_popup(self, title, message):
        """Show popup message"""
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        content.add_widget(Label(text=message, text_size=(300, None), halign='center'))
        
        button = Button(text='OK', size_hint=(1, 0.3))
        content.add_widget(button)
        
        popup = Popup(title=title, content=content, size_hint=(0.8, 0.4))
        button.bind(on_press=popup.dismiss)
        popup.open()

