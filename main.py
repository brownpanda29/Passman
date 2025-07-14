# === main.py ===
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from login_screen import LoginScreen
from vault_screen import VaultScreen

class SecurePassApp(App):
    def build(self):
        # Load the KV files
        Builder.load_file('login.kv')
        Builder.load_file('vault.kv')
        
        # Create screen manager
        sm = ScreenManager()
        
        # Add screens
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(VaultScreen(name='vault'))
        
        return sm

if __name__ == '__main__':
    SecurePassApp().run()

