"""
Komponen Antarmuka Pengguna Desktop (CustomTkinter).
"""

from client.ui.chat_window import ChatWindow
from client.ui.visualizer_panel import VisualizerPanel
from client.ui.key_dialog import IdentityDialog, AddContactDialog

__all__ = [
    "ChatWindow",
    "VisualizerPanel",
    "IdentityDialog",
    "AddContactDialog",
]
