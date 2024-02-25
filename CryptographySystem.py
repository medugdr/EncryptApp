import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QIcon, QPalette, QColor
from cryptography.fernet import Fernet

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/Decryption System")
        self.setGeometry(100, 100, 400, 200)
        
        # Other initialization code...

        layout = QVBoxLayout()

        # Set background color
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor("#212121"))
        self.setPalette(palette)

        # Title label
        title_label = QLabel("Encryption/Decryption System")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        # Message input
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Enter the message")
        self.message_input.setStyleSheet("border-radius: 5px; background-color: white; color: black;")
        layout.addWidget(self.message_input)

        # Key input
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter the encryption key")
        self.key_input.setStyleSheet("border-radius: 5px; background-color: white; color: black;")
        layout.addWidget(self.key_input)

        # Encrypt button
        encrypt_button = QPushButton("Encrypt")
        encrypt_button.clicked.connect(self.encrypt_message)
        encrypt_button.setStyleSheet("border-radius: 5px; background-color: #6e6e6e; color: white;")
        layout.addWidget(encrypt_button)

        # Decrypt button
        decrypt_button = QPushButton("Decrypt")
        decrypt_button.clicked.connect(self.decrypt_message)
        decrypt_button.setStyleSheet("border-radius: 5px; background-color: #6e6e6e; color: white;")
        layout.addWidget(decrypt_button)

        # Generate key button
        generate_key_button = QPushButton("Generate Key")
        generate_key_button.clicked.connect(self.generate_key)
        generate_key_button.setStyleSheet("border-radius: 5px; background-color: #6e6e6e; color: white;")
        layout.addWidget(generate_key_button)

        self.setLayout(layout)

        # Initialize key variable
        self.key = None

    def encrypt_message(self):
        message = self.message_input.text()
        key = self.key_input.text()

        if not message or not key:
            QMessageBox.warning(self, "Error", "Please enter a message and key.")
            return

        fernet = Fernet(key.encode())
        encrypted_message = fernet.encrypt(message.encode())

        msg_box = QMessageBox()
        msg_box.setWindowTitle("Encrypted Message")
        msg_box.setText(f"Encrypted message: {encrypted_message.decode()}")
        copy_button = msg_box.addButton("Copy", QMessageBox.ActionRole)
        msg_box.exec_()

        if msg_box.clickedButton() == copy_button:
            clipboard = QApplication.clipboard()
            clipboard.setText(encrypted_message.decode())

    def decrypt_message(self):
        encrypted_message = self.message_input.text()
        key = self.key_input.text()

        if not encrypted_message or not key:
            QMessageBox.warning(self, "Error", "Please enter an encrypted message and key.")
            return

        fernet = Fernet(key.encode())
        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()

        msg_box = QMessageBox()
        msg_box.setWindowTitle("Decrypted Message")
        msg_box.setText(f"Decrypted message: {decrypted_message}")
        copy_button = msg_box.addButton("Copy", QMessageBox.ActionRole)
        msg_box.exec_()

        if msg_box.clickedButton() == copy_button:
            clipboard = QApplication.clipboard()
            clipboard.setText(decrypted_message)

    def generate_key(self):
        key = Fernet.generate_key()
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Generated Key")
        msg_box.setText(f"Generated key: {key.decode()}")
        copy_button = msg_box.addButton("Copy", QMessageBox.ActionRole)
        msg_box.exec_()
        if msg_box.clickedButton() == copy_button:
            clipboard = QApplication.clipboard()
            clipboard.setText(key.decode())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_())