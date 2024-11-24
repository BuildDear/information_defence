import tkinter as tk
from tkinter import filedialog, messagebox
from all_labs.logic.lab4 import RSAEncryption


class Lab4App:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA")
        self.root.geometry("1000x700")  # Збільшений розмір вікна
        self.root.configure(bg="#FFDAB9")  # Теплий фон вікна
        self.root.resizable(False, False)

        self.rsa = RSAEncryption()

        self.saved_private_key = None
        self.saved_public_key = None

        self.setup_ui()

    def setup_ui(self):
        # Заголовок програми
        title_label = tk.Label(
            self.root,
            text="RSA Tool",
            font=("Arial", 16, "bold"),
            bg="#FFDAB9",
            fg="#8B4513"
        )
        title_label.pack(pady=70)

        self.create_key_buttons()

        self.create_encryption_buttons()

        self.create_comparison_button()

    def create_key_buttons(self):
        # Кнопки для роботи з ключами
        self.generate_key_button = tk.Button(
            self.root,
            text="Generate Keys",
            command=self.generate_keys,
            bg="#FFA07A",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.generate_key_button.pack(fill="x", padx=300, pady=5)

        self.load_public_key_button = tk.Button(
            self.root,
            text="Load Public Key",
            command=self.load_public_key,
            bg="#FF7F50",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.load_public_key_button.pack(fill="x", padx=280, pady=5)

        self.load_private_key_button = tk.Button(
            self.root,
            text="Load Private Key",
            command=self.load_private_key,
            bg="#FF6347",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.load_private_key_button.pack(fill="x", padx=260, pady=5)

    def create_encryption_buttons(self):
        # Кнопки для шифрування та дешифрування
        self.encrypt_button = tk.Button(
            self.root,
            text="Encrypt",
            command=self.encrypt,
            bg="#CD5C5C",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.encrypt_button.pack(fill="x", padx=240, pady=5)

        self.decrypt_button = tk.Button(
            self.root,
            text="Decrypt",
            command=self.decrypt,
            bg="#F08080",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.decrypt_button.pack(fill="x", padx=220, pady=5)

    def create_comparison_button(self):
        # Кнопка для порівняння алгоритмів RSA і RC5
        self.compare_button = tk.Button(
            self.root,
            text="Compare RSA vs RC5",
            command=self.compare_rsa_vs_rc5,
            bg="#FFA07A",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.compare_button.pack(fill="x", padx=200, pady=5)

    def generate_keys(self):
        self.rsa.generate_keys()
        save_path = self.ask_save_filename("Save Private Key", ".pem")
        if save_path:
            self.rsa.save_keys(save_path, save_path.replace(".pem", "_pub.pem"))
            self.saved_private_key = save_path
            self.saved_public_key = save_path.replace(".pem", "_pub.pem")
            self.show_info("Success", "Keys generated and saved!")

    def load_public_key(self):
        pub_path = self.ask_open_filename("Select Public Key")
        if pub_path:
            self.rsa.load_public_key(pub_path)
            self.saved_public_key = pub_path
            self.show_info("Success", "Public Key Loaded")

    def load_private_key(self):
        priv_path = self.ask_open_filename("Select Private Key")
        if priv_path:
            self.rsa.load_private_key(priv_path)
            self.saved_private_key = priv_path
            self.show_info("Success", "Private Key Loaded")

    def encrypt(self):
        import os
        if not self.saved_public_key:
            messagebox.showerror("Error", "Please load the public key first.")
            return
        plaintext_path = self.ask_open_filename("Select File to Encrypt")
        if plaintext_path:
            with open(plaintext_path, 'rb') as file:
                data = file.read()

            file_extension = os.path.splitext(plaintext_path)[1].encode()
            encrypted_data = self.rsa.encrypt(file_extension + b'::' + data)

            save_path = self.ask_save_filename("Save Encrypted File", ".enc")
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)
                self.show_info("Success", "File Encrypted")

    def decrypt(self):
        if not self.saved_private_key:
            messagebox.showerror("Error", "Please load the private key first.")
            return
        ciphertext_path = self.ask_open_filename("Select File to Decrypt")
        if ciphertext_path:
            with open(ciphertext_path, 'rb') as file:
                data = file.read()

            decrypted_data = self.rsa.decrypt(data)

            extension, actual_data = decrypted_data.split(b'::', 1)
            extension = extension.decode()

            save_path = self.ask_save_filename("Save Decrypted File", extension)
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(actual_data)
                self.show_info("Success", f"File Decrypted and saved as {save_path}")

    def compare_rsa_vs_rc5(self):
        file_path = self.ask_open_filename("Select File for Comparison")
        if file_path:
            comparison = self.rsa.test_rsa_vs_rc5(file_path)

            comparison_results = (
                f"RSA Encryption Time: {comparison['RSA Encryption Time']:.6f} s\n"
                f"RSA Decryption Time: {comparison['RSA Decryption Time']:.6f} s\n"
                f"RC5 Encryption Time: {comparison['RC5 Encryption Time']:.6f} s\n"
                f"RC5 Decryption Time: {comparison['RC5 Decryption Time']:.6f} s\n\n"
                f"RSA faster in Encryption: {comparison['RSA faster in Encryption']}\n"
                f"RSA faster in Decryption: {comparison['RSA faster in Decryption']}"
            )
            self.show_info("Comparison Results", comparison_results)

    def ask_open_filename(self, title):
        return filedialog.askopenfilename(title=title)

    def ask_save_filename(self, title, def_extension):
        return filedialog.asksaveasfilename(title=title, defaultextension=def_extension)

    def show_info(self, title, message):
        messagebox.showinfo(title, message)


if __name__ == "__main__":
    root = tk.Tk()
    app = Lab4App(root)
    root.mainloop()
