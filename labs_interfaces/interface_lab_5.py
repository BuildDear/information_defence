import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from all_labs.logic import lab5


class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DSS Digital Signature Tool")
        self.root.geometry("800x700")
        self.root.configure(bg="#FFDAB9")  # Світло-персиковий фон

        self.private_key_path = None
        self.public_key_path = None

        self.create_widgets()

    def create_widgets(self):
        # Title label
        tk.Label(
            self.root,
            text="Digital Signature Tool",
            font=("Arial", 16, "bold"),
            bg="#FFDAB9",
            fg="#8B4513",  # Темно-коричневий текст
        ).pack(pady=10)

        # Buttons with warm colors
        button_style = {
            "bg": "#FFA07A",  # Світло-помаранчевий фон кнопки
            "fg": "#8B0000",  # Темно-червоний текст
            "activebackground": "#FF7F50",  # Яскраво-помаранчевий при натисканні
            "activeforeground": "#FFFFFF",  # Білий текст при натисканні
            "width": 20,
            "font": ("Arial", 10),
        }

        self.generate_key_btn = tk.Button(
            self.root, text="Generate Keys", command=self.generate_keys, **button_style
        )
        self.generate_key_btn.pack(pady=5)

        self.load_private_key_btn = tk.Button(
            self.root, text="Load Private Key", command=self.load_private_key, **button_style
        )
        self.load_private_key_btn.pack(pady=5)

        self.load_public_key_btn = tk.Button(
            self.root, text="Load Public Key", command=self.load_public_key, **button_style
        )
        self.load_public_key_btn.pack(pady=5)

        self.sign_text_btn = tk.Button(
            self.root, text="Sign Text", command=self.sign_text, **button_style
        )
        self.sign_text_btn.pack(pady=5)

        self.verify_text_btn = tk.Button(
            self.root,
            text="Verify Text Signature",
            command=self.verify_text_signature,
            **button_style,
        )
        self.verify_text_btn.pack(pady=5)

        self.sign_file_btn = tk.Button(
            self.root, text="Sign File", command=self.sign_file, **button_style
        )
        self.sign_file_btn.pack(pady=5)

        self.verify_file_btn = tk.Button(
            self.root, text="Verify File Signature", command=self.verify_file, **button_style
        )
        self.verify_file_btn.pack(pady=5)

        # Input fields with warm border colors
        label_style = {"bg": "#FFDAB9", "fg": "#8B4513", "font": ("Arial", 10, "bold")}
        tk.Label(self.root, text="Text to Sign:", **label_style).pack(pady=5)
        self.text_input = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, width=40, height=5, bg="#FFF8DC", fg="#8B4513"
        )
        self.text_input.pack(pady=5)

        tk.Label(self.root, text="Signature (Hex):", **label_style).pack(pady=5)
        self.signature_text = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, width=40, height=5, bg="#FFF8DC", fg="#8B4513"
        )
        self.signature_text.pack(pady=5)

    def generate_keys(self):
        private_key_path = filedialog.asksaveasfilename(
            defaultextension=".pem", title="Save Private Key", filetypes=[("PEM files", "*.pem")]
        )
        public_key_path = filedialog.asksaveasfilename(
            defaultextension=".pem", title="Save Public Key", filetypes=[("PEM files", "*.pem")]
        )
        if private_key_path and public_key_path:
            lab5.generate_keys(private_key_path, public_key_path)
            self.private_key_path = private_key_path
            self.public_key_path = public_key_path
            messagebox.showinfo("Success", "Keys generated and saved successfully.")

    def load_private_key(self):
        file_path = filedialog.askopenfilename(
            title="Select Private Key", filetypes=[("PEM files", "*.pem")]
        )
        if file_path:
            self.private_key_path = file_path
            messagebox.showinfo("Success", "Private key loaded successfully.")

    def load_public_key(self):
        file_path = filedialog.askopenfilename(
            title="Select Public Key", filetypes=[("PEM files", "*.pem")]
        )
        if file_path:
            self.public_key_path = file_path
            messagebox.showinfo("Success", "Public key loaded successfully.")

    def sign_text(self):
        if not self.private_key_path:
            messagebox.showwarning("Warning", "Please load or generate a private key first.")
            return
        text = self.text_input.get("1.0", tk.END).strip()
        if text:
            signature = lab5.sign_data(text.encode(), self.private_key_path)
            self.signature_text.delete(1.0, tk.END)
            self.signature_text.insert(tk.END, signature)

    def verify_text_signature(self):
        if not self.public_key_path:
            messagebox.showwarning("Warning", "Please load or generate a public key first.")
            return
        text = self.text_input.get("1.0", tk.END).strip()
        hex_signature = self.signature_text.get("1.0", tk.END).strip()
        if text and hex_signature:
            is_valid = lab5.verify_signature(text.encode(), hex_signature, self.public_key_path)
            if is_valid:
                messagebox.showinfo("Verification", "Signature is valid.")
            else:
                messagebox.showwarning("Verification", "Signature is invalid.")

    def sign_file(self):
        if not self.private_key_path:
            messagebox.showwarning("Warning", "Please load or generate a private key first.")
            return
        file_path = filedialog.askopenfilename(title="Select a file to sign")
        if file_path:
            with open(file_path, "rb") as f:
                data = f.read()
            signature = lab5.sign_data(data, self.private_key_path)
            self.signature_text.delete(1.0, tk.END)
            self.signature_text.insert(tk.END, signature)

    def verify_file(self):
        if not self.public_key_path:
            messagebox.showwarning("Warning", "Please load or generate a public key first.")
            return
        file_path = filedialog.askopenfilename(title="Select a file to verify")
        if file_path:
            hex_signature = self.signature_text.get("1.0", tk.END).strip()
            with open(file_path, "rb") as f:
                data = f.read()
            is_valid = lab5.verify_signature(data, hex_signature, self.public_key_path)
            if is_valid:
                messagebox.showinfo("Verification", "Signature is valid.")
            else:
                messagebox.showwarning("Verification", "Signature is invalid.")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
