import tkinter as tk
from tkinter import filedialog, messagebox

from all_labs.logic.lab2 import md5_file, md5_string


class Lab2App:
    def __init__(self, root):
        self.root = root
        self.root.title("MD5 Хешування")
        self.root.geometry("600x400")
        self.root.configure(bg="#ffa386")  # Теплий фон для вікна

        # Рядок для хешування
        tk.Label(root, text="Введіть рядок для хешування:", bg="#FFFAF0", fg="#8B4513", font=("Arial", 12)).pack(pady=5)
        self.string_entry = tk.Entry(root, width=50, bg="#FFF5EE", fg="#8B4513", font=("Arial", 11))
        self.string_entry.pack(pady=5)

        # Кнопка для хешування рядка
        self.hash_string_button = tk.Button(root, text="Хешувати рядок", command=self.hash_string, bg="#FF6347", fg="white", font=("Arial", 11, "bold"))
        self.hash_string_button.pack(pady=5)

        # Кнопка для вибору файлу та хешування
        self.hash_file_button = tk.Button(root, text="Хешувати файл", command=self.hash_file, bg="#FF7F50", fg="white", font=("Arial", 11, "bold"))
        self.hash_file_button.pack(pady=5)

        # Поле для відображення результату
        self.result_text = tk.StringVar()
        self.result_label = tk.Label(root, textvariable=self.result_text, bg="#FFFAF0", fg="#8B4513", font=("Arial", 11, "italic"))
        self.result_label.pack(pady=5)

        # Кнопка для копіювання результату
        self.copy_button = tk.Button(root, text="Копіювати результат", command=self.copy_result, state=tk.DISABLED, bg="#CD5C5C", fg="white", font=("Arial", 11, "bold"))
        self.copy_button.pack(pady=5)

        # Кнопка для збереження хешу у файл
        self.save_button = tk.Button(root, text="Зберегти результат у файл", command=self.save_result, state=tk.DISABLED, bg="#F08080", fg="white", font=("Arial", 11, "bold"))
        self.save_button.pack(pady=5)

        # Кнопка для вибору файлу для перевірки
        self.load_file_button = tk.Button(root, text="Завантажити файл для перевірки", command=self.load_file, bg="#FF4500", fg="white", font=("Arial", 11, "bold"))
        self.load_file_button.pack(pady=5)

        # Кнопка для перевірки цілісності файлу
        self.verify_file_button = tk.Button(root, text="Перевірити файл", command=self.verify_file, state=tk.DISABLED, bg="#CD5C5C", fg="white", font=("Arial", 11, "bold"))
        self.verify_file_button.pack(pady=5)

        self.current_hash = None
        self.file_to_verify = None

    def hash_string(self):
        """Хешування рядка"""
        input_string = self.string_entry.get()
        if input_string:
            hash_value = md5_string(input_string)
            self.result_text.set(f"MD5 для рядка: {hash_value}")
            self.current_hash = hash_value
            self.save_button.config(state=tk.NORMAL)
            self.copy_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Помилка", "Введіть рядок для хешування!")

    def hash_file(self):
        """Хешування файлу"""
        file_path = filedialog.askopenfilename()
        if file_path:
            hash_value = md5_file(file_path)
            self.result_text.set(f"MD5 для файлу: {hash_value}")
            self.current_hash = hash_value
            self.save_button.config(state=tk.NORMAL)
            self.copy_button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Помилка", "Виберіть файл для хешування!")

    def copy_result(self):
        """Копіювання результату хешування в буфер обміну"""
        if self.current_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_hash)
            messagebox.showinfo("Копіювання", "Результат хешування скопійовано в буфер обміну!")

    def save_result(self):
        """Збереження результату хешування у файл"""
        if self.current_hash:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(self.current_hash)
                messagebox.showinfo("Успіх", f"Результат збережено у файл: {file_path}")
            else:
                messagebox.showerror("Помилка", "Виберіть правильний файл для збереження!")

    def load_file(self):
        """Завантаження файлу для перевірки цілісності"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_to_verify = file_path
            self.verify_file_button.config(state=tk.NORMAL)
            messagebox.showinfo("Успіх", f"Файл для перевірки обрано: {file_path}")
        else:
            messagebox.showerror("Помилка", "Виберіть файл для перевірки!")

    def verify_file(self):
        """Перевірка цілісності файлу за вмістом, а не хешуванням"""
        if self.file_to_verify and self.current_hash:
            try:
                # Читаємо вміст файлу, де знаходиться хеш
                with open(self.file_to_verify, 'r') as f:
                    file_hash = f.read().strip()  # Видаляємо зайві пробіли і перенос рядка

                # Порівнюємо вміст файлу з відображеним хешем
                if file_hash == self.current_hash:
                    messagebox.showinfo("Успіх", "Хеш збігається!")
                else:
                    messagebox.showerror("Помилка", "Хеш не збігається!")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка при читанні файлу: {str(e)}")
        else:
            messagebox.showerror("Помилка", "Немає даних для перевірки або поточний хеш не встановлено!")


def start_app():
    """Запуск програми з tkinter"""
    root = tk.Tk()
    app = Lab2App(root)
    root.mainloop()


# Запуск програми
start_app()
