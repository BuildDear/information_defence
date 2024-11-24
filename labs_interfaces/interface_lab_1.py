import tkinter as tk
from tkinter import messagebox

from all_labs.logic.lab1 import generate_lemer_numbers


class Lab1App:
    def __init__(self, root):
        self.root = root
        self.root.title("Lemer Generator Test")
        self.root.geometry("600x400")
        self.root.configure(bg="#FFDAB9")  # Теплий фон вікна

        # Введення кількості пар
        self.num_pairs_label = tk.Label(root, text="Введіть кількість пар (n):", bg="#FFDAB9", fg="#8B4513", font=("Arial", 12))
        self.num_pairs_label.pack(pady=10)
        self.num_pairs_entry = tk.Entry(root, width=30, bg="#FFF5EE", fg="#8B4513", font=("Arial", 11))
        self.num_pairs_entry.pack(pady=10)

        # Кнопка для запуску тесту
        self.start_button = tk.Button(root, text="Запустити тест", command=self.start_test, bg="#FFA07A", fg="white", font=("Arial", 11, "bold"))
        self.start_button.pack(pady=10)

        # Текстова область для відображення результатів
        self.result_text = tk.Text(root, height=15, width=50, bg="#FFF5EE", fg="#8B4513", font=("Arial", 11))
        self.result_text.pack(pady=10)

    def start_test(self):
        """Обробка запуску тесту генератора Лемера."""
        try:
            num_pairs = int(self.num_pairs_entry.get())
            if num_pairs <= 0:
                raise ValueError("Кількість пар має бути додатнім числом.")

            # Виклик функції генерації чисел Лемера
            results = generate_lemer_numbers(num_pairs)

            # Відображення результатів у текстовій області
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Оцінка π (Лемер): {results['pi_lemer']}\n")
            self.result_text.insert(tk.END, f"Період Лемера: {results['period']}\n")
            self.result_text.insert(tk.END, "Згенеровані числа:\n")
            self.result_text.insert(tk.END, ', '.join(map(str, results['generated_numbers'])) + "\n")
        except ValueError as e:
            messagebox.showerror("Помилка введення", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = Lab1App(root)
    root.mainloop()